package verify

import (
	"context"
	"errors"
	"io"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
)

// AADError reports that an object's associated data could not be built,
// because its key or bucket cannot be encoded. That is a property of the name,
// not of the stored object, so it is not a Failure. It reads as the underlying
// error, which is what the proxy has always shown the client.
type AADError struct{ Err error }

func (e *AADError) Error() string { return e.Err.Error() }
func (e *AADError) Unwrap() error { return e.Err }

// UnwrapDEK recovers an object's data key, bound to its bucket and key.
//
// key is the object's identity -- the name a client uses -- not the name it is
// stored under: with name encryption on the two differ, and the data key was
// wrapped under the identity (FORMAT.md §6).
func UnwrapDEK(ctx context.Context, kp keys.KeyProvider, bucket, key string, meta objectmeta.Meta) ([]byte, error) {
	aad, err := keys.ObjectAAD(meta.KeyID, bucket, key)
	if err != nil {
		return nil, &AADError{Err: err}
	}
	dek, err := kp.Unwrap(ctx, meta.KeyID, meta.WrappedDEK, aad)
	if err != nil {
		if errors.Is(err, keys.ErrUnknownKID) {
			return nil, fail(KindUnknownKID, "data key", err)
		}
		return nil, fail(KindDEKUnwrap, "data key", err)
	}
	return dek, nil
}

// OpenSegment authenticates the header and first chunk of a single-part object.
//
// Everything that can fail before the body is streamed fails here, so that the
// proxy can still answer with an error rather than a truncated body (ADR-004).
// The returned metadata carries the chunk size the authenticated header states.
func OpenSegment(body io.Reader, dek []byte, meta objectmeta.Meta) (*stream.DecryptReader, objectmeta.Meta, error) {
	// AnyChunkSize: the segment states its own size, and unlike the metadata
	// that statement is authenticated.
	reader, err := stream.NewDecryptReader(body, dek, stream.SegmentParams{Log2ChunkSize: stream.AnyChunkSize})
	if err != nil {
		return nil, objectmeta.Meta{}, fail(KindHeader, "segment header", err)
	}
	if err := reader.VerifyFirst(); err != nil {
		_ = reader.Close()
		return nil, objectmeta.Meta{}, fail(KindChunk, "first chunk", err)
	}

	// Past this point the header is authenticated, so it can be trusted over the
	// metadata. A recorded chunk size that disagrees with it means the metadata
	// was altered.
	authenticated := reader.Header().Log2ChunkSize
	if meta.HasChunkSize && meta.Log2ChunkSize != authenticated {
		_ = reader.Close()
		return nil, objectmeta.Meta{}, fail(KindChunk, "chunk size",
			errors.New("object metadata disagrees with the authenticated segment header"))
	}
	meta.Log2ChunkSize = authenticated
	return reader, meta, nil
}
