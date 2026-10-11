package verify

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// ErrShortRead reports that the provider's body ended before the length it
// announced. To a decoder that is indistinguishable from a truncated object, but
// the object did not say it was shorter -- the connection did -- so it is a
// failure to read, not a finding about what is stored.
var ErrShortRead = errors.New("verify: the body ended before its announced length")

// Target names an object two ways: Identity is the name its data key is bound
// to (the name a client uses), Stored is the name the provider holds it under.
// They are the same unless name encryption is on.
type Target struct {
	Bucket   string
	Identity string
	Stored   string
}

// Result is what a verified object turned out to be.
type Result struct {
	// ETag is the provider's ETag of the version that was read, so a caller can
	// tell whether a later look at the key sees the same object.
	ETag       string
	KeyID      string
	Multipart  bool
	Parts      int
	PlainBytes int64
	// CipherBytes is what was read from the provider for the object itself,
	// not counting a manifest.
	CipherBytes int64
}

// Object reads one stored object in full and verifies it as a GET of the whole
// object does, discarding the plaintext.
//
// The outcome is one of three. A nil error means every check passed. A
// *Failure means the object as stored does not verify, and says which check it
// failed. Anything else -- objectmeta.ErrNotEncrypted for an object the gateway
// did not write, *AADError, ErrShortRead, a provider error -- says nothing about
// the integrity of the object. ETag is set whenever the object was reached, so a
// caller can recheck a failure against the current version.
func Object(
	ctx context.Context, up *upstream.Client, kp keys.KeyProvider, t Target, fallbackLog2C uint8,
) (Result, error) {
	out, err := up.GetObject(ctx, upstream.GetObjectInput{Bucket: t.Bucket, Key: t.Stored})
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = out.Body.Close() }()
	res := Result{ETag: out.ETag}

	meta, err := objectmeta.Parse(out.Metadata, fallbackLog2C)
	if errors.Is(err, objectmeta.ErrNotEncrypted) {
		return res, err
	}
	if err != nil {
		return res, fail(KindMetadata, "object metadata", err)
	}
	res.KeyID, res.Multipart = meta.KeyID, meta.Multipart

	dek, err := UnwrapDEK(ctx, kp, t.Bucket, t.Identity, meta)
	if err != nil {
		return res, err
	}
	defer clear(dek)

	body := &countingReader{r: out.Body}
	var plain io.Reader
	if meta.Multipart {
		chain, n, err := openMultipart(ctx, up, t, meta, out.ContentLength, body, dek)
		if err != nil {
			return res, shortOr(err, body, out.ContentLength)
		}
		defer func() { _ = chain.Close() }()
		res.Parts = n
		plain = chain
	} else {
		reader, opened, err := OpenSegment(body, dek, meta)
		if err != nil {
			return res, shortOr(err, body, out.ContentLength)
		}
		defer func() { _ = reader.Close() }()
		if _, err := stream.OpenedSize(out.ContentLength, opened.Log2ChunkSize); err != nil {
			return res, fail(KindSize, "ciphertext size", err)
		}
		res.Parts = 1
		plain = reader
	}

	n, err := io.Copy(io.Discard, plain)
	res.PlainBytes, res.CipherBytes = n, body.n
	if err != nil {
		if kind, ok := streamKind(err); ok {
			return res, shortOr(fail(kind, "stream", err), body, out.ContentLength)
		}
		return res, err
	}
	return res, nil
}

// openMultipart loads and checks the manifest, then opens the first part.
func openMultipart(
	ctx context.Context, up *upstream.Client, t Target, meta objectmeta.Meta,
	storedCipher int64, body io.Reader, dek []byte,
) (*SegmentChain, int, error) {
	m, err := LoadManifest(ctx, up, t.Bucket, t.Stored, meta.ManifestID, dek)
	if err != nil {
		if kind, ok := streamKind(err); ok {
			return nil, 0, fail(kind, "manifest", err)
		}
		return nil, 0, err
	}
	layout, err := NewLayout(m.Parts, meta.Log2ChunkSize, m.HasSalts())
	if err != nil {
		return nil, 0, fail(KindManifest, "manifest", err)
	}
	if err := layout.CheckAgainst(storedCipher); err != nil {
		return nil, 0, fail(KindSize, "object size", err)
	}
	chain, err := NewSegmentChain(body, dek, layout)
	if err != nil {
		kind, ok := streamKind(err)
		if !ok {
			kind = KindHeader
		}
		return nil, 0, fail(kind, "segment header", err)
	}
	if err := chain.VerifyFirst(); err != nil {
		_ = chain.Close()
		kind, ok := streamKind(err)
		if !ok {
			kind = KindChunk
		}
		return nil, 0, fail(kind, "first chunk", err)
	}
	return chain, len(layout.Parts), nil
}

// shortOr turns a failure into ErrShortRead when the provider sent less than it
// announced: the decoder saw a truncated stream, but what truncated it was the
// transfer, and a scrub must not report a dropped connection as tampering.
func shortOr(err error, body *countingReader, announced int64) error {
	if _, isFailure := AsFailure(err); !isFailure {
		return err
	}
	if body.err != nil && !errors.Is(body.err, io.EOF) {
		return fmt.Errorf("%w: %w", ErrShortRead, body.err)
	}
	if body.eof && announced >= 0 && body.n < announced {
		return fmt.Errorf("%w: %d of %d bytes", ErrShortRead, body.n, announced)
	}
	return err
}

// countingReader counts what the provider actually delivered, and remembers how
// the body ended.
type countingReader struct {
	r   io.Reader
	n   int64
	eof bool
	err error
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if errors.Is(err, io.EOF) {
		c.eof = true
	} else if err != nil {
		c.err = err
	}
	return n, err
}
