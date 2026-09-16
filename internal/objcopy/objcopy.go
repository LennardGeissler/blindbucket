// Package objcopy republishes a stored object under a freshly wrapped data key,
// without its ciphertext ever travelling through this process.
//
// Two callers need exactly this. `blindbucket rotate` re-wraps an object's data
// key under a new KEK and writes it back to the key it came from. CopyObject
// writes it to a different key. Both keep the data key itself, both have to
// re-wrap it because the wrap is bound to the object's identity (FORMAT §6.1),
// both have to preserve a multipart object's part boundaries so the size
// arithmetic still reads, and both have to obey the manifest lifecycle rules
// R1-R3 that spec/tla/Multipart.tla checks.
//
// That last point is why this is one package and not two implementations. The
// rules are ordering constraints on three writes, the model proves the ordering,
// and ADR-010 records which counterexample each rule came from. Written twice,
// they would eventually be two different orderings, and only one of them would
// be the one that was verified.
//
// # Why the data key is kept rather than replaced
//
// A copy produces a second object with the same data key, the same segment salt
// and therefore byte-identical ciphertext. That is not nonce reuse in the sense
// that matters: a nonce is reused with the same key only over identical
// plaintext, which produces the ciphertext the provider is holding anyway. What
// would be unsafe is reusing a key across *different* plaintexts, and that
// cannot arise here -- an object is immutable, and overwriting one is a new PUT
// with a new data key. The alternative, re-encrypting under a fresh key, would
// move every byte through this process twice and buy nothing. See ADR-012.
package objcopy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// MaxManifestBytes bounds a manifest read back from the provider.
const MaxManifestBytes = 1 << 20

// ErrPreconditionFailed reports that one of the conditional writes was refused:
// the source changed between being read and being copied, or the destination
// changed between being read and being published.
//
// For rotation it means a client wrote during the run and its version stands --
// invariant I2 holding rather than a failure. For CopyObject it is the client's
// own x-amz-copy-source-if-* condition coming back.
var ErrPreconditionFailed = errors.New("objcopy: the object changed during the copy")

// Hook points, named as spec/tla/Multipart.tla names the steps. They exist so
// an integration test can hold a copy open and replay a counterexample; they are
// nil everywhere else.
const (
	HookCreate   = "copyCreate"   // after the upload is opened
	HookParts    = "copyParts"    // after the last part is copied
	HookManifest = "copyManifest" // after the new manifest is written
	HookComplete = "copyComplete" // after the publishing write lands
)

// Deps are what a copy needs from the rest of the system.
type Deps struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	Log      *slog.Logger
}

// Source is the object being copied, as it was read.
//
// Info and Meta come from a HEAD the caller has already done: it needs them to
// decide whether to copy at all, and repeating the request here would open a
// window between the two reads.
type Source struct {
	Bucket string
	// Key is the key the *client* names, which is the object's identity: it is
	// what the wrapped data key is bound to and what a manifest is bound to.
	//
	// StoredKey is where the object actually lives. The two differ only when
	// object-name encryption is on (ADR-015), and separating them is not
	// cosmetic: building associated data from the stored key would produce an
	// object the gateway cannot open, because every read binds the plaintext
	// key. Both must be set; see FORMAT.md section 15.4.
	Key       string
	StoredKey string
	Info      *upstream.ObjectInfo
	Meta      objectmeta.Meta
}

// Dest is where the object lands.
type Dest struct {
	Bucket string
	// Key and StoredKey split the same way Source's do: identity against
	// address. Both must be set.
	Key       string
	StoredKey string
	// KeyID is the KEK the data key is wrapped under at the destination. For
	// rotation it is the target KEK; for a copy it is whichever is active.
	KeyID string

	// UserMetadata is the destination's metadata without the bb-* entries,
	// which this package sets itself and which a caller must not supply.
	UserMetadata map[string]string

	ContentType        string
	CacheControl       string
	ContentDisposition string
	ContentEncoding    string
	ContentLanguage    string
}

// Request describes one copy.
type Request struct {
	Source Source
	Dest   Dest

	// SourceIfMatch refuses the copy unless the source still has this ETag. It
	// closes the window between the caller's HEAD and the copy itself, in which
	// the source could be replaced: without it, a copy can pair one version's
	// metadata with another version's bytes.
	SourceIfMatch string

	// DestIfMatch makes the publishing write conditional on the destination's
	// current ETag. Rotation sets it, because writing back unconditionally would
	// discard a client write that landed in between (invariant I2). A plain
	// CopyObject leaves it empty: S3's own semantics are last-writer-wins, and a
	// client asking to copy over an object means it.
	DestIfMatch string

	// ReplacedManifest is the manifest id of the destination version this copy
	// replaces, to be deleted once the new version is published (rule R3).
	//
	// Only a caller that already knows the destination's previous metadata may
	// set it -- rotation does, because its destination is its source. A caller
	// that does not know leaves it nil and lets `blindbucket gc` collect the
	// orphan, which is what the ordinary PutObject path does too.
	ReplacedManifest *manifest.ID

	// Hook is called at the steps named above.
	Hook func(point string)
}

// Result reports what the provider recorded for the new object.
type Result struct {
	ETag         string
	LastModified time.Time
	// Meta is the metadata the destination was written with.
	Meta objectmeta.Meta
}

func (r Request) at(point string) {
	if r.Hook != nil {
		r.Hook(point)
	}
}

// Do copies the object described by req.
//
// Everything moves inside the provider: the data key is unwrapped, re-wrapped
// under the destination's identity and written as metadata, while the segments
// themselves are copied with UploadPartCopy. A terabyte costs what a megabyte
// costs.
func Do(ctx context.Context, deps Deps, req Request) (*Result, error) {
	switch {
	case deps.Upstream == nil:
		return nil, errors.New("objcopy: an upstream client is required")
	case deps.Keys == nil:
		return nil, errors.New("objcopy: a key provider is required")
	case req.Source.Info == nil:
		return nil, errors.New("objcopy: the source has not been read")
	// Both halves of each key, always. A caller that set only one would either
	// address the wrong object or bind the data key to the wrong name, and the
	// second of those produces an object that cannot be opened again -- so it is
	// refused here rather than left to a zero value.
	case req.Source.Key == "" || req.Source.StoredKey == "":
		return nil, errors.New("objcopy: the source needs both Key and StoredKey")
	case req.Dest.Key == "" || req.Dest.StoredKey == "":
		return nil, errors.New("objcopy: the destination needs both Key and StoredKey")
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if err := keys.ValidateKID(req.Dest.KeyID); err != nil {
		return nil, fmt.Errorf("objcopy: destination key id: %w", err)
	}

	next, dek, err := rewrap(ctx, deps, req)
	if err != nil {
		return nil, err
	}
	defer clear(dek)

	return publish(ctx, deps, req, next, dek)
}

// rewrap unwraps the data key under the source's identity and wraps it under the
// destination's.
//
// Both the key id and the object's bucket and key are associated data of the
// wrap (FORMAT §6.1), so a copy that skipped this step would store a key that
// cannot be unwrapped at its new location -- the object would be unreadable, and
// only at the next read. Rotation changes the key id; a copy changes the bucket
// and key; the operation is the same one.
func rewrap(ctx context.Context, deps Deps, req Request) (objectmeta.Meta, []byte, error) {
	src, dst := req.Source, req.Dest

	// The identity, deliberately: the wrapped data key is bound to the key the
	// client names, so an object reads the same whether or not names are
	// encrypted, and moving between the two is a rename rather than a rewrite.
	oldAAD, err := keys.ObjectAAD(src.Meta.KeyID, src.Bucket, src.Key)
	if err != nil {
		return objectmeta.Meta{}, nil, err
	}
	dek, err := deps.Keys.Unwrap(ctx, src.Meta.KeyID, src.Meta.WrappedDEK, oldAAD)
	if err != nil {
		return objectmeta.Meta{}, nil, fmt.Errorf("unwrapping under %q: %w", src.Meta.KeyID, err)
	}

	newAAD, err := keys.ObjectAAD(dst.KeyID, dst.Bucket, dst.Key)
	if err != nil {
		clear(dek)
		return objectmeta.Meta{}, nil, err
	}
	wrapped, err := deps.Keys.Wrap(ctx, dst.KeyID, dek, newAAD)
	if err != nil {
		clear(dek)
		return objectmeta.Meta{}, nil, fmt.Errorf("wrapping under %q: %w", dst.KeyID, err)
	}

	out := src.Meta
	out.KeyID = dst.KeyID
	out.WrappedDEK = wrapped
	return out, dek, nil
}

// publish writes the destination object.
//
// Both shapes go through a multipart upload, single-part objects included. A
// plain CopyObject would work for those, but CompleteMultipartUpload is where
// the conditional write lives, and a single part keeps the size arithmetic
// identical (M = 1 gives the same result as a single-part object, FORMAT §7.2).
func publish(ctx context.Context, deps Deps, req Request,
	next objectmeta.Meta, dek []byte,
) (*Result, error) {
	src, dst := req.Source, req.Dest

	// Rule R1: the new version mints a new manifest id rather than pointing at
	// the one the source uses. Two object versions sharing a manifest is the
	// state the model produces its first counterexample from -- deleting either
	// version then takes the other's manifest with it.
	var layout []manifest.Part
	if src.Meta.Multipart {
		parts, err := loadParts(ctx, deps, src, dek)
		if err != nil {
			return nil, err
		}
		layout = parts

		id, err := manifest.NewID()
		if err != nil {
			return nil, err
		}
		next.ManifestID, next.Multipart = id, true
	}

	metadata := map[string]string{}
	for name, value := range dst.UserMetadata {
		if strings.HasPrefix(strings.ToLower(name), objectmeta.Prefix) {
			continue
		}
		metadata[name] = value
	}
	for name, value := range next.Headers() {
		metadata[name] = value
	}

	uploadID, err := deps.Upstream.CreateMultipartUpload(ctx, upstream.CreateMultipartUploadInput{
		Bucket: dst.Bucket, Key: dst.StoredKey,
		ContentType:        dst.ContentType,
		CacheControl:       dst.CacheControl,
		ContentDisposition: dst.ContentDisposition,
		ContentEncoding:    dst.ContentEncoding,
		ContentLanguage:    dst.ContentLanguage,
		Metadata:           metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("opening the copy upload: %w", err)
	}
	// Any failure from here leaves an upload the provider would keep until its
	// lifecycle rule expires it, so it is aborted on every path out.
	req.at(HookCreate)
	committed := false
	defer func() {
		if !committed {
			if err := deps.Upstream.AbortMultipartUpload(ctx, dst.Bucket, dst.StoredKey, uploadID); err != nil {
				deps.Log.Warn("could not abort a failed copy upload",
					"bucket", dst.Bucket, "key", dst.Key, "err", err)
			}
		}
	}()

	completed, err := copyParts(ctx, deps, req, layout, uploadID)
	if err != nil {
		if upstream.PreconditionFailed(err) {
			return nil, ErrPreconditionFailed
		}
		return nil, err
	}
	req.at(HookParts)

	// Rule R2: the manifest exists before the object that names it does. The
	// other way round there is a window in which a reader finds an object
	// pointing at a manifest that is not there yet, and fails a read that should
	// have worked.
	if next.Multipart {
		m := &manifest.Manifest{
			Bucket: dst.Bucket, Key: dst.StoredKey, ID: next.ManifestID, Parts: layout,
		}
		if err := writeManifest(ctx, deps, m, dek); err != nil {
			return nil, err
		}
	}
	req.at(HookManifest)

	out, err := deps.Upstream.CompleteMultipartUpload(ctx, upstream.CompleteMultipartUploadInput{
		Bucket: dst.Bucket, Key: dst.StoredKey, UploadID: uploadID,
		Parts: completed, IfMatch: req.DestIfMatch,
	})
	if err != nil {
		if upstream.PreconditionFailed(err) {
			return nil, ErrPreconditionFailed
		}
		return nil, fmt.Errorf("completing the copy: %w", err)
	}
	committed = true
	req.at(HookComplete)

	// Rule R3: and only now, the manifest of the version just replaced -- the id
	// read before this write landed, and nothing else. Deleting it any earlier
	// would strand a reader that is still on the old version.
	if id := req.ReplacedManifest; id != nil && *id != next.ManifestID {
		if err := deps.Upstream.DeleteObject(ctx, dst.Bucket, id.ObjectKey(dst.StoredKey)); err != nil {
			deps.Log.Warn("could not remove the replaced manifest; gc will collect it",
				"bucket", dst.Bucket, "key", dst.Key, "err", err)
		}
	}

	return &Result{ETag: out.ETag, LastModified: time.Now().UTC(), Meta: next}, nil
}

// copyParts fills the upload from the source object, without moving any bytes
// through this process.
func copyParts(ctx context.Context, deps Deps, req Request,
	layout []manifest.Part, uploadID string,
) ([]upstream.CompletedPart, error) {
	src, dst := req.Source, req.Dest

	// A single-part object is copied whole as part 1.
	if layout == nil {
		etag, err := deps.Upstream.UploadPartCopy(ctx, upstream.UploadPartCopyInput{
			SourceBucket: src.Bucket, SourceKey: src.StoredKey,
			Bucket: dst.Bucket, Key: dst.StoredKey, UploadID: uploadID,
			PartNumber: 1, WholeObject: true, SourceIfMatch: req.SourceIfMatch,
		})
		if err != nil {
			return nil, fmt.Errorf("copying the object: %w", err)
		}
		return []upstream.CompletedPart{{PartNumber: 1, ETag: etag}}, nil
	}

	// A multipart object keeps its part boundaries: the copy has to be the same
	// shape as the original, or the manifest would describe a different object.
	out := make([]upstream.CompletedPart, 0, len(layout))
	var offset int64
	for _, part := range layout {
		sealed, err := stream.SealedSize(part.PlainSize, src.Meta.Log2ChunkSize)
		if err != nil {
			return nil, fmt.Errorf("part %d has an impossible size: %w", part.Number, err)
		}
		etag, err := deps.Upstream.UploadPartCopy(ctx, upstream.UploadPartCopyInput{
			SourceBucket: src.Bucket, SourceKey: src.StoredKey,
			Bucket: dst.Bucket, Key: dst.StoredKey, UploadID: uploadID,
			//nolint:gosec // part numbers come from a verified manifest, 1..10000.
			PartNumber: int(part.Number),
			First:      offset, Last: offset + sealed - 1,
			SourceIfMatch: req.SourceIfMatch,
		})
		if err != nil {
			return nil, fmt.Errorf("copying part %d: %w", part.Number, err)
		}
		//nolint:gosec // bounded by the manifest.
		out = append(out, upstream.CompletedPart{PartNumber: int(part.Number), ETag: etag})
		offset += sealed
	}
	return out, nil
}

// loadParts fetches and verifies the manifest of a multipart source.
func loadParts(ctx context.Context, deps Deps, src Source, dek []byte) ([]manifest.Part, error) {
	out, err := deps.Upstream.GetObject(ctx, upstream.GetObjectInput{
		Bucket: src.Bucket, Key: src.Meta.ManifestID.ObjectKey(src.StoredKey),
	})
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(out.Body, MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", manifest.ErrVerify, MaxManifestBytes)
	}
	// The manifest is bound to the *stored* key, not the identity, and its path
	// is the hash of the same. That pairing is what keeps `gc` free of the name
	// key: it reads a key out of a manifest and checks that it hashes back to
	// the directory the manifest was found in, and both halves of that check
	// live in the provider's namespace. The object's own data key goes the other
	// way, bound to the identity, because that is what a read has in hand.
	m, err := manifest.Unmarshal(raw, dek, src.Bucket, src.StoredKey, src.Meta.ManifestID)
	if err != nil {
		return nil, err
	}
	if m.HasSalts() {
		return m.Parts, nil
	}

	// A manifest written before part salts were recorded. The destination's
	// will be written in the current format, and writing zero salts into it
	// would produce an object that fails its own verification on the first
	// read. The salts are recoverable here in a way they are not at
	// completion: the source is a finished object, so its part headers can be
	// read. Copying and rotation therefore upgrade an old object rather than
	// carrying its gap forward.
	return fillSaltsFromHeaders(ctx, deps, src, m.Parts)
}

// fillSaltsFromHeaders reads each part's segment header off the source object.
func fillSaltsFromHeaders(
	ctx context.Context, deps Deps, src Source, parts []manifest.Part,
) ([]manifest.Part, error) {
	out := make([]manifest.Part, len(parts))
	copy(out, parts)

	var offset int64
	for i, part := range out {
		sealed, err := stream.SealedSize(part.PlainSize, src.Meta.Log2ChunkSize)
		if err != nil {
			return nil, fmt.Errorf("part %d has an impossible size: %w", part.Number, err)
		}
		got, err := deps.Upstream.GetObject(ctx, upstream.GetObjectInput{
			Bucket: src.Bucket, Key: src.StoredKey,
			Range:   fmt.Sprintf("bytes=%d-%d", offset, offset+stream.HeaderSize-1),
			IfMatch: src.Info.ETag,
		})
		if err != nil {
			return nil, fmt.Errorf("reading the header of part %d: %w", part.Number, err)
		}
		raw := make([]byte, stream.HeaderSize)
		_, readErr := io.ReadFull(got.Body, raw)
		_ = got.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading the header of part %d: %w", part.Number, readErr)
		}
		salt, ok := stream.SaltFromHeader(raw)
		if !ok {
			return nil, fmt.Errorf("the header of part %d is short", part.Number)
		}
		out[i].Salt = salt
		offset += sealed
	}
	deps.Log.Info("upgraded a manifest written before part salts were recorded",
		"bucket", src.Bucket, "key", src.Key, "parts", len(out))
	return out, nil
}

// writeManifest stores the manifest of the destination object.
func writeManifest(ctx context.Context, deps Deps, m *manifest.Manifest, dek []byte) error {
	raw, err := m.Marshal(dek)
	if err != nil {
		return fmt.Errorf("building the manifest: %w", err)
	}
	_, err = deps.Upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: m.Bucket, Key: m.ID.ObjectKey(m.Key),
		Body: strings.NewReader(string(raw)), ContentLength: int64(len(raw)),
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("storing the manifest: %w", err)
	}
	return nil
}
