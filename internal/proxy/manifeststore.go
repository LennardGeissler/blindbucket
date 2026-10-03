package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// maxManifestBytes bounds a manifest read back from the provider.
//
// A manifest of 10000 parts is about 100 KB. The bound matters because the
// provider is untrusted: without it, a manifest object could be made arbitrarily
// large and every GET of the object would allocate it.
const maxManifestBytes = 1 << 20

// writeManifest stores a manifest as a sidecar object.
//
// This is step 3 of the completion order in FORMAT.md 10.7, and rule R2:
// the manifest exists before the operation makes the object visible, never
// after. It does not disturb the object currently visible, because that object's
// metadata names a different manifest id.
func (p *Proxy) writeManifest(ctx context.Context, m *manifest.Manifest, dek []byte) error {
	raw, err := m.Marshal(dek)
	if err != nil {
		return fmt.Errorf("building the manifest: %w", err)
	}
	_, err = p.upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket:        m.Bucket,
		Key:           m.ID.ObjectKey(m.Key),
		Body:          bytes.NewReader(raw),
		ContentLength: int64(len(raw)),
		ContentType:   "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("storing the manifest: %w", err)
	}
	return nil
}

// loadManifest fetches and verifies the manifest of a multipart object.
//
// bucket, key and id are what the caller expects; the manifest itself gets no
// say in them. A manifest from another object, or from an earlier upload of this
// one, therefore fails to verify rather than producing a plausible part list.
func (p *Proxy) loadManifest(
	ctx context.Context, bucket, key string, id manifest.ID, dek []byte,
) (*manifest.Manifest, error) {
	out, err := p.upstream.GetObject(ctx, upstream.GetObjectInput{
		Bucket: bucket, Key: id.ObjectKey(key),
	})
	if err != nil {
		if upstream.NotFound(err) {
			// The object is visible but its manifest is not there. That is the
			// failure invariant I1 exists to prevent, so it is reported as an
			// integrity failure and not as a missing object: the object is very
			// much there, it just cannot be served.
			return nil, fmt.Errorf("%w: the manifest of this object is missing", manifest.ErrVerify)
		}
		return nil, err
	}
	defer func() { _ = out.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(out.Body, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	if len(raw) > maxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", manifest.ErrVerify, maxManifestBytes)
	}
	return manifest.Unmarshal(raw, dek, bucket, key, id)
}

// deleteManifest removes one manifest.
//
// Rule R3 governs every call: a request may delete at most the manifest id it
// read from the visible object *before* its own successful replacement or
// deletion. Nothing else is ever deleted here -- in particular not "the other
// manifests of this key", which is the version 0.1 rule that
// spec/tla/Multipart.tla produces a counterexample for.
func (p *Proxy) deleteManifest(ctx context.Context, bucket, key string, id manifest.ID) error {
	return p.upstream.DeleteObject(ctx, bucket, id.ObjectKey(key))
}

// observedManifest reports the manifest id of the object currently visible at
// key, if that object is a multipart one.
//
// This is step 2 of the completion order: the observation that R3 later licenses
// a delete of. An object that is absent, single-part, or not written by this
// gateway yields no id, and therefore no delete.
func (p *Proxy) observedManifest(ctx context.Context, bucket, key string) (manifest.ID, bool) {
	info, err := p.upstream.HeadObject(ctx, bucket, key)
	if err != nil {
		return manifest.ID{}, false
	}
	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if err != nil || !meta.Multipart {
		return manifest.ID{}, false
	}
	return meta.ManifestID, true
}

// replacedSince reports whether the object at key has stopped using the
// manifest id observed at step 2 -- the check that licenses step 5 (ADR-025).
//
// A successful completion is not proof. AWS S3 keeps the write that was
// initiated last, so an upload created before the visible version's write is
// acknowledged and then discarded, and the version observed at step 2 is still
// the one every reader gets. Only an answer that shows something else -- another
// version, or none -- counts as replaced: a HEAD that failed, or metadata that
// does not parse, says nothing, and a manifest kept by mistake is an orphan for
// gc while one deleted by mistake is an object nobody can read.
func (p *Proxy) replacedSince(ctx context.Context, bucket, key string, observed manifest.ID) bool {
	info, err := p.upstream.HeadObject(ctx, bucket, key)
	if err != nil {
		return upstream.NotFound(err)
	}
	meta, err := parseObjectMeta(info.Metadata, p.log2C)
	if err != nil {
		return false
	}
	return !meta.Multipart || meta.ManifestID != observed
}

// isManifestFailure reports whether err means the manifest could not be trusted,
// as opposed to the provider being unreachable.
func isManifestFailure(err error) bool {
	return errors.Is(err, manifest.ErrVerify)
}
