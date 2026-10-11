package verify

import (
	"context"
	"fmt"
	"io"

	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// MaxManifestBytes bounds a manifest read back from the provider.
//
// A manifest of 10000 parts is about 100 KB. The bound matters because the
// provider is untrusted: without it, a manifest object could be made arbitrarily
// large and every GET of the object would allocate it.
const MaxManifestBytes = 1 << 20

// LoadManifest fetches and verifies the manifest of a multipart object.
//
// bucket, key and id are what the caller expects; the manifest itself gets no
// say in them. A manifest from another object, or from an earlier upload of this
// one, therefore fails to verify rather than producing a plausible part list.
// key is the name the object is stored under: the manifest lives at its hash
// and is bound to it, which is what keeps gc free of the name key.
//
// A failure to trust the manifest wraps manifest.ErrVerify; any other error is
// the provider being unreachable.
func LoadManifest(
	ctx context.Context, up *upstream.Client, bucket, key string, id manifest.ID, dek []byte,
) (*manifest.Manifest, error) {
	out, err := up.GetObject(ctx, upstream.GetObjectInput{
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

	raw, err := io.ReadAll(io.LimitReader(out.Body, MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", manifest.ErrVerify, MaxManifestBytes)
	}
	return manifest.Unmarshal(raw, dek, bucket, key, id)
}
