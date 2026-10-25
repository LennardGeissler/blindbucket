// Package objectmeta reads and writes the bb-* metadata blindbucket records
// alongside an object.
//
// It is the encoding of docs/FORMAT.md section 6.3 and nothing else. It lives on
// its own because both the proxy and `blindbucket rotate` have to agree on it
// exactly, and a normative encoding kept in two places is an encoding that will
// eventually be kept in two different ways.
package objectmeta

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

// ErrNotEncrypted reports an upstream object that blindbucket did not write.
//
// Such an object is served to nobody. Passing it through would mean the same
// endpoint sometimes returns authenticated plaintext and sometimes returns
// whatever happened to be in the bucket, with no way for a client to tell which.
var ErrNotEncrypted = errors.New("object was not written by this gateway")

// Metadata keys blindbucket sets on upstream objects, without the
// x-amz-meta- prefix. See docs/FORMAT.md section 6.3.
const (
	// Prefix is reserved: a client may not set metadata that starts with it.
	Prefix        = "bb-"
	metaPrefix    = Prefix
	metaVersion   = "bb-v"
	metaKeyID     = "bb-kid"
	metaDEK       = "bb-dek"
	metaChunkSize = "bb-c"
	// metaManifestID names the manifest of a multipart object. Its absence is
	// what makes an object single-part.
	metaManifestID = "bb-mid"
)

// Meta is what blindbucket records alongside an object so it can be read
// back later.
type Meta struct {
	Version       int
	KeyID         string
	WrappedDEK    []byte
	Log2ChunkSize uint8
	// HasChunkSize reports whether Log2ChunkSize came from the object itself
	// rather than from the configured fallback. Only a recorded value may be
	// checked against the authenticated segment header: a fallback that happens
	// to differ is a stale configuration, not tampering.
	HasChunkSize bool

	// ManifestID names the object's manifest. Multipart reports whether it is
	// set; a single-part object has none.
	ManifestID manifest.ID
	Multipart  bool
}

// Headers renders the metadata for an upstream request.
func (m Meta) Headers() map[string]string {
	out := map[string]string{
		metaVersion:   strconv.Itoa(m.Version),
		metaKeyID:     m.KeyID,
		metaDEK:       keys.EncodeWrapped(m.WrappedDEK),
		metaChunkSize: strconv.Itoa(int(m.Log2ChunkSize)),
	}
	if m.Multipart {
		out[metaManifestID] = m.ManifestID.String()
	}
	return out
}

// StoredDEK returns an object's bb-dek exactly as the provider holds it, or ""
// for an object the gateway did not write. A tag sidecar is named after this
// string, not after the key it decodes to (FORMAT.md section 17.1), so that gc,
// which has no keyring, names it the same way.
func StoredDEK(md map[string]string) string {
	for name, value := range md {
		if strings.EqualFold(name, metaDEK) {
			return value
		}
	}
	return ""
}

// StoredDEKOf is StoredDEK for metadata the gateway is about to write.
func StoredDEKOf(m Meta) string { return m.Headers()[metaDEK] }

// Parse reads blindbucket's metadata off an upstream response.
//
// fallbackLog2C is used for objects written before bb-c existed, and for any
// provider that drops the header. It is the configured chunk size, which is
// correct for every object a given deployment wrote.
func Parse(md map[string]string, fallbackLog2C uint8) (Meta, error) {
	lookup := func(key string) string {
		// Providers canonicalise metadata keys differently -- MinIO returns
		// "Bb-Kid", others lower-case -- so match case-insensitively.
		for name, value := range md {
			if strings.EqualFold(name, key) {
				return value
			}
		}
		return ""
	}

	raw := lookup(metaDEK)
	if raw == "" {
		return Meta{}, ErrNotEncrypted
	}

	version, err := strconv.Atoi(lookup(metaVersion))
	if err != nil {
		return Meta{}, fmt.Errorf("object metadata has no usable %s: %w", metaVersion, err)
	}
	if version != stream.Version {
		return Meta{}, fmt.Errorf("object is format version %d, this build reads %d",
			version, stream.Version)
	}

	kid := lookup(metaKeyID)
	if err := keys.ValidateKID(kid); err != nil {
		return Meta{}, fmt.Errorf("object metadata has no usable %s: %w", metaKeyID, err)
	}

	wrapped, err := keys.DecodeWrapped(raw)
	if err != nil {
		return Meta{}, fmt.Errorf("object metadata has an unreadable %s: %w", metaDEK, err)
	}
	if len(wrapped) != keys.WrappedDEKSize {
		return Meta{}, fmt.Errorf("wrapped key is %d bytes, want %d",
			len(wrapped), keys.WrappedDEKSize)
	}

	log2C, recorded := fallbackLog2C, false
	if raw := lookup(metaChunkSize); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > 255 {
			return Meta{}, fmt.Errorf("object metadata has an unreadable %s", metaChunkSize)
		}
		log2C, recorded = uint8(parsed), true
	}
	if err := stream.ValidateLog2ChunkSize(log2C); err != nil {
		return Meta{}, err
	}

	out := Meta{
		Version:       version,
		KeyID:         kid,
		WrappedDEK:    wrapped,
		Log2ChunkSize: log2C,
		HasChunkSize:  recorded,
	}

	// A multipart object names its manifest here. The id is not authenticated,
	// but it does not need to be: a wrong one simply fails to load a manifest
	// that verifies, because the manifest's MAC covers the id itself.
	if raw := lookup(metaManifestID); raw != "" {
		id, err := manifest.ParseID(raw)
		if err != nil {
			return Meta{}, fmt.Errorf("object metadata has an unreadable %s: %w",
				metaManifestID, err)
		}
		out.ManifestID, out.Multipart = id, true
	}
	return out, nil
}
