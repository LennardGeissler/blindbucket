package proxytest

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
)

// These are the multipart entries in the attack catalogue: what a storage
// provider that is actively hostile, rather than merely unreliable, can do to a
// multipart object. Every one of them must end in a refusal, never in plaintext
// and never in a silently different object.

// ManifestKeyOf returns where an object's manifest is stored.
func (h *Harness) ManifestKeyOf(t *testing.T, key string) (string, manifest.ID) {
	t.Helper()
	info, err := h.Upstream.HeadObject(t.Context(), Bucket, key)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	for name, value := range info.Metadata {
		if strings.EqualFold(name, "bb-mid") {
			id, err := manifest.ParseID(value)
			if err != nil {
				t.Fatalf("bb-mid is unreadable: %v", err)
			}
			return id.ObjectKey(key), id
		}
	}
	t.Fatalf("object %q carries no bb-mid", key)
	return "", manifest.ID{}
}

// StoreParts uploads a multipart object and returns the parts it was built from.
func (h *Harness) StoreParts(t *testing.T, key string, sizes ...int) [][]byte {
	t.Helper()
	parts := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		parts = append(parts, RandomBytes(t, size))
	}
	h.MpuStore(t, key, parts)
	t.Cleanup(func() {
		mk, _ := h.ManifestKeyOfQuiet(key)
		if mk != "" {
			_ = h.Upstream.DeleteObject(context.Background(), Bucket, mk)
		}
	})
	return parts
}

// ManifestKeyOfQuiet is ManifestKeyOf for a test that expects there may be no
// manifest: it reports that instead of failing.
func (h *Harness) ManifestKeyOfQuiet(key string) (string, bool) {
	info, err := h.Upstream.HeadObject(context.Background(), Bucket, key)
	if err != nil {
		return "", false
	}
	for name, value := range info.Metadata {
		if strings.EqualFold(name, "bb-mid") {
			id, err := manifest.ParseID(value)
			if err != nil {
				return "", false
			}
			return id.ObjectKey(key), true
		}
	}
	return "", false
}

// ReencryptPart produces the ciphertext of one part as this gateway would have
// written it, under the object's own data key and a fresh salt.
//
// It stands in for an earlier upload attempt: the gateway wrote one exactly
// like this, and the provider kept it.
func (h *Harness) ReencryptPart(t *testing.T, key string, partNumber uint32, plain []byte) []byte {
	t.Helper()
	ctx := context.Background()

	info, err := h.Upstream.HeadObject(ctx, Bucket, key)
	if err != nil {
		t.Fatalf("HEAD upstream: %v", err)
	}
	meta, err := objectmeta.Parse(info.Metadata, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("parsing metadata: %v", err)
	}
	aad, err := keys.ObjectAAD(meta.KeyID, Bucket, key)
	if err != nil {
		t.Fatalf("ObjectAAD: %v", err)
	}
	dek, err := h.Keyring.Unwrap(ctx, meta.KeyID, meta.WrappedDEK, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	defer clear(dek)

	var buf bytes.Buffer
	ew, err := stream.NewEncryptWriter(&buf, dek, stream.SegmentParams{
		Log2ChunkSize: meta.Log2ChunkSize, Multipart: true, Index: partNumber,
	})
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := ew.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}
