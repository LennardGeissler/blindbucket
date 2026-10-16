package proxytest

import (
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// RotateConfig builds a run against the harness, adding a second KEK to rotate
// onto.
//
// A guarded rotation is refused on a provider that does not enforce both
// conditional writes, so these tests skip there. What the refusal looks like is
// TestIntegrationRotateRefusedWithoutGuards; what rotation does on such a
// provider is TestIntegrationRotateUnconditional.
func (h *Harness) RotateConfig(t *testing.T, prefix string) rotate.Config {
	t.Helper()
	if p := testprovider.Require(t); !p.Guarded() {
		t.Skipf("the provider does not enforce both conditional writes "+
			"(copy source: %s, completion: %s), so a guarded rotation is refused",
			p.CopySourceIfMatch, p.CompleteIfMatch)
	}
	return h.UnguardedRotateConfig(t, prefix)
}

// UnguardedRotateConfig is rotateConfig without the skip, for the tests that
// run on every provider.
func (h *Harness) UnguardedRotateConfig(t *testing.T, prefix string) rotate.Config {
	t.Helper()
	const target = "rotated-key"
	if !HasKID(h.Keyring, target) {
		if err := h.Keyring.Generate(target); err != nil {
			t.Fatalf("Generate: %v", err)
		}
	}
	return rotate.Config{
		Upstream: h.Upstream, Keys: h.Keyring, Bucket: Bucket, Prefix: prefix,
		TargetKID: target, Log2ChunkSize: stream.MinLog2ChunkSize,
		Concurrency: 4, Log: DiscardLogger(),
	}
}

// HasKID reports whether ring holds the key kid.
func HasKID(ring *keys.Keyring, kid string) bool {
	for _, k := range ring.KIDs() {
		if k == kid {
			return true
		}
	}
	return false
}

// ObjectKID reads the key id an object records.
func (h *Harness) ObjectKID(t *testing.T, key string) string {
	t.Helper()
	info, err := h.Upstream.HeadObject(t.Context(), Bucket, key)
	if err != nil {
		t.Fatalf("HEAD %q: %v", key, err)
	}
	meta, err := objectmeta.Parse(info.Metadata, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("parsing metadata of %q: %v", key, err)
	}
	return meta.KeyID
}

// CountingTransport totals the body bytes that actually cross the wire.
//
// It counts bytes *read*, not the Content-Length a response declares. A HEAD
// answers with the object's Content-Length and no body at all, so counting the
// header would charge this test the full size of every object it looked at --
// which is exactly the number it is trying to prove does not move.
type CountingTransport struct {
	Base  http.RoundTripper
	Bytes atomic.Int64
}

type countingBody struct {
	io.ReadCloser
	total *atomic.Int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.total.Add(int64(n))
	return n, err
}

// RoundTrip counts what req and its response carry.
func (c *CountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.ContentLength > 0 {
		c.Bytes.Add(req.ContentLength)
	}
	resp, err := c.Base.RoundTrip(req)
	if err == nil && resp.Body != nil {
		resp.Body = countingBody{ReadCloser: resp.Body, total: &c.Bytes}
	}
	return resp, err
}
