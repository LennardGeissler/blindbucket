package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/freshness"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// swappableIndex is a freshness.Store whose index a test can replace while
// the gateway runs, as if the gateway had restarted with a lost index -- but
// with the same keyring, which a rebuilt gateway would not have.
type swappableIndex struct {
	mu    sync.Mutex
	store freshness.Store
}

func (s *swappableIndex) swap(to freshness.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = to
}

func (s *swappableIndex) current() freshness.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store
}

func (s *swappableIndex) Check(bucket, key string, tag freshness.Tag) (freshness.Verdict, error) {
	return s.current().Check(bucket, key, tag)
}

func (s *swappableIndex) Record(bucket, key string, tag freshness.Tag) error {
	return s.current().Record(bucket, key, tag)
}

func (s *swappableIndex) Forget(bucket, key string) error { return s.current().Forget(bucket, key) }

func (s *swappableIndex) Invalidate(bucket, key string) error {
	return s.current().Invalidate(bucket, key)
}

func (s *swappableIndex) Stats() freshness.Stats { return s.current().Stats() }

func (s *swappableIndex) Close() error { return s.current().Close() }

// version is an object exactly as the provider holds it.
type version struct {
	body     []byte
	metadata map[string]string
}

// snapshot copies what the provider is holding, so it can be put back later.
// This is the whole attack: nothing is forged, an earlier genuine version is
// simply served again.
func snapshot(t *testing.T, h *proxytest.Harness, key string) version {
	t.Helper()
	out, err := h.Upstream.GetObject(context.Background(),
		upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: key})
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}
	body, err := io.ReadAll(out.Body)
	_ = out.Body.Close()
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}
	return version{body: body, metadata: out.Metadata}
}

// restore puts an earlier version back, behind the gateway's back.
func restore(t *testing.T, h *proxytest.Harness, key string, v version) {
	t.Helper()
	if _, err := h.Upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key,
		Body: bytes.NewReader(v.body), ContentLength: int64(len(v.body)),
		Metadata: v.metadata,
	}); err != nil {
		t.Fatalf("restoring the earlier version: %v", err)
	}
}

func expectRollback(t *testing.T, h *proxytest.Harness, method, key string, headers map[string]string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.URL(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := proxytest.ReadBody(t, resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("%s returned %d, want 502: %s", method, resp.StatusCode, body)
	}
	if !strings.Contains(body, "RollbackDetected") {
		t.Errorf("%s answered %q; want RollbackDetected, not a generic failure", method, body)
	}
}

// TestRollbackIsRefused is the feature.
func TestRollbackIsRefused(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")

	h.Store(t, key, []byte("the first version, which the client later replaced"))
	first := snapshot(t, h, key)

	second := []byte("the second version, which is the current one")
	h.Store(t, key, second)
	// Reading it once is what puts the current version in the index.
	if got := getOK(t, h, key); got != string(second) {
		t.Fatalf("the current version read back as %q", got)
	}

	restore(t, h, key, first)
	expectRollback(t, h, http.MethodGet, key, nil)
}

// TestRollbackIsRefusedOnARange. A parallel downloader reads by ranges, so a
// check that only covered whole-object reads would be bypassed by every one of
// them.
func TestRollbackIsRefusedOnARange(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")

	h.Store(t, key, bytes.Repeat([]byte("first "), 2000))
	first := snapshot(t, h, key)

	h.Store(t, key, bytes.Repeat([]byte("second "), 2000))
	_ = getOK(t, h, key)

	restore(t, h, key, first)
	expectRollback(t, h, http.MethodGet, key, map[string]string{"Range": "bytes=100-200"})
}

// TestMultipartRollbackIsRefused. A multipart object is its manifest plus its
// segments, and a provider rolling one back would put both versions of both
// back. The tag covers every part's salt, so the pair is what it catches.
func TestMultipartRollbackIsRefused(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")

	h.StoreParts(t, key, 5*1024*1024, 1024)
	manifestKey, _ := h.ManifestKeyOf(t, key)
	firstObject := snapshot(t, h, key)
	firstManifest := snapshot(t, h, manifestKey)

	h.StoreParts(t, key, 5*1024*1024, 2048)
	secondManifestKey, _ := h.ManifestKeyOf(t, key)
	_ = getOK(t, h, key)

	// Both halves of the earlier version go back, which is what a provider with
	// versioning switched on would be able to do without forging anything.
	restore(t, h, manifestKey, firstManifest)
	restore(t, h, key, firstObject)
	t.Cleanup(func() {
		_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, manifestKey)
		_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, secondManifestKey)
	})

	expectRollback(t, h, http.MethodGet, key, nil)
}

// TestSuppressedDeleteIsRefused. Without a tombstone the index would still hold
// the object's tag, agree with it, and serve a key the client deleted.
func TestSuppressedDeleteIsRefused(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")

	h.Store(t, key, []byte("deleted, but the provider kept a copy"))
	_ = getOK(t, h, key)
	stored := snapshot(t, h, key)

	resp := h.Do(t, http.MethodDelete, key)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", resp.StatusCode)
	}

	// The provider ignored the delete.
	restore(t, h, key, stored)
	expectRollback(t, h, http.MethodGet, key, nil)
}

// TestTheCurrentVersionStillReads is the negative control. Every test above
// would also pass if the gateway refused everything.
func TestTheCurrentVersionStillReads(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")
	body := "nothing was rolled back, and this must come back unchanged"

	h.Store(t, key, []byte(body))
	for i := range 3 {
		if got := getOK(t, h, key); got != body {
			t.Fatalf("read %d returned %q", i, got)
		}
	}
	// Overwriting is not a rollback either, and the new version must read back
	// without the index objecting to it.
	updated := "and neither is an ordinary overwrite"
	h.Store(t, key, []byte(updated))
	if got := getOK(t, h, key); got != updated {
		t.Errorf("after an overwrite: %q, want %q", got, updated)
	}
}

// TestFirstSightingOfAnUnknownObjectIsServed is the trust-on-first-use bound,
// stated as a test rather than only in the ADR. An index that has just been
// created, or lost, knows nothing -- and refusing every object until it has
// learned them would make a replaced disk an outage, which ADR-018 rejects in
// those words.
//
// The index is swapped rather than the gateway rebuilt, because a second
// harness would bring a second keyring with it and the object would fail to
// unwrap for reasons that have nothing to do with freshness.
func TestFirstSightingOfAnUnknownObjectIsServed(t *testing.T) {
	index := &swappableIndex{}
	index.swap(proxytest.NewIndex(t))
	h := proxytest.New(t, func(c *proxy.Config) { c.Freshness = index })
	key := proxytest.TestKey(t, "obj")
	body := "written while one index was live, read after it was lost"

	h.Store(t, key, []byte(body))
	if got := getOK(t, h, key); got != body {
		t.Fatalf("with the original index: %q", got)
	}

	// The index is lost and replaced with an empty one.
	index.swap(proxytest.NewIndex(t))

	if got := getOK(t, h, key); got != body {
		t.Errorf("an object the new index has never seen: %q, want %q", got, body)
	}
	// And that first sighting is what puts it back under guard: a rollback after
	// it must be caught again.
	first := snapshot(t, h, key)
	h.Store(t, key, []byte("a second version"))
	_ = getOK(t, h, key)
	restore(t, h, key, first)
	expectRollback(t, h, http.MethodGet, key, nil)
}

// TestACopiedObjectIsNotRefused. A server-side copy replaces the destination
// with ciphertext whose salts the gateway never reads, so the index is told to
// forget rather than to record. If it kept the entry instead, a copy over an
// existing object would make that object unreadable.
func TestACopiedObjectIsNotRefused(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	src := proxytest.TestKey(t, "src")
	dst := proxytest.TestKey(t, "dst")

	h.Store(t, src, []byte("the source"))
	h.Store(t, dst, []byte("the destination, about to be overwritten by a copy"))
	// Both are in the index now.
	_ = getOK(t, h, src)
	_ = getOK(t, h, dst)

	copyOK(t, h, src, dst, nil)
	if got := getOK(t, h, dst); got != "the source" {
		t.Errorf("after a copy over a known object: %q", got)
	}
}

// TestRotationDoesNotInvalidateTheIndex is the property the tag's shape was
// chosen for, and the reason it is a hash over segment salts rather than over
// the wrapped data key.
//
// ADR-009 rotates by re-wrapping metadata and explicitly does not move
// ciphertext. The salts live in the ciphertext, so a rotated object is the same
// write and the index needs no update. Had the tag covered the wrapped key
// instead -- the other obvious candidate, and the one considered first -- every
// rotation would have invalidated every entry, and an operator rotating a KEK
// would have turned the whole bucket unreadable until each object had been read
// once.
func TestRotationDoesNotInvalidateTheIndex(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")
	body := "rotated onto a new KEK, and still the same write"

	h.Store(t, key, []byte(body))
	if got := getOK(t, h, key); got != body {
		t.Fatalf("before the rotation: %q", got)
	}
	before := h.ObjectKID(t, key)

	result, err := rotate.Run(t.Context(), h.RotateConfig(t, key))
	if err != nil {
		t.Fatalf("rotate.Run: %v", err)
	}
	if result.Rotated != 1 {
		t.Fatalf("rotated %d objects, want 1", result.Rotated)
	}
	if after := h.ObjectKID(t, key); after == before {
		t.Fatalf("the object still records key %q; nothing was rotated", after)
	}

	// The index was not touched by the rotation, and must still agree.
	if got := getOK(t, h, key); got != body {
		t.Errorf("after the rotation: %q, want %q", got, body)
	}
}

// TestRotationDoesNotInvalidateAMultipartIndexEntry is the same property for the
// path that has more to go wrong: rotation mints a fresh manifest, and if the
// tag depended on the manifest id rather than on the salts it carries, this
// would refuse.
func TestRotationDoesNotInvalidateAMultipartIndexEntry(t *testing.T) {
	h := proxytest.New(t, proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "obj")

	h.StoreParts(t, key, 5*1024*1024, 1024)
	before := getOK(t, h, key)
	manifestKey, _ := h.ManifestKeyOf(t, key)
	t.Cleanup(func() {
		_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, manifestKey)
	})

	result, err := rotate.Run(t.Context(), h.RotateConfig(t, key))
	if err != nil {
		t.Fatalf("rotate.Run: %v", err)
	}
	if result.Rotated != 1 {
		t.Fatalf("rotated %d objects, want 1", result.Rotated)
	}
	rotatedManifest, _ := h.ManifestKeyOf(t, key)
	t.Cleanup(func() {
		_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, rotatedManifest)
	})

	if got := getOK(t, h, key); got != before {
		t.Errorf("after rotating a multipart object the index refused it or the "+
			"content changed: %d bytes, want %d", len(got), len(before))
	}
}
