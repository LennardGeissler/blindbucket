package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/freshness"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Rollback is the one attack in THREAT_MODEL §5 that the object format cannot
// catch on its own: the bytes are genuine, the wrap is bound to the right
// identity, every tag verifies. Only an index that remembers can tell.
//
// These run against a real provider, and the rollback is performed the way a
// provider would perform it -- by putting an earlier version's bytes and
// metadata back, outside the gateway. A fake upstream would prove nothing here,
// because what is being tested is whether genuine old data is refused.

// newIndex opens an empty index in the test's own temporary directory.
func newIndex(t *testing.T) *freshness.Local {
	t.Helper()
	key := make([]byte, freshness.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	index, err := freshness.Open(freshness.Options{
		Path: filepath.Join(t.TempDir(), "freshness.idx"),
		Key:  key,
	})
	if err != nil {
		t.Fatalf("freshness.Open: %v", err)
	}
	t.Cleanup(func() { _ = index.Close() })
	return index
}

// withFreshness turns rollback detection on for one test.
func withFreshness(t *testing.T) func(*Config) {
	t.Helper()
	index := newIndex(t)
	return func(c *Config) { c.Freshness = index }
}

// version is an object exactly as the provider holds it.
type version struct {
	body     []byte
	metadata map[string]string
}

// snapshot copies what the provider is holding, so it can be put back later.
// This is the whole attack: nothing is forged, an earlier genuine version is
// simply served again.
func (h *harness) snapshot(t *testing.T, key string) version {
	t.Helper()
	out, err := h.upstream.GetObject(context.Background(),
		upstream.GetObjectInput{Bucket: testBucket, Key: key})
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
func (h *harness) restore(t *testing.T, key string, v version) {
	t.Helper()
	if _, err := h.upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: testBucket, Key: key,
		Body: bytes.NewReader(v.body), ContentLength: int64(len(v.body)),
		Metadata: v.metadata,
	}); err != nil {
		t.Fatalf("restoring the earlier version: %v", err)
	}
}

func (h *harness) expectRollback(t *testing.T, method, key string, headers map[string]string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("%s returned %d, want 502: %s", method, resp.StatusCode, body)
	}
	if !strings.Contains(body, "RollbackDetected") {
		t.Errorf("%s answered %q; want RollbackDetected, not a generic failure", method, body)
	}
}

// TestRollbackIsRefused is the feature.
func TestRollbackIsRefused(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")

	h.store(t, key, []byte("the first version, which the client later replaced"))
	first := h.snapshot(t, key)

	second := []byte("the second version, which is the current one")
	h.store(t, key, second)
	// Reading it once is what puts the current version in the index.
	if got := h.getOK(t, key); got != string(second) {
		t.Fatalf("the current version read back as %q", got)
	}

	h.restore(t, key, first)
	h.expectRollback(t, http.MethodGet, key, nil)
}

// TestRollbackIsRefusedOnARange. A parallel downloader reads by ranges, so a
// check that only covered whole-object reads would be bypassed by every one of
// them.
func TestRollbackIsRefusedOnARange(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")

	h.store(t, key, bytes.Repeat([]byte("first "), 2000))
	first := h.snapshot(t, key)

	h.store(t, key, bytes.Repeat([]byte("second "), 2000))
	_ = h.getOK(t, key)

	h.restore(t, key, first)
	h.expectRollback(t, http.MethodGet, key, map[string]string{"Range": "bytes=100-200"})
}

// TestMultipartRollbackIsRefused. A multipart object is its manifest plus its
// segments, and a provider rolling one back would put both versions of both
// back. The tag covers every part's salt, so the pair is what it catches.
func TestMultipartRollbackIsRefused(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")

	h.storeParts(t, key, 5*1024*1024, 1024)
	manifestKey, _ := h.manifestKeyOf(t, key)
	firstObject := h.snapshot(t, key)
	firstManifest := h.snapshot(t, manifestKey)

	h.storeParts(t, key, 5*1024*1024, 2048)
	secondManifestKey, _ := h.manifestKeyOf(t, key)
	_ = h.getOK(t, key)

	// Both halves of the earlier version go back, which is what a provider with
	// versioning switched on would be able to do without forging anything.
	h.restore(t, manifestKey, firstManifest)
	h.restore(t, key, firstObject)
	t.Cleanup(func() {
		_ = h.upstream.DeleteObject(context.Background(), testBucket, manifestKey)
		_ = h.upstream.DeleteObject(context.Background(), testBucket, secondManifestKey)
	})

	h.expectRollback(t, http.MethodGet, key, nil)
}

// TestSuppressedDeleteIsRefused. Without a tombstone the index would still hold
// the object's tag, agree with it, and serve a key the client deleted.
func TestSuppressedDeleteIsRefused(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")

	h.store(t, key, []byte("deleted, but the provider kept a copy"))
	_ = h.getOK(t, key)
	stored := h.snapshot(t, key)

	resp := h.do(t, http.MethodDelete, key)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", resp.StatusCode)
	}

	// The provider ignored the delete.
	h.restore(t, key, stored)
	h.expectRollback(t, http.MethodGet, key, nil)
}

// TestTheCurrentVersionStillReads is the negative control. Every test above
// would also pass if the gateway refused everything.
func TestTheCurrentVersionStillReads(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")
	body := "nothing was rolled back, and this must come back unchanged"

	h.store(t, key, []byte(body))
	for i := range 3 {
		if got := h.getOK(t, key); got != body {
			t.Fatalf("read %d returned %q", i, got)
		}
	}
	// Overwriting is not a rollback either, and the new version must read back
	// without the index objecting to it.
	updated := "and neither is an ordinary overwrite"
	h.store(t, key, []byte(updated))
	if got := h.getOK(t, key); got != updated {
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
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")
	body := "written while one index was live, read after it was lost"

	h.store(t, key, []byte(body))
	if got := h.getOK(t, key); got != body {
		t.Fatalf("with the original index: %q", got)
	}

	// The index is lost and replaced with an empty one.
	h.gateway.fresh = newIndex(t)

	if got := h.getOK(t, key); got != body {
		t.Errorf("an object the new index has never seen: %q, want %q", got, body)
	}
	// And that first sighting is what puts it back under guard: a rollback after
	// it must be caught again.
	first := h.snapshot(t, key)
	h.store(t, key, []byte("a second version"))
	_ = h.getOK(t, key)
	h.restore(t, key, first)
	h.expectRollback(t, http.MethodGet, key, nil)
}

// TestACopiedObjectIsNotRefused. A server-side copy replaces the destination
// with ciphertext whose salts the gateway never reads, so the index is told to
// forget rather than to record. If it kept the entry instead, a copy over an
// existing object would make that object unreadable.
func TestACopiedObjectIsNotRefused(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	src := testKey(t, "src")
	dst := testKey(t, "dst")

	h.store(t, src, []byte("the source"))
	h.store(t, dst, []byte("the destination, about to be overwritten by a copy"))
	// Both are in the index now.
	_ = h.getOK(t, src)
	_ = h.getOK(t, dst)

	h.copyOK(t, src, dst, nil)
	if got := h.getOK(t, dst); got != "the source" {
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
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")
	body := "rotated onto a new KEK, and still the same write"

	h.store(t, key, []byte(body))
	if got := h.getOK(t, key); got != body {
		t.Fatalf("before the rotation: %q", got)
	}
	before := h.objectKID(t, key)

	result, err := rotate.Run(t.Context(), h.rotateConfig(t, key))
	if err != nil {
		t.Fatalf("rotate.Run: %v", err)
	}
	if result.Rotated != 1 {
		t.Fatalf("rotated %d objects, want 1", result.Rotated)
	}
	if after := h.objectKID(t, key); after == before {
		t.Fatalf("the object still records key %q; nothing was rotated", after)
	}

	// The index was not touched by the rotation, and must still agree.
	if got := h.getOK(t, key); got != body {
		t.Errorf("after the rotation: %q, want %q", got, body)
	}
}

// TestRotationDoesNotInvalidateAMultipartIndexEntry is the same property for the
// path that has more to go wrong: rotation mints a fresh manifest, and if the
// tag depended on the manifest id rather than on the salts it carries, this
// would refuse.
func TestRotationDoesNotInvalidateAMultipartIndexEntry(t *testing.T) {
	h := newHarness(t, withFreshness(t))
	key := testKey(t, "obj")

	h.storeParts(t, key, 5*1024*1024, 1024)
	before := h.getOK(t, key)
	manifestKey, _ := h.manifestKeyOf(t, key)
	t.Cleanup(func() {
		_ = h.upstream.DeleteObject(context.Background(), testBucket, manifestKey)
	})

	result, err := rotate.Run(t.Context(), h.rotateConfig(t, key))
	if err != nil {
		t.Fatalf("rotate.Run: %v", err)
	}
	if result.Rotated != 1 {
		t.Fatalf("rotated %d objects, want 1", result.Rotated)
	}
	rotatedManifest, _ := h.manifestKeyOf(t, key)
	t.Cleanup(func() {
		_ = h.upstream.DeleteObject(context.Background(), testBucket, rotatedManifest)
	})

	if got := h.getOK(t, key); got != before {
		t.Errorf("after rotating a multipart object the index refused it or the "+
			"content changed: %d bytes, want %d", len(got), len(before))
	}
}
