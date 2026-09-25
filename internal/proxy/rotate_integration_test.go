package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// rotateConfig builds a run against the harness, adding a second KEK to rotate
// onto.
func (h *harness) rotateConfig(t *testing.T, prefix string) rotate.Config {
	t.Helper()
	const target = "rotated-key"
	if !hasKID(h.keyring, target) {
		if err := h.keyring.Generate(target); err != nil {
			t.Fatalf("Generate: %v", err)
		}
	}
	return rotate.Config{
		Upstream: h.upstream, Keys: h.keyring, Bucket: testBucket, Prefix: prefix,
		TargetKID: target, Log2ChunkSize: stream.MinLog2ChunkSize,
		Concurrency: 4, Log: discardLogger(),
	}
}

func hasKID(ring *keys.Keyring, kid string) bool {
	for _, k := range ring.KIDs() {
		if k == kid {
			return true
		}
	}
	return false
}

// objectKID reads the key id an object records.
func (h *harness) objectKID(t *testing.T, key string) string {
	t.Helper()
	info, err := h.upstream.HeadObject(t.Context(), testBucket, key)
	if err != nil {
		t.Fatalf("HEAD %q: %v", key, err)
	}
	meta, err := objectmeta.Parse(info.Metadata, stream.MinLog2ChunkSize)
	if err != nil {
		t.Fatalf("parsing metadata of %q: %v", key, err)
	}
	return meta.KeyID
}

// Rotating a single-part object changes the key that wraps its data key and
// nothing else the client can see.
func TestIntegrationRotateSinglePart(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "single.bin")
	payload := randomBytes(t, 5000)
	h.store(t, key, payload)

	before := h.objectKID(t, key)
	cfg := h.rotateConfig(t, key)
	result, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Rotated != 1 {
		t.Fatalf("rotated %d objects, want 1 (%+v)", result.Rotated, *result)
	}

	if after := h.objectKID(t, key); after != cfg.TargetKID {
		t.Errorf("object still wrapped under %q, want %q", after, cfg.TargetKID)
	}
	if before == cfg.TargetKID {
		t.Fatal("the object was already on the target key; the test proves nothing")
	}
	if got := h.mustRead(t, key, "after rotation"); !bytes.Equal(got, payload) {
		t.Error("rotation changed the plaintext")
	}
}

// A multipart object keeps its part boundaries, because the copy is made part by
// part rather than flattened into one.
func TestIntegrationRotateMultipart(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "multi.bin")
	parts := [][]byte{randomBytes(t, testPart), randomBytes(t, testPart), randomBytes(t, 321)}
	whole := h.mpuStore(t, key, parts)

	oldManifest, oldID := h.manifestKeyOf(t, key)

	cfg := h.rotateConfig(t, key)
	if _, err := rotate.Run(t.Context(), cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if after := h.objectKID(t, key); after != cfg.TargetKID {
		t.Errorf("object wrapped under %q, want %q", after, cfg.TargetKID)
	}

	// Rule R1: a new object version gets a new manifest id, never the old one.
	newManifest, newID := h.manifestKeyOf(t, key)
	if newID == oldID {
		t.Error("the rotated object reuses the manifest id of the version it replaced")
	}
	if _, err := h.upstream.HeadObject(t.Context(), testBucket, oldManifest); err == nil {
		t.Error("the replaced manifest is still there")
	}
	if _, err := h.upstream.HeadObject(t.Context(), testBucket, newManifest); err != nil {
		t.Errorf("the new manifest is missing: %v", err)
	}

	// The ETag suffix is the part count, and the listing arithmetic depends on
	// it: a rotation that flattened the object would report the wrong size for
	// ever after.
	info, err := h.upstream.HeadObject(t.Context(), testBucket, key)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	if !strings.HasSuffix(strings.Trim(info.ETag, `"`), "-3") {
		t.Errorf("ETag %q does not report three parts", info.ETag)
	}
	if got := h.list(t, key); got != int64(len(whole)) {
		t.Errorf("listing reports %d bytes after rotation, want %d", got, len(whole))
	}

	if got := h.mustRead(t, key, "after rotation"); !bytes.Equal(got, whole) {
		t.Error("rotation changed the plaintext")
	}
	// And a range still lands in the right part.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	req.Header.Set("Range", "bytes=5242870-5242890")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("ranged GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got := make([]byte, 21)
	if _, err := resp.Body.Read(got); err != nil && err.Error() != "EOF" {
		t.Fatalf("reading the range: %v", err)
	}
	if !bytes.Equal(got, whole[5242870:5242891]) {
		t.Error("a range across the first part boundary is wrong after rotation")
	}
}

// A second run does nothing, which is what makes an interrupted rotation safe to
// restart.
func TestIntegrationRotateIsIdempotent(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "idempotent.bin")
	h.store(t, key, randomBytes(t, 2048))

	cfg := h.rotateConfig(t, key)
	first, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if first.Rotated != 1 || second.Rotated != 0 {
		t.Errorf("rotated %d then %d, want 1 then 0", first.Rotated, second.Rotated)
	}
	if second.AlreadyCurrent != 1 {
		t.Errorf("second run reported %d already current, want 1", second.AlreadyCurrent)
	}
}

// A bucket may hold objects this gateway never wrote. They have no wrapped key,
// so rotation leaves them alone rather than failing.
func TestIntegrationRotateLeavesForeignObjectsAlone(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "foreign.bin")
	body := []byte("not written by the gateway")
	if _, err := h.upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: testBucket, Key: key,
		Body: bytes.NewReader(body), ContentLength: int64(len(body)),
	}); err != nil {
		t.Fatalf("writing the foreign object: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, key) })

	result, err := rotate.Run(t.Context(), h.rotateConfig(t, key))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Foreign != 1 || result.Rotated != 0 || result.Failed != 0 {
		t.Errorf("got %+v, want one foreign object and nothing else", *result)
	}

	out, err := h.upstream.GetObject(t.Context(), upstream.GetObjectInput{Bucket: testBucket, Key: key})
	if err != nil {
		t.Fatalf("the foreign object is gone: %v", err)
	}
	defer func() { _ = out.Body.Close() }()
	got := make([]byte, len(body))
	_, _ = out.Body.Read(got)
	if !bytes.Equal(got, body) {
		t.Error("rotation modified an object it does not own")
	}
}

// countingTransport totals the body bytes that actually cross the wire.
//
// It counts bytes *read*, not the Content-Length a response declares. A HEAD
// answers with the object's Content-Length and no body at all, so counting the
// header would charge this test the full size of every object it looked at --
// which is exactly the number it is trying to prove does not move.
type countingTransport struct {
	base  http.RoundTripper
	bytes atomic.Int64
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

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.ContentLength > 0 {
		c.bytes.Add(req.ContentLength)
	}
	resp, err := c.base.RoundTrip(req)
	if err == nil && resp.Body != nil {
		resp.Body = countingBody{ReadCloser: resp.Body, total: &c.bytes}
	}
	return resp, err
}

// The claim rotation exists for: the ciphertext never moves. Rotating megabytes
// must cost kilobytes.
func TestIntegrationRotateMovesNoData(t *testing.T) {
	h := newHarness(t)
	prefix := testKey(t, "nodata")

	var stored int64
	for i, size := range []int{200_000, 300_000, 500_000} {
		key := prefix + "/" + string(rune('a'+i)) + ".bin"
		h.store(t, key, randomBytes(t, size))
		stored += int64(size)
	}

	counter := &countingTransport{base: http.DefaultTransport}
	meteredCfg := upstreamConfig(t)
	meteredCfg.HTTPClient = &http.Client{Transport: counter}
	metered, err := upstream.New(meteredCfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	cfg := h.rotateConfig(t, prefix)
	cfg.Upstream = metered
	result, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Rotated != 3 {
		t.Fatalf("rotated %d objects, want 3 (%+v)", result.Rotated, *result)
	}

	moved := counter.bytes.Load()
	// Generous: the point is orders of magnitude, not a tight bound. A rotation
	// that read and rewrote the bodies would move at least `stored` bytes twice.
	if moved > stored/50 {
		t.Errorf("rotation moved %d bytes for %d bytes of objects; it is copying data",
			moved, stored)
	}
	t.Logf("rotated %d bytes of objects while moving %d bytes over the wire", stored, moved)
}

// TestIntegrationRotateDoesNotLoseUpdates is invariant I2, and the last of the
// four counterexamples from spec/tla/ to get an integration test.
//
// The model's trace is six states: rotation reads the object, a client replaces
// it, rotation completes, and the client's write is gone. The conditional write
// is what stops it -- the completion carries If-Match with the etag rotation read
// at the start, so a client write in between turns the completion into a 412 and
// the object is skipped. This drives exactly that interleaving.
func TestIntegrationRotateDoesNotLoseUpdates(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "contested.bin")

	original := randomBytes(t, 4096)
	clientWrote := randomBytes(t, 8192)
	h.store(t, key, original)

	held := newGate()
	cfg := h.rotateConfig(t, key)
	var once sync.Once
	cfg.Hook = func(point, _ string) {
		if point == rotate.HookHead {
			once.Do(held.wait)
		}
	}

	done := make(chan *rotate.Result, 1)
	errs := make(chan error, 1)
	go func() {
		result, err := rotate.Run(t.Context(), cfg)
		done <- result
		errs <- err
	}()
	held.await(t, "the rotation to read the object")

	// The client replaces the object while the rotation is in flight. This is
	// the write that must survive.
	h.store(t, key, clientWrote)

	held.open()
	if err := <-errs; err != nil {
		t.Fatalf("rotate: %v", err)
	}
	result := <-done

	// The object the client wrote is the object that is there.
	got := h.mustRead(t, key, "after a rotation raced a client write")
	if bytes.Equal(got, original) {
		t.Fatal("the client's write was replaced by the pre-rotation version: I2 violated")
	}
	if !bytes.Equal(got, clientWrote) {
		t.Fatalf("the object is neither version: %d bytes", len(got))
	}

	// And the rotation says so, rather than reporting success.
	if result.Rotated != 0 || result.Conflicted != 1 {
		t.Errorf("got %+v, want nothing rotated and one conflict", *result)
	}

	// A later run picks it up, which is what makes the skip harmless.
	second, err := rotate.Run(t.Context(), h.rotateConfig(t, key))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Rotated != 1 {
		t.Errorf("the second run rotated %d objects, want 1", second.Rotated)
	}
	if after := h.mustRead(t, key, "after the second rotation"); !bytes.Equal(after, clientWrote) {
		t.Error("the second rotation changed the plaintext")
	}
}

// TestIntegrationRotateAtScale is the M5 definition of done: a prefix of a
// thousand objects rotated with no data transfer, shown with byte counters
// rather than asserted.
//
// It is off by default because writing a thousand objects through the gateway
// takes longer than a unit test should:
//
//	BLINDBUCKET_TEST_SCALE=1 go test ./internal/proxy -run RotateAtScale -v
func TestIntegrationRotateAtScale(t *testing.T) {
	if os.Getenv("BLINDBUCKET_TEST_SCALE") == "" {
		t.Skip("set BLINDBUCKET_TEST_SCALE=1 to rotate a thousand objects")
	}
	h := newHarness(t)
	prefix := testKey(t, "scale")

	// 64 KiB rather than a token size: the claim is that the ciphertext does not
	// move, and at 1 KiB the five requests each object needs are larger than the
	// object, which hides the thing being measured behind protocol chatter.
	const objects = 1000
	payload := randomBytes(t, 64*1024)
	for i := range objects {
		resp := h.put(t, fmt.Sprintf("%s/%04d.bin", prefix, i), payload, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("object %d: PUT returned %d", i, resp.StatusCode)
		}
	}
	t.Cleanup(func() {
		for i := range objects {
			_ = h.upstream.DeleteObject(context.Background(), testBucket,
				fmt.Sprintf("%s/%04d.bin", prefix, i))
		}
	})
	stored := int64(objects) * int64(len(payload))

	counter := &countingTransport{base: http.DefaultTransport}
	meteredCfg := upstreamConfig(t)
	meteredCfg.HTTPClient = &http.Client{Transport: counter}
	metered, err := upstream.New(meteredCfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	cfg := h.rotateConfig(t, prefix)
	cfg.Upstream = metered
	cfg.Concurrency = 16

	started := time.Now()
	result, err := rotate.Run(t.Context(), cfg)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if result.Rotated != objects {
		t.Fatalf("rotated %d of %d objects (%+v)", result.Rotated, objects, *result)
	}
	moved := counter.bytes.Load()
	perObject := moved / objects
	t.Logf("rotated %d objects (%s of payload) in %s, moving %s over the wire "+
		"-- %d bytes per object, %.0f:1",
		objects, mib(stored), elapsed.Round(time.Millisecond), mib(moved),
		perObject, float64(stored)/float64(moved))

	// The invariant is that the wire cost is O(objects), not O(bytes): five
	// small requests per object whatever the object weighs. Asserting on the
	// ratio alone would pass or fail depending on the payload size chosen here.
	if perObject > 4096 {
		t.Errorf("%d bytes moved per object; the bodies are being copied", perObject)
	}
	if moved > stored/10 {
		t.Errorf("moved %d bytes for %d bytes of objects; data is being copied", moved, stored)
	}

	// A sample still decrypts to what was written.
	for _, i := range []int{0, objects / 2, objects - 1} {
		key := fmt.Sprintf("%s/%04d.bin", prefix, i)
		if got := h.mustRead(t, key, "after rotating at scale"); !bytes.Equal(got, payload) {
			t.Fatalf("object %d changed", i)
		}
		if kid := h.objectKID(t, key); kid != cfg.TargetKID {
			t.Fatalf("object %d is on %q, want %q", i, kid, cfg.TargetKID)
		}
	}
}

// mib renders a byte count for a log line.
func mib(n int64) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
}
