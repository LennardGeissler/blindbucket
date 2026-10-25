package rotate_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Rotating a single-part object changes the key that wraps its data key and
// nothing else the client can see.
func TestIntegrationRotateSinglePart(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "single.bin")
	payload := proxytest.RandomBytes(t, 5000)
	h.Store(t, key, payload)

	before := h.ObjectKID(t, key)
	cfg := h.RotateConfig(t, key)
	result, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Rotated != 1 {
		t.Fatalf("rotated %d objects, want 1 (%+v)", result.Rotated, *result)
	}

	if after := h.ObjectKID(t, key); after != cfg.TargetKID {
		t.Errorf("object still wrapped under %q, want %q", after, cfg.TargetKID)
	}
	if before == cfg.TargetKID {
		t.Fatal("the object was already on the target key; the test proves nothing")
	}
	if got := h.MustRead(t, key, "after rotation"); !bytes.Equal(got, payload) {
		t.Error("rotation changed the plaintext")
	}
}

// TestIntegrationRotateRefusedWithoutGuards: on a provider that ignores or
// refuses a conditional write, a guarded rotation does not start, says which
// guard is missing, and has touched nothing (ADR-020).
func TestIntegrationRotateRefusedWithoutGuards(t *testing.T) {
	h := proxytest.New(t)
	if testprovider.Require(t).Guarded() {
		t.Skip("the provider enforces both conditional writes; nothing to refuse")
	}
	key := proxytest.TestKey(t, "unguarded.bin")
	h.Store(t, key, proxytest.RandomBytes(t, 5000))
	before := h.ObjectKID(t, key)

	_, err := rotate.Run(t.Context(), h.UnguardedRotateConfig(t, key))
	var refusal *rotate.UnguardedError
	if !errors.As(err, &refusal) {
		t.Fatalf("rotate.Run returned %v, want an UnguardedError", err)
	}
	if refusal.Conditions.SafeForRotation() {
		t.Error("the refusal carries conditions that say it is safe")
	}
	if !strings.Contains(err.Error(), "--allow-unconditional") {
		t.Errorf("the refusal does not name the way out: %v", err)
	}
	if after := h.ObjectKID(t, key); after != before {
		t.Errorf("the refused run re-wrapped the object under %q", after)
	}
}

// TestIntegrationRotateUnconditional runs where a guarded rotation cannot: with
// --allow-unconditional, on every provider. It covers both copy paths -- a
// small single-part object goes through CopyObject, which is the only way to
// copy it on Garage, and a multipart object part by part.
func TestIntegrationRotateUnconditional(t *testing.T) {
	h := proxytest.New(t)
	prefix := proxytest.TestKey(t, "unconditional")

	small := proxytest.RandomBytes(t, 5000)
	h.Store(t, prefix+"/small.bin", small)
	parts := [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 321)}
	whole := h.MpuStore(t, prefix+"/multi.bin", parts)

	cfg := h.UnguardedRotateConfig(t, prefix+"/")
	cfg.AllowUnconditional = true
	result, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Rotated != 2 || result.Failed != 0 {
		t.Fatalf("rotated %d, failed %d; want 2 and 0 (%+v)", result.Rotated, result.Failed, *result)
	}
	for key, want := range map[string][]byte{prefix + "/small.bin": small, prefix + "/multi.bin": whole} {
		if kid := h.ObjectKID(t, key); kid != cfg.TargetKID {
			t.Errorf("%s wrapped under %q, want %q", key, kid, cfg.TargetKID)
		}
		if got := h.MustRead(t, key, "after rotation"); !bytes.Equal(got, want) {
			t.Errorf("%s: rotation changed the plaintext", key)
		}
	}
}

// contentHeaders are the headers a client stores with an object besides its
// metadata, and each one a rotation must carry over.
var contentHeaders = map[string]string{
	"Content-Type":        "application/x-test",
	"Cache-Control":       "max-age=60",
	"Content-Disposition": `attachment; filename="report.bin"`,
	"Content-Encoding":    "br",
	"Content-Language":    "de",
	"X-Amz-Meta-Owner":    "lennard",
}

// TestIntegrationRotateKeepsContentHeaders: what the client stored with an
// object is still there after the rotation, on every copy path -- the guarded
// one, and both unconditional ones, CopyObject for a small object and part by
// part for a multipart one.
func TestIntegrationRotateKeepsContentHeaders(t *testing.T) {
	for _, guarded := range []bool{true, false} {
		t.Run(fmt.Sprintf("guarded=%t", guarded), func(t *testing.T) {
			h := proxytest.New(t)
			prefix := proxytest.TestKey(t, "headers")
			small, multi := prefix+"/small.bin", prefix+"/multi.bin"

			resp := h.Put(t, small, proxytest.RandomBytes(t, 5000), contentHeaders)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("PUT returned %d", resp.StatusCode)
			}
			t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, small) })

			token := h.MpuStart(t, multi, contentHeaders)
			var completed []proxytest.CompletedPart
			for i, part := range [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 321)} {
				etag, resp := h.MpuPart(t, multi, token, i+1, part)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("part %d returned %d", i+1, resp.StatusCode)
				}
				completed = append(completed, proxytest.CompletedPart{PartNumber: i + 1, ETag: etag})
			}
			resp = h.MpuComplete(t, multi, token, completed)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("completion returned %d", resp.StatusCode)
			}

			var cfg rotate.Config
			if guarded {
				cfg = h.RotateConfig(t, prefix+"/")
			} else {
				cfg = h.UnguardedRotateConfig(t, prefix+"/")
				cfg.AllowUnconditional = true
			}
			result, err := rotate.Run(t.Context(), cfg)
			if err != nil {
				t.Fatalf("rotate: %v", err)
			}
			if result.Rotated != 2 {
				t.Fatalf("rotated %d objects, want 2 (%+v)", result.Rotated, *result)
			}

			for _, key := range []string{small, multi} {
				head := h.Do(t, http.MethodHead, key)
				_ = head.Body.Close()
				for name, want := range contentHeaders {
					if got := head.Header.Get(name); got != want {
						t.Errorf("%s: %s = %q after the rotation, want %q", key, name, got, want)
					}
				}
			}
		})
	}
}

// TestIntegrationRotateYieldsToAnUploadInProgress: an object a client is
// uploading over right now is left for a later run. A provider that ranks
// uploads by when they were created -- AWS S3 -- would discard the client's
// upload if it completed after the rotation's copy, and If-Match cannot see an
// upload that is still open (ADR-025, MCAwsRotate). Guarded where the provider
// allows it; unconditionally, through the same part-by-part copy, everywhere.
func TestIntegrationRotateYieldsToAnUploadInProgress(t *testing.T) {
	for _, guarded := range []bool{true, false} {
		t.Run(fmt.Sprintf("guarded=%t", guarded), func(t *testing.T) {
			h := proxytest.New(t)
			key := proxytest.TestKey(t, "busy.bin")
			h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 10)})
			before := h.ObjectKID(t, key)

			token := h.MpuStart(t, key, nil)
			clientWrote := proxytest.RandomBytes(t, 1000)
			etag := h.UploadOnePart(t, key, token, clientWrote)

			var cfg rotate.Config
			if guarded {
				cfg = h.RotateConfig(t, key)
			} else {
				cfg = h.UnguardedRotateConfig(t, key)
				cfg.AllowUnconditional = true
			}
			result, err := rotate.Run(t.Context(), cfg)
			if err != nil {
				t.Fatalf("rotate: %v", err)
			}
			if result.Conflicted != 1 || result.Rotated != 0 {
				t.Fatalf("with an upload open: %+v, want the object left as conflicted", *result)
			}
			if after := h.ObjectKID(t, key); after != before {
				t.Errorf("the object was re-wrapped under %q while a client was uploading", after)
			}

			resp := h.MpuComplete(t, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("the client's completion answered %d", resp.StatusCode)
			}
			if got := h.MustRead(t, key, "after the upload completed"); !bytes.Equal(got, clientWrote) {
				t.Error("the client's upload is not what the object holds")
			}

			if again, err := rotate.Run(t.Context(), cfg); err != nil || again.Rotated != 1 {
				t.Fatalf("the next run: %+v, %v; want the client's object rotated", again, err)
			}
		})
	}
}

// A multipart object keeps its part boundaries, because the copy is made part by
// part rather than flattened into one.
func TestIntegrationRotateMultipart(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "multi.bin")
	parts := [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 321)}
	whole := h.MpuStore(t, key, parts)

	oldManifest, oldID := h.ManifestKeyOf(t, key)

	cfg := h.RotateConfig(t, key)
	if _, err := rotate.Run(t.Context(), cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if after := h.ObjectKID(t, key); after != cfg.TargetKID {
		t.Errorf("object wrapped under %q, want %q", after, cfg.TargetKID)
	}

	// Rule R1: a new object version gets a new manifest id, never the old one.
	newManifest, newID := h.ManifestKeyOf(t, key)
	if newID == oldID {
		t.Error("the rotated object reuses the manifest id of the version it replaced")
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, oldManifest); err == nil {
		t.Error("the replaced manifest is still there")
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, newManifest); err != nil {
		t.Errorf("the new manifest is missing: %v", err)
	}

	// The ETag suffix is the part count, and the listing arithmetic depends on
	// it: a rotation that flattened the object would report the wrong size for
	// ever after.
	info, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, key)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	if !strings.HasSuffix(strings.Trim(info.ETag, `"`), "-3") {
		t.Errorf("ETag %q does not report three parts", info.ETag)
	}
	if got := h.List(t, key); got != int64(len(whole)) {
		t.Errorf("listing reports %d bytes after rotation, want %d", got, len(whole))
	}

	if got := h.MustRead(t, key, "after rotation"); !bytes.Equal(got, whole) {
		t.Error("rotation changed the plaintext")
	}
	// And a range still lands in the right part.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
	req.Header.Set("Range", "bytes=5242870-5242890")
	resp, err := h.Client.Do(req)
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "idempotent.bin")
	h.Store(t, key, proxytest.RandomBytes(t, 2048))

	cfg := h.RotateConfig(t, key)
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "foreign.bin")
	body := []byte("not written by the gateway")
	if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key,
		Body: bytes.NewReader(body), ContentLength: int64(len(body)),
	}); err != nil {
		t.Fatalf("writing the foreign object: %v", err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key) })

	result, err := rotate.Run(t.Context(), h.RotateConfig(t, key))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Foreign != 1 || result.Rotated != 0 || result.Failed != 0 {
		t.Errorf("got %+v, want one foreign object and nothing else", *result)
	}

	out, err := h.Upstream.GetObject(t.Context(), upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: key})
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

// The claim rotation exists for: the ciphertext never moves. Rotating megabytes
// must cost kilobytes.
func TestIntegrationRotateMovesNoData(t *testing.T) {
	h := proxytest.New(t)
	prefix := proxytest.TestKey(t, "nodata")

	var stored int64
	for i, size := range []int{200_000, 300_000, 500_000} {
		key := prefix + "/" + string(rune('a'+i)) + ".bin"
		h.Store(t, key, proxytest.RandomBytes(t, size))
		stored += int64(size)
	}

	counter := &proxytest.CountingTransport{Base: http.DefaultTransport}
	meteredCfg := proxytest.UpstreamConfig(t)
	meteredCfg.HTTPClient = &http.Client{Transport: counter}
	metered, err := upstream.New(meteredCfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	cfg := h.RotateConfig(t, prefix)
	cfg.Upstream = metered
	result, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.Rotated != 3 {
		t.Fatalf("rotated %d objects, want 3 (%+v)", result.Rotated, *result)
	}

	moved := counter.Bytes.Load()
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "contested.bin")

	original := proxytest.RandomBytes(t, 4096)
	clientWrote := proxytest.RandomBytes(t, 8192)
	h.Store(t, key, original)

	held := proxytest.NewGate()
	cfg := h.RotateConfig(t, key)
	var once sync.Once
	cfg.Hook = func(point, _ string) {
		if point == rotate.HookHead {
			once.Do(held.Wait)
		}
	}

	done := make(chan *rotate.Result, 1)
	errs := make(chan error, 1)
	go func() {
		result, err := rotate.Run(t.Context(), cfg)
		done <- result
		errs <- err
	}()
	held.Await(t, "the rotation to read the object")

	// The client replaces the object while the rotation is in flight. This is
	// the write that must survive.
	h.Store(t, key, clientWrote)

	held.Open()
	if err := <-errs; err != nil {
		t.Fatalf("rotate: %v", err)
	}
	result := <-done

	// The object the client wrote is the object that is there.
	got := h.MustRead(t, key, "after a rotation raced a client write")
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
	second, err := rotate.Run(t.Context(), h.RotateConfig(t, key))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Rotated != 1 {
		t.Errorf("the second run rotated %d objects, want 1", second.Rotated)
	}
	if after := h.MustRead(t, key, "after the second rotation"); !bytes.Equal(after, clientWrote) {
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
	h := proxytest.New(t)
	prefix := proxytest.TestKey(t, "scale")

	// 64 KiB rather than a token size: the claim is that the ciphertext does not
	// move, and at 1 KiB the five requests each object needs are larger than the
	// object, which hides the thing being measured behind protocol chatter.
	const objects = 1000
	payload := proxytest.RandomBytes(t, 64*1024)
	for i := range objects {
		resp := h.Put(t, fmt.Sprintf("%s/%04d.bin", prefix, i), payload, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("object %d: PUT returned %d", i, resp.StatusCode)
		}
	}
	t.Cleanup(func() {
		for i := range objects {
			_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket,
				fmt.Sprintf("%s/%04d.bin", prefix, i))
		}
	})
	stored := int64(objects) * int64(len(payload))

	counter := &proxytest.CountingTransport{Base: http.DefaultTransport}
	meteredCfg := proxytest.UpstreamConfig(t)
	meteredCfg.HTTPClient = &http.Client{Transport: counter}
	metered, err := upstream.New(meteredCfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	cfg := h.RotateConfig(t, prefix)
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
	moved := counter.Bytes.Load()
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
		if got := h.MustRead(t, key, "after rotating at scale"); !bytes.Equal(got, payload) {
			t.Fatalf("object %d changed", i)
		}
		if kid := h.ObjectKID(t, key); kid != cfg.TargetKID {
			t.Fatalf("object %d is on %q, want %q", i, kid, cfg.TargetKID)
		}
	}
}

// mib renders a byte count for a log line.
func mib(n int64) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
}

// TestIntegrationRotateKeepsTags: a rotation rewraps the data key, which moves
// the tag sidecar to a new name, and the object keeps its tags (ADR-037).
func TestIntegrationRotateKeepsTags(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "tagged.bin")
	h.CleanupStored(t, key)
	resp := h.Put(t, key, proxytest.RandomBytes(t, 5000), map[string]string{"X-Amz-Tagging": "team=platform&tier=gold"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: %d", resp.StatusCode)
	}
	cfg := h.RotateConfig(t, key)
	if result, err := rotate.Run(t.Context(), cfg); err != nil || result.Rotated != 1 {
		t.Fatalf("rotate: %+v, %v", result, err)
	}
	if after := h.ObjectKID(t, key); after != cfg.TargetKID {
		t.Fatalf("the object is still wrapped under %q", after)
	}
	if got := strings.Join(h.Tags(t, key), "&"); got != "team=platform&tier=gold" {
		t.Fatalf("after rotation the tags are %q", got)
	}
}
