package proxy_test

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"sync"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/gc"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// holdAt installs a hook that holds the named point of the request carrying
// uploadID. Points for other requests pass straight through.
func holdAt(t *testing.T, h *proxytest.Harness, gates map[string]*proxytest.Gate) {
	t.Helper()
	proxy.SetHook(h.Gateway, func(point string, req s3api.Request) {
		if g, ok := gates[point+"|"+req.UploadID]; ok {
			g.Wait()
		}
	})
	t.Cleanup(func() { proxy.SetHook(h.Gateway, nil) })
}

// Scenario 1 of spec/tla/README.md, the second race ADR-010 records.
//
// Version 0.1 had a completion delete "the other manifests of this key". TLC
// reaches an unreadable object in eleven states: u1 completes, u2 writes its
// manifest, u1's cleanup runs late and takes u2's manifest with it, u2
// completes. Rule R3 replaces that with "only the id observed before my own
// replacement", which is what this test holds u1 open to exercise.
func TestIntegrationRaceCleanupAgainstConcurrentUpload(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "contested.bin")

	// A single-part object is visible first, exactly as in the trace, so that
	// u1's HEAD observes no manifest at all.
	h.Store(t, key, proxytest.RandomBytes(t, 4096))

	tokenA := h.MpuStart(t, key, nil)
	tokenB := h.MpuStart(t, key, nil)
	partA := proxytest.RandomBytes(t, proxytest.TestPart)
	partB := proxytest.RandomBytes(t, proxytest.TestPart)
	etagA := h.UploadOnePart(t, key, tokenA, partA)
	etagB := h.UploadOnePart(t, key, tokenB, partB)

	// u1 is held after its completion, before its cleanup. u2 is held after it
	// has written its manifest.
	holdA := proxytest.NewGate()
	holdB := proxytest.NewGate()
	holdAt(t, h, map[string]*proxytest.Gate{
		proxy.HookUpComplete + "|" + tokenA: holdA,
		proxy.HookUpManifest + "|" + tokenB: holdB,
	})

	doneA := completeAsync(t, h, key, tokenA, etagA)
	holdA.Await(t, "u1 to finish completing")

	doneB := completeAsync(t, h, key, tokenB, etagB)
	holdB.Await(t, "u2 to write its manifest")

	// Now u1 runs its cleanup while u2's manifest is already on the provider.
	// Under the version 0.1 rule this is where u2's manifest disappeared.
	holdA.Open()
	if status := <-doneA; status != http.StatusOK {
		t.Fatalf("u1 completion returned %d", status)
	}

	holdB.Open()
	if status := <-doneB; status != http.StatusOK {
		t.Fatalf("u2 completion returned %d", status)
	}

	// The object is whichever upload completed last, and it must be readable.
	got := h.MustRead(t, key, "after the interleaved cleanup")
	if !bytes.Equal(got, partB) {
		t.Errorf("the visible object is not u2's: got %d bytes, want %d", len(got), len(partB))
	}
}

// Scenario 2 of spec/tla/README.md, the first race ADR-010 records.
//
// Version 0.1's gc listed the manifests, read the current id and deleted the
// rest, with no regard for uploads in flight. TLC's trace: an upload writes its
// manifest, gc sees it is not the current one and removes it, the upload then
// completes and the object is unreadable. R4 step 2 closes it by skipping any
// key with an open upload.
func TestIntegrationRaceGcAgainstUploadInFlight(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "gc-vs-upload.bin")

	h.Store(t, key, proxytest.RandomBytes(t, 4096)) // a single-part object is visible

	token := h.MpuStart(t, key, nil)
	part := proxytest.RandomBytes(t, proxytest.TestPart)
	etag := h.UploadOnePart(t, key, token, part)

	// Hold the upload after its manifest is written and before it completes --
	// the exact window the old gc reached into.
	hold := proxytest.NewGate()
	holdAt(t, h, map[string]*proxytest.Gate{proxy.HookUpManifest + "|" + token: hold})

	done := completeAsync(t, h, key, token, etag)
	hold.Await(t, "the upload to write its manifest")

	// The age guard is off on purpose: it would hide the ordering rule, and the
	// ordering rule is what is under test.
	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Deleted != 0 {
		t.Errorf("gc deleted %d manifests while an upload was in flight", result.Deleted)
	}
	if result.KeysSkipped == 0 {
		t.Error("gc did not report the key as skipped; the open-upload check did not fire")
	}

	hold.Open()
	if status := <-done; status != http.StatusOK {
		t.Fatalf("completion returned %d", status)
	}

	got := h.MustRead(t, key, "after a gc pass during the upload")
	if sha256.Sum256(got) != sha256.Sum256(part) {
		t.Error("the object survived gc but its contents changed")
	}
}

// Scenario 3 of spec/tla/README.md: the result that paid for the milestone.
//
// R4 fixes an order for two steps that both only read -- list the manifests,
// then ask for open uploads. Swapping them yields an unreadable object in twelve
// states, because a check that runs before the listing says nothing about
// manifests written after it. This test drives the exact interleaving: gc is
// held after its listing, an entire upload runs to completion inside that
// window, and the object must survive.
func TestIntegrationRaceGcOrderingIsLoadBearing(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "gc-ordering.bin")

	// An orphan from an earlier upload, so the pass has something real to do and
	// a clean run is distinguishable from a run that did nothing.
	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 64)})
	staleManifest, _ := h.ManifestKeyOf(t, key)
	h.Store(t, key, proxytest.RandomBytes(t, 4096)) // a single-part PUT orphans it (10.8)

	hold := proxytest.NewGate()
	var once sync.Once
	cfg := gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
		Hook: func(point, _ string) {
			if point == gc.HookList {
				once.Do(hold.Wait)
			}
		},
	}

	gcDone := make(chan *gc.Result, 1)
	gcErr := make(chan error, 1)
	go func() {
		result, err := gc.Run(t.Context(), cfg)
		gcDone <- result
		gcErr <- err
	}()
	hold.Await(t, "gc to finish listing")

	// The whole upload happens inside the window between gc's listing and its
	// open-upload check. Its manifest is therefore written after the listing,
	// which is precisely what makes listing-first safe.
	fresh := proxytest.RandomBytes(t, proxytest.TestPart)
	h.MpuStore(t, key, [][]byte{fresh, proxytest.RandomBytes(t, 32)})

	hold.Open()
	if err := <-gcErr; err != nil {
		t.Fatalf("gc: %v", err)
	}
	result := <-gcDone

	// The object written during the window must still be readable. This is the
	// assertion the swapped order fails.
	got := h.MustRead(t, key, "after gc ran across the upload")
	if !bytes.HasPrefix(got, fresh) {
		t.Fatal("the object written during the gc window is not the visible one")
	}

	// And gc must have done its actual job: the orphan from before the listing
	// is gone.
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, staleManifest); err == nil {
		t.Error("gc left the stale manifest behind, so the pass proved nothing")
	}
	if result.Deleted == 0 {
		t.Error("gc deleted nothing at all")
	}
}

// The M4 definition of done: two uploads racing on one key with a gc pass
// running alongside must leave a readable object.
func TestIntegrationRaceParallelUploadsWithGc(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "parallel.bin")

	payloads := [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, proxytest.TestPart)}
	var wg sync.WaitGroup
	for _, payload := range payloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := h.MpuStart(t, key, nil)
			etag := h.UploadOnePart(t, key, token, payload)
			resp := h.MpuComplete(t, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
			_ = resp.Body.Close()
		}()
	}

	// A gc pass with no age guard at all, running against both uploads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 3 {
			_, _ = gc.Run(t.Context(), gc.Config{
				Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
				DisableMinAge: true, Log: proxytest.DiscardLogger(),
			})
		}
	}()
	wg.Wait()

	got := h.MustRead(t, key, "after two parallel uploads and a concurrent gc")
	if !bytes.Equal(got, payloads[0]) && !bytes.Equal(got, payloads[1]) {
		t.Fatalf("the object is neither upload's payload (%d bytes)", len(got))
	}
}

// Deleting a multipart object removes its manifest too, and only that one: the
// Del process of the model. A second object on another key must be untouched.
func TestIntegrationDeleteRemovesOnlyItsOwnManifest(t *testing.T) {
	h := proxytest.New(t)
	victim := proxytest.TestKey(t, "deleted.bin")
	bystander := proxytest.TestKey(t, "bystander.bin")

	h.MpuStore(t, victim, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 10)})
	h.MpuStore(t, bystander, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 10)})

	victimManifest, _ := h.ManifestKeyOf(t, victim)
	bystanderManifest, _ := h.ManifestKeyOf(t, bystander)

	resp := h.Do(t, http.MethodDelete, victim)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", resp.StatusCode)
	}

	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, victimManifest); err == nil {
		t.Error("the deleted object's manifest is still there")
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, bystanderManifest); err != nil {
		t.Errorf("the bystander's manifest was removed too: %v", err)
	}
	h.MustRead(t, bystander, "after a delete on another key")
}

// completeAsync starts a completion and reports its status when it returns.
func completeAsync(t *testing.T, h *proxytest.Harness, key, token, etag string) <-chan int {
	t.Helper()
	out := make(chan int, 1)
	go func() {
		resp := h.MpuComplete(t, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
		_ = resp.Body.Close()
		out <- resp.StatusCode
	}()
	return out
}
