package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// These tests fail the provider at one step of an operation and then ask the
// provider directly what it holds. The question each time is the one the TLA+
// model asks of crashes: whatever the gateway told the client, is anything left
// behind that a later reader could take for a whole object -- or an object that
// is visible but cannot be read?

func plainPut(keyPart string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return r.Method == http.MethodPut && !isManifest(r) &&
			strings.Contains(r.URL.Path, keyPart) && r.URL.RawQuery == "" &&
			r.Header.Get("X-Amz-Copy-Source") == ""
	}
}

func absentUpstream(t *testing.T, h *proxytest.Harness, key string) {
	t.Helper()
	if _, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, key); !upstream.NotFound(err) {
		t.Errorf("%s exists at the provider after a failed write (err %v)", key, err)
	}
}

func TestFaultPutObjectLeavesNothing(t *testing.T) {
	for name, rule := range map[string]*fault{
		"the provider refuses":        {status: http.StatusInternalServerError},
		"the connection drops":        {drop: true},
		"the provider is unavailable": {status: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFaultyProvider(t)
			h := proxytest.New(t, f.option(t))
			key := proxytest.TestKey(t, "put.bin")
			rule.match = plainPut(key)
			f.fail(rule)

			resp := h.Put(t, key, proxytest.RandomBytes(t, 200_000), nil)
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				t.Errorf("a failed upstream write answered %d", resp.StatusCode)
			}
			if f.hits(rule) == 0 {
				t.Fatal("the fault was never reached")
			}
			absentUpstream(t, h, key)
		})
	}
}

// TestFaultGetObjectIsCutOff: a provider that stops sending partway through
// must never produce a download that ends cleanly. Headers are already out by
// then, so the only honest signal left is a broken connection.
func TestFaultGetObjectIsCutOff(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))

	for name, tc := range map[string]struct {
		store func(key string) []byte
		rng   string
	}{
		"a single-part object": {func(key string) []byte {
			body := proxytest.RandomBytes(t, 300_000)
			h.Store(t, key, body)
			return body
		}, ""},
		"a range of one": {func(key string) []byte {
			body := proxytest.RandomBytes(t, 300_000)
			h.Store(t, key, body)
			return body[1000:250_000]
		}, "bytes=1000-249999"},
		"a multipart object": {func(key string) []byte {
			return h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 70_000)})
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			key := proxytest.TestKey(t, "cut.bin")
			want := tc.store(key)
			rule := f.fail(&fault{match: objectRequest(http.MethodGet, key), times: 1, cutAfter: 100_000})

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if tc.rng != "" {
				req.Header.Set("Range", tc.rng)
			}
			resp, err := h.Client.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			got, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if f.hits(rule) == 0 {
				t.Fatal("the fault was never reached")
			}
			if readErr == nil && resp.StatusCode == http.StatusOK {
				t.Errorf("a cut-off download ended cleanly with %d of %d bytes", len(got), len(want))
			}
			if bytes.Equal(got, want) {
				t.Error("the whole object arrived although the provider stopped sending")
			}
			if len(got) > 0 && !bytes.HasPrefix(want, got) {
				t.Error("what did arrive is not a prefix of the plaintext")
			}

			// And the object itself is untouched: the next read is whole.
			if back := getOK(t, h, key); back != string(want) && tc.rng == "" {
				t.Error("the object does not read back whole after a cut-off download")
			}
		})
	}
}

// TestFaultCompleteMultipartUpload fails each step of completion in turn.
// Rule R2: the manifest exists before the object is visible. Rule R3: only a
// manifest observed as visible is ever deleted.
func TestFaultCompleteMultipartUpload(t *testing.T) {
	parts := func(t *testing.T) [][]byte {
		return [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 40_000)}
	}

	for name, step := range map[string]func(key string) *fault{
		"step 1, ListParts": func(key string) *fault {
			return &fault{match: objectRequest(http.MethodGet, key, "uploadId"), times: 1, status: 500}
		},
		"step 3, the manifest": func(string) *fault {
			return &fault{match: manifestRequest(http.MethodPut), times: 1, status: 500}
		},
		"step 4, the completion": func(key string) *fault {
			return &fault{match: objectRequest(http.MethodPost, key, "uploadId"), times: 1, status: 500}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFaultyProvider(t)
			h := proxytest.New(t, f.option(t))
			key := proxytest.TestKey(t, "mpu.bin")
			body := parts(t)
			whole := append(append([]byte{}, body[0]...), body[1]...)

			token := h.MpuStart(t, key, nil)
			var done []proxytest.CompletedPart
			for i, part := range body {
				etag, resp := h.MpuPart(t, key, token, i+1, part)
				_ = resp.Body.Close()
				done = append(done, proxytest.CompletedPart{PartNumber: i + 1, ETag: etag})
			}

			rule := f.fail(step(key))
			resp := h.MpuComplete(t, key, token, done)
			_ = resp.Body.Close()
			if f.hits(rule) == 0 {
				t.Fatal("the fault was never reached")
			}
			if resp.StatusCode == http.StatusOK {
				t.Fatal("a completion whose step failed was reported as done")
			}
			// Not visible: a visible multipart object without its manifest is
			// the unreadable state the model exists to rule out.
			absentUpstream(t, h, key)

			// The upload is still open, and the same completion finishes it.
			resp = h.MpuComplete(t, key, token, done)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("retrying the completion returned %d", resp.StatusCode)
			}
			if got := getOK(t, h, key); got != string(whole) {
				t.Error("the object does not read back after a retried completion")
			}
		})
	}
}

// TestFaultReplacedManifestIsLeftForGC is step 5: the upload is complete and
// visible, and the old manifest could not be removed. That is best effort -- an
// orphan gc will collect -- so the client is told it succeeded, and it did.
func TestFaultReplacedManifestIsLeftForGC(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "replaced.bin")
	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1000)})
	oldManifest, _ := h.ManifestKeyOf(t, key)

	rule := f.fail(&fault{match: manifestRequest(http.MethodDelete), times: 1, status: 500})
	second := h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 2000)})
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if got := getOK(t, h, key); got != string(second) {
		t.Error("the replacing object does not read back")
	}
	if _, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, oldManifest); err != nil {
		t.Errorf("the old manifest is gone although its delete failed: %v", err)
	}
	h.CleanupStored(t, oldManifest)
}

func TestFaultUploadPartCanBeRetried(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "part-retry.bin")
	body := proxytest.RandomBytes(t, proxytest.TestPart)

	token := h.MpuStart(t, key, nil)
	rule := f.fail(&fault{match: objectRequest(http.MethodPut, key, "partNumber"), times: 1, drop: true})
	_, resp := h.MpuPart(t, key, token, 1, body)
	_ = resp.Body.Close()
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a part whose upload failed was acknowledged")
	}

	etag, resp := h.MpuPart(t, key, token, 1, body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the retried part returned %d", resp.StatusCode)
	}
	resp = h.MpuComplete(t, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion after a retried part returned %d", resp.StatusCode)
	}
	if got := getOK(t, h, key); got != string(body) {
		t.Error("the object does not read back after a retried part")
	}
}

func TestFaultCreateMultipartUploadIsRefused(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "create.bin")
	rule := f.fail(&fault{match: objectRequest(http.MethodPost, key, "uploads"), status: 500})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL(key)+"?uploads", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if resp.StatusCode < 500 {
		t.Errorf("a refused CreateMultipartUpload answered %d", resp.StatusCode)
	}
}

func TestFaultCopyObjectLeavesNoDestination(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	src, dst := proxytest.TestKey(t, "src.bin"), proxytest.TestKey(t, "dst.bin")
	h.Store(t, src, []byte("copied, or not"))

	rule := f.fail(&fault{match: func(r *http.Request) bool {
		return r.Method == http.MethodPut && r.Header.Get("X-Amz-Copy-Source") != ""
	}, status: 500})
	resp := copyTo(t, h, src, dst, nil)
	_ = resp.Body.Close()
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a failed copy was reported as done")
	}
	absentUpstream(t, h, dst)
	if got := getOK(t, h, src); got != "copied, or not" {
		t.Error("the source was changed by a failed copy")
	}
}

func TestFaultDeleteAndListAreReported(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "kept.bin")
	h.Store(t, key, []byte("still here"))

	rule := f.fail(&fault{match: objectRequest(http.MethodDelete, key), times: 1, status: 500})
	resp := h.Do(t, http.MethodDelete, key)
	_ = resp.Body.Close()
	if f.hits(rule) == 0 || resp.StatusCode < 500 {
		t.Errorf("a failed delete answered %d (fault reached: %t)", resp.StatusCode, f.hits(rule) > 0)
	}
	if got := getOK(t, h, key); got != "still here" {
		t.Error("the object is gone after a delete that failed")
	}

	list := f.fail(&fault{match: func(r *http.Request) bool {
		return r.Method == http.MethodGet && r.URL.Query().Has("list-type")
	}, times: 1, status: 500})
	status, body, _ := listQuery(t, h, "list-type=2")
	if f.hits(list) == 0 || status < 500 {
		t.Errorf("a failed listing answered %d: %s", status, body)
	}
}

// TestFaultDiscardedCompletionKeepsTheVisibleManifest: AWS keeps the write that
// was initiated last, so a completion can succeed while the version it observed
// at step 2 stays the visible one. Step 5 must not take that version's manifest
// with it (ADR-025), and with rollback detection on, the write that was
// discarded must not be recorded as the one the key holds. The discard is
// simulated here -- the completion is answered 200 and never reaches the
// provider -- because MinIO keeps the write that lands last and Garage refuses
// the outranked one; the AWS workflow meets the real thing.
func TestFaultDiscardedCompletionKeepsTheVisibleManifest(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t), proxytest.WithFreshness(t))
	key := proxytest.TestKey(t, "discarded.bin")
	visible := h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 10)})
	visibleManifest, _ := h.ManifestKeyOf(t, key)

	token := h.MpuStart(t, key, nil)
	etag, resp := h.MpuPart(t, key, token, 1, proxytest.RandomBytes(t, 1000))
	_ = resp.Body.Close()
	rule := f.fail(&fault{
		match: objectRequest(http.MethodPost, key, "uploadId"),
		acknowledge: `<?xml version="1.0" encoding="UTF-8"?>` +
			`<CompleteMultipartUploadResult><ETag>"discarded-1"</ETag></CompleteMultipartUploadResult>`,
	})
	resp = h.MpuComplete(t, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the acknowledged completion answered %d", resp.StatusCode)
	}
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}

	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, visibleManifest); err != nil {
		t.Errorf("the manifest of the version still visible was deleted: %v", err)
	}
	if got := h.MustRead(t, key, "after a discarded completion"); !bytes.Equal(got, visible) {
		t.Error("the visible object reads differently after a discarded completion")
	}
}
