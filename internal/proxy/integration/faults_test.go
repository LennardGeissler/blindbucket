package integration

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// faultyProvider sits between the gateway and the real provider and fails the
// requests a test picks: with an S3 error, by dropping the connection before
// answering, or by cutting a response off partway through its body.
//
// It is the transport of the gateway's upstream client rather than a server in
// front of the provider, so every request it lets through goes to the
// provider's own address, signed for it. A proxy in front would have to be
// reached under a host of its own -- which a provider addressed by virtual
// host, AWS among them, cannot be. The harness keeps its own direct client,
// which is how a test sees what the provider really holds after the gateway was
// told something failed.
type faultyProvider struct {
	base http.RoundTripper

	mu    sync.Mutex
	rules []*fault
}

// fault is one injected failure.
type fault struct {
	match func(*http.Request) bool
	// times is how many matching requests fail; later ones pass. Zero means all.
	times int

	status   int    // answer with this status and an S3 error document
	code     string // the error code in that document; InjectedFault if empty
	drop     bool   // fail without an answer, as a dropped connection does
	cutAfter int64  // forward, but end the response body after this many bytes
	// setHeader forwards the request and adds these to the provider's answer,
	// for what a real provider would send and MinIO does not.
	setHeader map[string]string
	// acknowledge answers 200 with this document and does not forward the
	// request: a write the provider reports as done and then discards, as AWS
	// does with a completion whose upload was initiated before the visible
	// version's write (ADR-025).
	acknowledge string

	hits int
}

func newFaultyProvider(t *testing.T) *faultyProvider {
	t.Helper()
	return &faultyProvider{base: http.DefaultTransport}
}

// RoundTrip sends what no rule matches to the provider, and fails the rest.
// A failed request's body is read to the end first, as a provider would have
// received it before answering.
func (f *faultyProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	rule := f.take(r)
	switch {
	case rule == nil:
		return f.base.RoundTrip(r)
	case rule.drop:
		drainBody(r)
		return nil, errors.New("connection dropped by the test")
	case rule.acknowledge != "":
		drainBody(r)
		return &http.Response{
			Status: "200 OK", StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"Content-Type": {"application/xml"}},
			Body:          io.NopCloser(strings.NewReader(rule.acknowledge)),
			ContentLength: int64(len(rule.acknowledge)),
			Request:       r,
		}, nil
	case rule.status != 0:
		drainBody(r)
		code := rule.code
		if code == "" {
			code = "InjectedFault"
		}
		body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
			`<Error><Code>%s</Code><Message>injected by the test</Message></Error>`, code)
		return &http.Response{
			Status:     fmt.Sprintf("%d %s", rule.status, http.StatusText(rule.status)),
			StatusCode: rule.status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"Content-Type": {"application/xml"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       r,
		}, nil
	default:
		resp, err := f.base.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		// The headers are out by the time a body is cut, so the gateway sees
		// a read that fails partway, as it would on a broken connection.
		if rule.cutAfter > 0 {
			resp.Body = &cutBody{r: resp.Body, left: rule.cutAfter}
		}
		for name, value := range rule.setHeader {
			resp.Header.Set(name, value)
		}
		return resp, nil
	}
}

func drainBody(r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
}

// fail adds a fault and returns it, so a test can check that it was reached.
func (f *faultyProvider) fail(rule *fault) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule)
	return rule
}

func (f *faultyProvider) take(r *http.Request) *fault {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rule := range f.rules {
		if (rule.times == 0 || rule.hits < rule.times) && rule.match(r) {
			rule.hits++
			return rule
		}
	}
	return nil
}

func (f *faultyProvider) hits(rule *fault) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return rule.hits
}

// option gives a harness's gateway the faulty provider as its transport, with
// retries off so that one injected failure is one failure the gateway sees.
func (f *faultyProvider) option(t *testing.T) func(*proxy.Config) {
	t.Helper()
	cfg := proxytest.UpstreamConfig(t)
	cfg.HTTPClient = &http.Client{Transport: f}
	cfg.MaxRetries = 1
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return func(c *proxy.Config) { c.Upstream = client }
}

// cutBody ends a response body early with an error.
type cutBody struct {
	r    io.ReadCloser
	left int64
}

func (c *cutBody) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errors.New("connection cut by the test")
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func (c *cutBody) Close() error { return c.r.Close() }

// Request matchers. Keys are matched by substring of the path, which is enough
// to tell an object from its manifest under the reserved prefix.

func isManifest(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/"+s3api.ReservedPrefix)
}

func objectRequest(method, keyPart string, query ...string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		if r.Method != method || isManifest(r) || !strings.Contains(r.URL.Path, keyPart) {
			return false
		}
		for _, q := range query {
			if !r.URL.Query().Has(q) {
				return false
			}
		}
		return true
	}
}

func manifestRequest(method string) func(*http.Request) bool {
	return func(r *http.Request) bool { return r.Method == method && isManifest(r) }
}

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

// gatewayDo sends a request with a query to the gateway and returns the status
// and body.
func gatewayDo(t *testing.T, h *proxytest.Harness, method, key, query string) (int, string) {
	t.Helper()
	target := h.URL(key)
	if key == "" {
		target = h.Server.URL + "/" + proxytest.Bucket
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target+"?"+query, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, query, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, proxytest.ReadBody(t, resp)
}

// TestFaultReadsFailBeforeAnyBody: a failure before the first byte is an error
// status, never an empty 200. A read is one GET -- the metadata comes with the
// body, with no HEAD before it -- plus, for a range, one for the header.
func TestFaultReadsFailBeforeAnyBody(t *testing.T) {
	for name, template := range map[string]fault{
		"the provider refuses": {times: 1, status: 500},
		// Every time: Go's transport retries an idempotent GET once on its own
		// when a connection dies before answering, and the retry then succeeds.
		"the connection drops": {drop: true},
	} {
		for _, rng := range []string{"", "bytes=200000-249999"} {
			t.Run(name+" "+rng, func(t *testing.T) {
				f := newFaultyProvider(t)
				h := proxytest.New(t, f.option(t))
				key := proxytest.TestKey(t, "read.bin")
				h.Store(t, key, proxytest.RandomBytes(t, 300_000))

				rule := template
				rule.match = objectRequest(http.MethodGet, key)
				f.fail(&rule)
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				if rng != "" {
					req.Header.Set("Range", rng)
				}
				resp, err := h.Client.Do(req)
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				_ = resp.Body.Close()
				if f.hits(&rule) == 0 {
					t.Fatal("the fault was never reached")
				}
				if resp.StatusCode < 500 {
					t.Errorf("a read whose provider call failed answered %d", resp.StatusCode)
				}
			})
		}
	}
}

// TestFaultDeletingAMultipartObjectKeepsGoing: the object is gone once the
// provider deletes it; its manifest is clean-up, and a failure there leaves an
// orphan for gc rather than failing a delete that happened.
func TestFaultDeletingAMultipartObjectKeepsGoing(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "delete-mpu.bin")
	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1000)})
	manifestKey, _ := h.ManifestKeyOf(t, key)
	h.CleanupStored(t, manifestKey)

	rule := f.fail(&fault{match: manifestRequest(http.MethodDelete), status: 500})
	resp := h.Do(t, http.MethodDelete, key)
	_ = resp.Body.Close()
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("the delete returned %d although the object was removed", resp.StatusCode)
	}
	absentUpstream(t, h, key)
}

// The same provider refusal is client input only when the listing query was
// forwarded. Name encryption builds a different query and keeps the gateway
// error instead (ADR-027).
func TestFaultListingBadRequest(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name, wantStatus, wantCode := "plaintext", http.StatusBadRequest, "ProviderSpecificArgument"
		if encrypted {
			name, wantStatus, wantCode = "encrypted", http.StatusBadGateway, "InternalError"
		}
		t.Run(name, func(t *testing.T) {
			f := newFaultyProvider(t)
			options := []any{f.option(t)}
			if encrypted {
				option, _ := proxytest.WithEncryptedNames(t)
				options = append(options, option)
			}
			h := proxytest.New(t, options...)
			rule := f.fail(&fault{match: func(r *http.Request) bool {
				return r.Method == http.MethodGet && r.URL.Query().Has("list-type")
			}, status: http.StatusBadRequest, code: "ProviderSpecificArgument"})
			status, body, _ := listQuery(t, h, "list-type=2&prefix=docs/")
			var result struct{ Code, Message string }
			if err := xml.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("error document: %v", err)
			}
			if status != wantStatus || result.Code != wantCode {
				t.Fatalf("listing returned %d %s: %s; want %d %s", status, result.Code, body, wantStatus, wantCode)
			}
			if encrypted && result.Message == "injected by the test" {
				t.Error("encrypted listing forwarded the provider's message")
			}
			if !encrypted && result.Message != "injected by the test" {
				t.Errorf("plaintext message = %q, want the provider's message", result.Message)
			}
			if got := f.hits(rule); got != 1 {
				t.Errorf("injected provider requests = %d, want 1", got)
			}
		})
	}
}
