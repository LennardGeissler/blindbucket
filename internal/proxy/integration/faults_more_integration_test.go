package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

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

// TestListMultipartUploadsIsRefused pins the one call deliberately left out:
// the upload ids this gateway hands out are sealed tokens, and the provider's
// listing holds only its own ids, which no client could use.
func TestIntegrationListMultipartUploadsIsRefused(t *testing.T) {
	h := proxytest.New(t)
	status, body := gatewayDo(t, h, http.MethodGet, "", "uploads")
	if status != http.StatusNotImplemented || !strings.Contains(body, "NotImplemented") {
		t.Errorf("returned %d: %s", status, body)
	}
}

// TestIntegrationEndedUploads: every call on an upload that no longer exists
// says NoSuchUpload, which is what a client retrying the whole upload acts on.
func TestIntegrationEndedUploads(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "ended.bin")
	token := h.MpuStart(t, key, nil)
	etag, resp := h.MpuPart(t, key, token, 1, proxytest.RandomBytes(t, 1000))
	_ = resp.Body.Close()

	// While it is open, ListParts reports the part in plaintext size.
	status, body := gatewayDo(t, h, http.MethodGet, key, "uploadId="+proxytest.URLQueryEscape(token))
	if status != http.StatusOK || !strings.Contains(body, "<Size>1000</Size>") {
		t.Errorf("ListParts on an open upload returned %d: %s", status, body)
	}

	if status, body := gatewayDo(t, h, http.MethodDelete, key, "uploadId="+proxytest.URLQueryEscape(token)); status != http.StatusNoContent {
		t.Fatalf("abort returned %d: %s", status, body)
	}

	for name, call := range map[string]func() (int, string){
		"ListParts": func() (int, string) {
			return gatewayDo(t, h, http.MethodGet, key, "uploadId="+proxytest.URLQueryEscape(token))
		},
		"completion": func() (int, string) {
			resp := h.MpuComplete(t, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode, proxytest.ReadBody(t, resp)
		},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := call()
			if status != http.StatusNotFound || !strings.Contains(body, "NoSuchUpload") {
				t.Errorf("returned %d: %s", status, body)
			}
		})
	}
}

// TestIntegrationTaggingOnAProviderWithout: the AWS CLI asks for an object's
// tags before every multipart server-side copy. Garage does not implement
// tagging, and a 502 there failed the copy; its true answer is no tags.
func TestIntegrationTaggingOnAProviderWithout(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "tags.bin")
	h.Store(t, key, []byte("tagged, or not"))

	// Against MinIO the request is forwarded and answered by it.
	if status, body := gatewayDo(t, h, http.MethodGet, key, "tagging"); status != http.StatusOK ||
		!strings.Contains(body, "Tagging") {
		t.Fatalf("GET ?tagging returned %d: %s", status, body)
	}

	rule := f.fail(&fault{match: objectRequest(http.MethodGet, key, "tagging"), times: 1,
		status: http.StatusNotImplemented, code: "NotImplemented"})
	status, body := gatewayDo(t, h, http.MethodGet, key, "tagging")
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if status != http.StatusOK || !strings.Contains(body, "<TagSet></TagSet>") {
		t.Errorf("a provider without tagging gave %d: %s", status, body)
	}

	// Any other failure is not dressed up as an empty tag set.
	f.fail(&fault{match: objectRequest(http.MethodGet, key, "tagging"), status: http.StatusInternalServerError})
	if status, _ := gatewayDo(t, h, http.MethodGet, key, "tagging"); status < 500 {
		t.Errorf("a failed tagging request answered %d", status)
	}
}

// TestIntegrationVersionIDIsPassedOn: on a versioned bucket the provider names
// the version it stored, and a client that asked for it must get it back.
// MinIO's test bucket is unversioned, so the header is added on its way back.
func TestIntegrationVersionIDIsPassedOn(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))

	put := proxytest.TestKey(t, "versioned.bin")
	f.fail(&fault{match: plainPut(put), setHeader: map[string]string{"x-amz-version-id": "v-put"}})
	resp := h.Put(t, put, []byte("versioned"), nil)
	_ = resp.Body.Close()
	if got := resp.Header.Get("x-amz-version-id"); got != "v-put" {
		t.Errorf("PutObject returned version %q, want v-put", got)
	}

	mpu := proxytest.TestKey(t, "versioned-mpu.bin")
	f.fail(&fault{match: objectRequest(http.MethodPost, mpu, "uploadId"),
		setHeader: map[string]string{"x-amz-version-id": "v-mpu"}})
	token := h.MpuStart(t, mpu, nil)
	etag, resp := h.MpuPart(t, mpu, token, 1, proxytest.RandomBytes(t, 1000))
	_ = resp.Body.Close()
	resp = h.MpuComplete(t, mpu, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
	_ = resp.Body.Close()
	if got := resp.Header.Get("x-amz-version-id"); got != "v-mpu" {
		t.Errorf("CompleteMultipartUpload returned version %q, want v-mpu", got)
	}
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
