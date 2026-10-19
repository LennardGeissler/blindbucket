package integration

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// A client's own conditions on a write (#168). Until they were forwarded, the
// gateway read neither header, and "create only if absent" overwrote the object
// without a word.
//
// The provider evaluates them, so what a client gets is what the provider does:
// a refusal where it enforces them, and on Garage v2.4.1, which ignores them, the
// overwrite a client talking to Garage directly would get too. The expectations
// are stated per provider (internal/testprovider), so a provider that changes
// fails a test.

// wantRefused checks the second write of a pair: refused with 412 where the
// provider enforces the condition, carried out where it ignores it.
func wantRefused(t *testing.T, h *proxytest.Harness, expect string, code int, key, kept, written string) {
	t.Helper()
	switch expect {
	case "enforced":
		if code != http.StatusPreconditionFailed {
			t.Fatalf("a write whose condition does not hold: %d, want 412", code)
		}
		wantBody(t, h, key, kept)
	case "ignored":
		if code != http.StatusOK {
			t.Fatalf("a provider that ignores the condition: %d, want 200", code)
		}
		wantBody(t, h, key, written)
	default:
		t.Fatalf("no expectation for a provider that answers %q", expect)
	}
}

// putStatus sends one PUT and returns its status with the ETag, or the error
// body, closing the response.
func putStatus(t *testing.T, h *proxytest.Harness, key, body string, headers map[string]string) (int, string) {
	t.Helper()
	resp := h.Put(t, key, []byte(body), headers)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, proxytest.ReadBody(t, resp)
	}
	return resp.StatusCode, resp.Header.Get("ETag")
}

// wantBody fails the test unless key reads back as body.
func wantBody(t *testing.T, h *proxytest.Harness, key, body string) {
	t.Helper()
	resp := h.Do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if got := proxytest.ReadBody(t, resp); resp.StatusCode != http.StatusOK || got != body {
		t.Fatalf("GET %s: %d %q, want 200 %q", key, resp.StatusCode, got, body)
	}
}

func TestPutIfNoneMatchCreatesOnlyOnce(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "names in clear", true: "names encrypted"}[encrypted], func(t *testing.T) {
			key := proxytest.TestKey(t, "once")
			h := proxytest.New(t)
			if encrypted {
				option, enc := proxytest.WithEncryptedNames(t)
				h = proxytest.New(t, option)
				stored, err := enc.EncryptKey(key)
				if err != nil {
					t.Fatalf("EncryptKey: %v", err)
				}
				h.CleanupStored(t, stored)
			} else {
				h.CleanupStored(t, key)
			}

			only := map[string]string{"If-None-Match": "*"}
			if code, msg := putStatus(t, h, key, "the first", only); code != http.StatusOK {
				t.Fatalf("the first conditional PUT: %d %s", code, msg)
			}
			code, _ := putStatus(t, h, key, "the second", only)
			wantRefused(t, h, testprovider.Require(t).PutIfNoneMatch, code, key, "the first", "the second")
		})
	}
}

func TestPutIfMatchComparesTheETagTheClientWasGiven(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "match")
	h.CleanupStored(t, key)

	code, etag := putStatus(t, h, key, "version one", nil)
	if code != http.StatusOK || etag == "" {
		t.Fatalf("PUT: %d, ETag %q", code, etag)
	}
	if code, msg := putStatus(t, h, key, "version two", map[string]string{"If-Match": etag}); code != http.StatusOK {
		t.Fatalf("PUT If-Match with the ETag the gateway returned: %d %s", code, msg)
	}
	// The ETag of version one is stale now.
	code, _ = putStatus(t, h, key, "version three", map[string]string{"If-Match": etag})
	wantRefused(t, h, testprovider.Require(t).PutIfMatch, code, key, "version two", "version three")

	// The ETag a read returns is the same one a write compares.
	head := h.Do(t, http.MethodHead, key)
	_ = head.Body.Close()
	if code, msg := putStatus(t, h, key, "version four", map[string]string{"If-Match": head.Header.Get("ETag")}); code != http.StatusOK {
		t.Fatalf("PUT If-Match with the ETag of a HEAD: %d %s", code, msg)
	}
}

func TestPutIfNoneMatchTakesOnlyTheWildcard(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "etag")
	if code, _ := putStatus(t, h, key, "body", map[string]string{"If-None-Match": `"abc"`}); code != http.StatusNotImplemented {
		t.Fatalf("If-None-Match with an ETag: %d, want 501", code)
	}
}

func TestCompleteIfNoneMatchRefusesToReplace(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "mpu")
	h.Store(t, key, []byte("already here"))

	token := h.MpuStart(t, key, nil)
	etag, resp := h.MpuPart(t, key, token, 1, []byte("a part that must not land"))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UploadPart: %d", resp.StatusCode)
	}
	complete := completeWith(t, h, key, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}},
		map[string]string{"If-None-Match": "*"})
	_ = complete.Body.Close()
	wantRefused(t, h, testprovider.Require(t).CompleteIfNoneMatch, complete.StatusCode,
		key, "already here", "a part that must not land")
}

func TestCopyIfNoneMatchRefusesToReplace(t *testing.T) {
	// A conditional copy publishes with a completion, which takes a part copy
	// even for a small object. Garage guards neither, and refuses to copy a
	// source it stores inline, under 3072 bytes, as a part at all, so there
	// this copy is answered 502.
	if p := testprovider.Require(t); p.CompleteIfNoneMatch != "enforced" {
		t.Skipf("the provider's completion leaves If-None-Match %s", p.CompleteIfNoneMatch)
	}
	h := proxytest.New(t)
	src, dst := proxytest.TestKey(t, "src"), proxytest.TestKey(t, "dst")
	h.Store(t, src, []byte("the source"))
	h.Store(t, dst, []byte("the destination"))

	resp := copyTo(t, h, src, dst, map[string]string{"If-None-Match": "*"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("a copy over an existing destination: %d, want 412", resp.StatusCode)
	}
	wantBody(t, h, dst, "the destination")

	fresh := proxytest.TestKey(t, "fresh")
	resp = copyTo(t, h, src, fresh, map[string]string{"If-None-Match": "*"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a copy to a new destination: %d", resp.StatusCode)
	}
	wantBody(t, h, fresh, "the source")
}

// completeWith is MpuComplete with headers.
func completeWith(t *testing.T, h *proxytest.Harness, key, token string,
	parts []proxytest.CompletedPart, headers map[string]string,
) *http.Response {
	t.Helper()
	body, err := xml.Marshal(proxytest.CompleteRequest{Parts: parts})
	if err != nil {
		t.Fatalf("marshalling the completion: %v", err)
	}
	target := fmt.Sprintf("%s?uploadId=%s", h.URL(key), proxytest.URLQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	return resp
}
