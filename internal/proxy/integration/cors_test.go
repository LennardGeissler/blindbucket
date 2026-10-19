package integration

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// CORS from the gateway's own configuration (ADR-036): a preflight answered for
// a listed origin and nothing else, and responses a page on that origin may
// read.

const appOrigin = "https://app.example"

func withCORS(origins ...string) func(*proxy.Config) {
	return func(c *proxy.Config) { c.CORSOrigins = origins }
}

// answer is a response whose body was read and closed.
type answer struct {
	StatusCode int
	Header     http.Header
}

// preflight sends an OPTIONS request the way a browser does, unsigned.
func preflight(t *testing.T, h *proxytest.Harness, key, origin, method, headers string) answer {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, h.URL(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if method != "" {
		req.Header.Set("Access-Control-Request-Method", method)
	}
	if headers != "" {
		req.Header.Set("Access-Control-Request-Headers", headers)
	}
	resp, err := h.Unsigned.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	_ = resp.Body.Close()
	return answer{resp.StatusCode, resp.Header}
}

func TestPreflightIsAnsweredForAListedOrigin(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit), withCORS(appOrigin))
	resp := preflight(t, h, proxytest.TestKey(t, "obj"), appOrigin, http.MethodPut,
		"Content-Type, x-amz-checksum-sha256, x-amz-meta-owner, if-none-match")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preflight: %d", resp.StatusCode)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":  appOrigin,
		"Access-Control-Allow-Methods": "GET, HEAD, PUT",
		"Access-Control-Allow-Headers": "content-type, x-amz-checksum-sha256, x-amz-meta-owner, if-none-match",
		"Access-Control-Max-Age":       "3600",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("%s is %q, want %q", name, got, want)
		}
	}
	if resp.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("a preflight allows credentials")
	}
	if !slices.Contains(resp.Header.Values("Vary"), "Origin") {
		t.Errorf("Vary is %q, want Origin among it", resp.Header.Values("Vary"))
	}
}

func TestPreflightIsRefusedForAnythingElse(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit), withCORS(appOrigin))
	key := proxytest.TestKey(t, "obj")
	for name, tc := range map[string]struct{ origin, method, headers string }{
		"an unlisted origin":       {"https://attacker.example", http.MethodPut, ""},
		"the origin over http":     {"http://app.example", http.MethodPut, ""},
		"no origin":                {"", http.MethodPut, ""},
		"DELETE":                   {appOrigin, http.MethodDelete, ""},
		"POST":                     {appOrigin, http.MethodPost, ""},
		"no method":                {appOrigin, "", ""},
		"an Authorization header":  {appOrigin, http.MethodPut, "authorization"},
		"a header outside the set": {appOrigin, http.MethodPut, "content-type, x-amz-acl"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := preflight(t, h, key, tc.origin, tc.method, tc.headers)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("preflight: %d, want 403", resp.StatusCode)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("a refused preflight names an origin: %q", got)
			}
		})
	}
}

func TestWithoutCORSNoPreflightIsAnswered(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	resp := preflight(t, h, proxytest.TestKey(t, "obj"), appOrigin, http.MethodPut, "")
	if resp.StatusCode == http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("a gateway with no origins listed answered a preflight: %d %q",
			resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

// TestResponsesNameTheListedOriginOnly: a page on the listed origin may read
// what it gets, the ETag included, and errors as well as successes; a page on
// another origin may read nothing.
func TestResponsesNameTheListedOriginOnly(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit), withCORS(appOrigin))
	key := proxytest.TestKey(t, "obj")
	h.CleanupStored(t, key)
	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, nil, nil)

	send := func(method, target, origin string) answer {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader("body"))
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if method == http.MethodGet {
			req.Body, req.ContentLength = http.NoBody, 0
		}
		req.Header.Set("Origin", origin)
		resp, err := h.Unsigned.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_ = resp.Body.Close()
		return answer{resp.StatusCode, resp.Header}
	}

	put := send(http.MethodPut, signed, appOrigin)
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PUT: %d", put.StatusCode)
	}
	if got := put.Header.Get("Access-Control-Allow-Origin"); got != appOrigin {
		t.Errorf("the upload's response names %q, want %q", got, appOrigin)
	}
	if !strings.Contains(put.Header.Get("Access-Control-Expose-Headers"), "ETag") || put.Header.Get("ETag") == "" {
		t.Errorf("the ETag is not readable: expose %q, ETag %q",
			put.Header.Get("Access-Control-Expose-Headers"), put.Header.Get("ETag"))
	}

	// A read, whose headers come from the provider: the gateway's CORS
	// headers must survive the copy.
	get := send(http.MethodGet, presignURL(t, h, http.MethodGet, key, 15*time.Minute, time.Now()), appOrigin)
	if get.StatusCode != http.StatusOK || get.Header.Get("Access-Control-Allow-Origin") != appOrigin ||
		!slices.Contains(get.Header.Values("Vary"), "Origin") {
		t.Errorf("GET: %d, origin %q, Vary %q", get.StatusCode,
			get.Header.Get("Access-Control-Allow-Origin"), get.Header.Values("Vary"))
	}

	// An error is readable too, so the page can say why.
	bad := send(http.MethodPut, strings.Replace(signed, "X-Amz-Signature=", "X-Amz-Signature=0", 1), appOrigin)
	if bad.StatusCode != http.StatusForbidden || bad.Header.Get("Access-Control-Allow-Origin") != appOrigin {
		t.Errorf("a refused upload: %d, origin %q", bad.StatusCode, bad.Header.Get("Access-Control-Allow-Origin"))
	}

	other := send(http.MethodPut, signed, "https://attacker.example")
	if got := other.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a response to another origin names %q", got)
	}
}
