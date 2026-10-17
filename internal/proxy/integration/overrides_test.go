package integration

import (
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// The response-* parameters of GetObject and HeadObject (ADR-032). GitLab puts
// response-content-disposition and response-content-type on every download
// link it hands out, and on every fetch Workhorse makes for a proxied one; until
// these were served, no file stored in a GitLab behind the gateway could be
// downloaded again.

// gitlabOverrides are the two GitLab sends, with the value it sends.
func gitlabOverrides() url.Values {
	return url.Values{
		"response-content-disposition": {`attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`},
		"response-content-type":        {"application/octet-stream"},
	}
}

// getWith makes a signed request for key with the query given.
func getWith(t *testing.T, h *proxytest.Harness, method, key string, query url.Values, rangeSpec string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.URL(key)+"?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if rangeSpec != "" {
		req.Header.Set("Range", rangeSpec)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, key, err)
	}
	return resp
}

func wantOverrides(t *testing.T, resp *http.Response, query url.Values) {
	t.Helper()
	if got, want := resp.Header.Get("Content-Disposition"), query.Get("response-content-disposition"); got != want {
		t.Errorf("Content-Disposition is %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Content-Type"), query.Get("response-content-type"); got != want {
		t.Errorf("Content-Type is %q, want %q", got, want)
	}
}

// TestPresignedGetSetsTheResponseHeadersItWasSignedWith is GitLab's download
// link: the overrides are in the signed URL, and the body is the object.
func TestPresignedGetSetsTheResponseHeadersItWasSignedWith(t *testing.T) {
	h := proxytest.New(t, withPresign())
	key := proxytest.TestKey(t, "obj")
	body := "a file GitLab hands out under its own name"
	put := h.Put(t, key, []byte(body), map[string]string{"Content-Type": "text/plain"})
	_ = put.Body.Close()
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", put.StatusCode)
	}

	query := gitlabOverrides()
	resp := fetch(t, h, http.MethodGet, presignURLWith(t, h, http.MethodGet, key, time.Hour, time.Now(), query))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", resp.StatusCode, proxytest.ReadBody(t, resp))
	}
	wantOverrides(t, resp, query)
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if string(got) != body {
		t.Errorf("GET returned %q, want %q", got, body)
	}
}

// TestPresignedOverrideCannotBeAdded: the signer chooses the overrides, not
// whoever holds the link.
func TestPresignedOverrideCannotBeAdded(t *testing.T) {
	h := proxytest.New(t, withPresign())
	key := proxytest.TestKey(t, "obj")
	h.Store(t, key, []byte("stored as it is"))

	u, err := url.Parse(presignURL(t, h, http.MethodGet, key, time.Hour, time.Now()))
	if err != nil {
		t.Fatalf("parsing the signed URL: %v", err)
	}
	query := u.Query()
	query.Set("response-content-type", "text/html")
	u.RawQuery = query.Encode()

	resp := fetch(t, h, http.MethodGet, u.String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a URL with an override added after signing returned %d, want 403", resp.StatusCode)
	}
}

// TestOverridesApplyToEveryReadPath: whole, ranged and HEAD, single-part and
// multipart. Each path writes its own headers, and each has to apply them.
func TestOverridesApplyToEveryReadPath(t *testing.T) {
	h := proxytest.New(t)
	single := proxytest.TestKey(t, "single")
	h.Store(t, single, []byte("0123456789abcdef"))
	multi := proxytest.TestKey(t, "multi")
	h.StoreParts(t, multi, proxytest.TestPart, 1024)

	query := gitlabOverrides()
	for _, tc := range []struct {
		name, method, key, rangeSpec string
		status                       int
	}{
		{"GET", http.MethodGet, single, "", http.StatusOK},
		{"ranged GET", http.MethodGet, single, "bytes=2-5", http.StatusPartialContent},
		{"HEAD", http.MethodHead, single, "", http.StatusOK},
		{"multipart GET", http.MethodGet, multi, "", http.StatusOK},
		{"multipart ranged GET", http.MethodGet, multi, "bytes=10-20", http.StatusPartialContent},
		{"multipart HEAD", http.MethodHead, multi, "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := getWith(t, h, tc.method, tc.key, query, tc.rangeSpec)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.status {
				t.Fatalf("returned %d, want %d: %s", resp.StatusCode, tc.status, proxytest.ReadBody(t, resp))
			}
			wantOverrides(t, resp, query)
		})
	}
}

// TestOverridesAreNotOnAnError: a missing object answers with S3's XML error,
// whatever type the request asked the object to be served as.
func TestOverridesAreNotOnAnError(t *testing.T) {
	h := proxytest.New(t)
	resp := getWith(t, h, http.MethodGet, proxytest.TestKey(t, "missing"), gitlabOverrides(), "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("returned %d, want 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Disposition"); got != "" {
		t.Errorf("an error response carries Content-Disposition %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/xml" {
		t.Errorf("an error response has Content-Type %q, want application/xml", got)
	}
}
