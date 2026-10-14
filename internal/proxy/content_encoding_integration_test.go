package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/LennardGeissler/blindbucket/internal/obs"
)

// TestIntegrationGzipEncodedObjectReadsBack: an object a client stores with
// Content-Encoding: gzip -- a pre-compressed web asset, say -- reads back whole
// through the gateway, with its header, and verifies under scrub. The provider
// returns the stored Content-Encoding on every GET, and a transport that took it
// for its own would gunzip the ciphertext; every read of such an object failed
// with 502 IntegrityCheckFailed and counted as an integrity failure (#110).
// Content-Encoding: br, which the rotation tests store, never showed it: Go
// decompresses only the gzip it asked for itself.
func TestIntegrationGzipEncodedObjectReadsBack(t *testing.T) {
	reg := prometheus.NewRegistry()
	h := newHarness(t, func(cfg *Config) { cfg.Metrics = obs.NewMetrics(reg, obs.MetricsConfig{}) })
	prefix := scrubPrefix(t)
	key := prefix + "page.html.gz"

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(bytes.Repeat([]byte("<p>blindbucket</p>\n"), 2000)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	plaintext := compressed.Bytes()

	resp := h.put(t, key, plaintext, map[string]string{
		"Content-Type": "text/html", "Content-Encoding": "gzip",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}
	h.cleanupStored(t, key)

	// The client's own transport would gunzip the response just as the
	// gateway's did; asking for identity keeps the bytes as stored.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	got, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = got.Body.Close() }()
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if got.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", got.StatusCode, body)
	}
	if !bytes.Equal(body, plaintext) {
		t.Errorf("GET returned %d bytes that differ from the %d stored", len(body), len(plaintext))
	}
	if enc := got.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", enc)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	// Every kind is registered at zero, so it is the counts that must stay zero.
	for _, family := range families {
		if family.GetName() != "blindbucket_integrity_failures_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			if m.GetCounter().GetValue() != 0 {
				t.Errorf("an intact object counted as an integrity failure: %v", m)
			}
		}
	}

	result := h.scrub(t, h.scrubConfig(prefix))
	if result.Scanned != 1 || result.Verified != 1 || result.Incomplete() {
		t.Errorf("scrub: scanned %d, verified %d, failed %d, unreadable %d; want 1 verified (findings: %+v)",
			result.Scanned, result.Verified, result.Failed, result.Errors, result.Findings)
	}
}
