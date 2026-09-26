package obs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// handlerFor builds the admin mux the way NewAdminServer does, without binding a
// port.
func handlerFor(t *testing.T, cfg AdminConfig) http.Handler {
	t.Helper()
	return NewAdminServer(cfg).server.Handler
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body, _ := io.ReadAll(rec.Body)
	return rec.Code, string(body)
}

// Liveness must not depend on the provider: a restart loop caused by an upstream
// outage is worse than the outage.
func TestHealthzIgnoresReadiness(t *testing.T) {
	h := handlerFor(t, AdminConfig{
		Ready: func(context.Context) error { return errors.New("upstream is down") },
	})
	if code, body := get(t, h, "/healthz"); code != http.StatusOK {
		t.Errorf("healthz = %d %q while readiness fails, want 200", code, body)
	}
}

func TestReadyzReportsWhyItIsNotReady(t *testing.T) {
	failing := handlerFor(t, AdminConfig{
		Ready: func(context.Context) error { return errors.New("no active key in the keyring") },
	})
	code, body := get(t, failing, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d, want 503", code)
	}
	if !strings.Contains(body, "no active key") {
		t.Errorf("readyz body %q does not say what is wrong", body)
	}

	ready := handlerFor(t, AdminConfig{Ready: func(context.Context) error { return nil }})
	if code, _ := get(t, ready, "/readyz"); code != http.StatusOK {
		t.Errorf("readyz = %d when ready, want 200", code)
	}
}

// Profiles carry goroutine stacks and heap contents, so they are off unless
// somebody asked for them.
func TestPprofIsOffByDefault(t *testing.T) {
	off := handlerFor(t, AdminConfig{})
	if code, _ := get(t, off, "/debug/pprof/"); code != http.StatusNotFound {
		t.Errorf("pprof answered %d without being enabled, want 404", code)
	}

	on := handlerFor(t, AdminConfig{EnablePprof: true})
	if code, _ := get(t, on, "/debug/pprof/"); code != http.StatusOK {
		t.Errorf("pprof answered %d when enabled, want 200", code)
	}
}

// The metrics the package documents must actually appear, with their
// label sets, or an alert written against them silently never fires.
func TestMetricsAreExported(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry, MetricsConfig{})

	m.Request("GetObject", 200, 0)
	m.Upstream("HeadObject", 0)
	m.Bytes(InPlain, 1)
	m.Bytes(OutCipher, 1)
	m.StreamStarted(Upload)
	m.IntegrityFailure(KindChunk)
	m.AuthFailure("SignatureDoesNotMatch")
	m.ChecksumMismatch("CRC32")

	h := handlerFor(t, AdminConfig{Registry: registry})
	code, body := get(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200", code)
	}

	for _, want := range []string{
		`blindbucket_requests_total{op="GetObject",status="2xx"} 1`,
		`blindbucket_upstream_duration_seconds_count{op="HeadObject"} 1`,
		`blindbucket_bytes_total{direction="in_plain"} 1`,
		`blindbucket_bytes_total{direction="out_cipher"} 1`,
		`blindbucket_active_streams{direction="upload"} 1`,
		`blindbucket_integrity_failures_total{kind="chunk"} 1`,
		`blindbucket_auth_failures_total{reason="SignatureDoesNotMatch"} 1`,
		`blindbucket_checksum_mismatches_total{algorithm="CRC32"} 1`,
		`blindbucket_request_duration_seconds_bucket{op="GetObject"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing from /metrics: %s", want)
		}
	}
}

// Build information must be present before any traffic and stay local to its
// registry, so separately configured gateways never inherit each other's labels.
func TestBuildInfoIsExportedWithoutTraffic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		want    string
	}{
		{name: "release", version: "0.5.0", want: "0.5.0"},
		{name: "development", version: "dev", want: "dev"},
		{name: "default", want: "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			NewMetrics(registry, MetricsConfig{Version: tc.version})
			h := handlerFor(t, AdminConfig{Registry: registry})
			for scrape := 0; scrape < 2; scrape++ {
				code, body := get(t, h, "/metrics")
				if code != http.StatusOK {
					t.Fatalf("metrics = %d, want 200", code)
				}
				want := fmt.Sprintf("blindbucket_build_info{go_version=%q,version=%q} 1\n",
					runtime.Version(), tc.want)
				if !strings.Contains(body, want) {
					t.Errorf("missing from /metrics: %s", want)
				}
				if !strings.Contains(body, "# TYPE blindbucket_build_info gauge\n") {
					t.Error("build information is not exported as a gauge")
				}
				if count := strings.Count(body, "\nblindbucket_build_info{"); count != 1 {
					t.Errorf("build information has %d series, want 1", count)
				}
			}
		})
	}
}

// TestKeyringMetricsExposeKeyAge covers the number a rotation policy is written
// against. Key age used to be visible only by opening the keyring by hand.
func TestKeyringMetricsExposeKeyAge(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry, MetricsConfig{})
	m.KeyringLoaded(testKeyring{
		active: "2026-09",
		created: map[string]time.Time{
			"2026-08": time.Unix(1_756_000_000, 0),
			"2026-09": time.Unix(1_758_000_000, 0),
			// A keyring written before creation dates existed. Its age is
			// unknown, and an unknown age must not be exported as a number: a
			// zero would read as 1970 and alert on every scrape.
			"legacy": {},
		},
	})

	h := handlerFor(t, AdminConfig{Registry: registry})
	code, body := get(t, h, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200", code)
	}
	for _, want := range []string{
		`blindbucket_keyring_keys 3`,
		`blindbucket_keyring_key_created_timestamp_seconds{active="false",kid="2026-08"} 1.756e+09`,
		`blindbucket_keyring_key_created_timestamp_seconds{active="true",kid="2026-09"} 1.758e+09`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing from /metrics: %s", want)
		}
	}
	if strings.Contains(body, `kid="legacy"`) {
		t.Error("a key with no recorded creation date was exported with one")
	}
}

// testKeyring is the KeyringInfo a real *keys.Keyring satisfies. The interface
// exists so that this package does not import the crypto packages, and the
// stub is what that buys.
type testKeyring struct {
	active  string
	created map[string]time.Time
}

func (k testKeyring) ActiveKID() string { return k.active }

func (k testKeyring) KIDs() []string {
	out := make([]string, 0, len(k.created))
	for kid := range k.created {
		out = append(out, kid)
	}
	sort.Strings(out)
	return out
}

func (k testKeyring) Created(kid string) (time.Time, bool) {
	t, ok := k.created[kid]
	return t, ok
}

// The status label is bucketed by class. The exact code belongs in a log line;
// as a label it would be unbounded enough to matter.
func TestStatusLabelIsBounded(t *testing.T) {
	cases := map[int]string{
		200: "2xx", 204: "2xx", 301: "3xx", 400: "4xx",
		404: "4xx", 500: "5xx", 502: "5xx", 0: "other",
	}
	for status, want := range cases {
		if got := statusLabel(status); got != want {
			t.Errorf("statusLabel(%d) = %q, want %q", status, got, want)
		}
	}
}

// A nil *Metrics has to be usable, or every call site needs a branch. The test
// is that none of these panics; there is nothing to assert afterwards.
func TestNilMetricsRecordNothing(*testing.T) {
	var m *Metrics
	m.Request("GetObject", 200, 0)
	m.Upstream("GetObject", 0)
	m.Bytes(InPlain, 1)
	m.StreamStarted(Upload)
	m.StreamFinished(Upload)
	m.IntegrityFailure(KindChunk)
	m.AuthFailure("x")
	m.ChecksumMismatch("x")
	m.KeyringLoaded(testKeyring{})
}
