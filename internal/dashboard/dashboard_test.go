package dashboard

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
)

type keyring struct{}

func (keyring) KIDs() []string    { return []string{"2026-10", "2026-01"} }
func (keyring) ActiveKID() string { return "2026-10" }
func (keyring) Created(kid string) (time.Time, bool) {
	return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), kid == "2026-01"
}

type auditLog struct{ status audit.Status }

func (a auditLog) Status() audit.Status { return a.status }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// reply is a response, read and closed.
type reply struct {
	code   int
	header http.Header
	body   string
}

func get(t *testing.T, h http.Handler, method, host, path string) reply {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	return reply{code: resp.StatusCode, header: resp.Header, body: string(b)}
}

// TestOnlyLoopbackHostsAreServed is the DNS-rebinding defence: a page that
// reaches loopback under its own name gets nothing, and a tunnel, which
// arrives as localhost, gets the page.
func TestOnlyLoopbackHostsAreServed(t *testing.T) {
	h := New(Config{Version: "1.6.0", Keyring: keyring{}, Sealing: "a passphrase", Logger: quiet()}).Handler()
	for host, want := range map[string]int{
		"localhost:9101":             http.StatusOK,
		"LOCALHOST":                  http.StatusOK,
		"127.0.0.1:9101":             http.StatusOK,
		"[::1]:9101":                 http.StatusOK,
		"attacker.example":           http.StatusMisdirectedRequest,
		"attacker.example:9101":      http.StatusMisdirectedRequest,
		"localhost.attacker.example": http.StatusMisdirectedRequest,
		"10.0.0.5:9101":              http.StatusMisdirectedRequest,
	} {
		resp := get(t, h, http.MethodGet, host, "/")
		if resp.code != want {
			t.Errorf("Host %q: %d, want %d", host, resp.code, want)
		}
		if want != http.StatusOK && strings.Contains(resp.body, "2026-10") {
			t.Errorf("Host %q was refused but shown the keyring", host)
		}
	}
}

// TestReadOnlyAndHeaders: every method but GET and HEAD is refused, and every
// response -- the refusals included -- carries the policy.
func TestReadOnlyAndHeaders(t *testing.T) {
	h := New(Config{Version: "1.6.0", Logger: quiet()}).Handler()
	for _, tc := range []struct {
		method, host, path string
		want               int
	}{
		{http.MethodGet, "localhost", "/", http.StatusOK},
		{http.MethodHead, "localhost", "/", http.StatusOK},
		{http.MethodGet, "localhost", "/style.css", http.StatusOK},
		{http.MethodPost, "localhost", "/", http.StatusMethodNotAllowed},
		{http.MethodDelete, "localhost", "/", http.StatusMethodNotAllowed},
		{http.MethodGet, "localhost", "/metrics", http.StatusNotFound},
		{http.MethodGet, "attacker.example", "/", http.StatusMisdirectedRequest},
	} {
		resp := get(t, h, tc.method, tc.host, tc.path)
		if resp.code != tc.want {
			t.Errorf("%s %s%s: %d, want %d", tc.method, tc.host, tc.path, resp.code, tc.want)
		}
		csp := resp.header.Get("Content-Security-Policy")
		for _, directive := range []string{"default-src 'none'", "style-src 'self'", "frame-ancestors 'none'", "form-action 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s %s%s: the policy %q lacks %q", tc.method, tc.host, tc.path, csp, directive)
			}
		}
		if resp.header.Get("X-Content-Type-Options") != "nosniff" || resp.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s%s: headers %v", tc.method, tc.host, tc.path, resp.header)
		}
	}
}

// TestThePageShowsStateAndNoScript: what the page says, escaped, with no
// script anywhere.
func TestThePageShowsStateAndNoScript(t *testing.T) {
	signed := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	s := New(Config{
		Version: "1.6.0", Keyring: keyring{},
		Sealing: `Vault Transit at https://vault:8200, key transit/<b>blindbucket</b>`,
		Ready:   func(context.Context) error { return errors.New("upstream: 503 from the provider") },
		Audit: auditLog{audit.Status{
			Path: "/var/lib/blindbucket/audit.log", Chain: "gw-1", Seq: 120,
			Signed: signed, SignedSeq: 100, Unsigned: 20,
		}},
		Logger: quiet(),
	})
	s.verified = &Verification{At: signed, OK: false, Files: 2, Error: "audit.log line 7: the chain breaks"}

	page := get(t, s.Handler(), http.MethodGet, "localhost", "/").body
	for _, want := range []string{
		"1.6.0", "Not ready", "upstream: 503 from the provider",
		"2026-10", "2026-01", "active", "2026-01-02 03:04:05 UTC",
		"&lt;b&gt;blindbucket&lt;/b&gt;",
		"/var/lib/blindbucket/audit.log", "gw-1", "entry 100", "20 entries",
		"Does not verify", "audit.log line 7: the chain breaks",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	if strings.Contains(page, "<b>blindbucket") {
		t.Error("the sealing description was rendered as HTML")
	}
	if strings.Contains(strings.ToLower(page), "<script") {
		t.Error("the page carries a script")
	}
}

// TestReadinessIsCheckedAtMostEveryTenSeconds: reloading the page must not
// make the gateway call its provider once per reload.
func TestReadinessIsCheckedAtMostEveryTenSeconds(t *testing.T) {
	var calls atomic.Int32
	s := New(Config{Version: "1.6.0", Logger: quiet(),
		Ready: func(context.Context) error { calls.Add(1); return nil }})
	for range 20 {
		_ = get(t, s.Handler(), http.MethodGet, "localhost", "/")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("20 page loads checked readiness %d times, want once", got)
	}
}

// TestTheAuditLogIsVerifiedInTheBackgroundOnly: at start and on a schedule,
// and never because someone loaded the page.
func TestTheAuditLogIsVerifiedInTheBackgroundOnly(t *testing.T) {
	var runs atomic.Int32
	s := New(Config{
		Listen: "127.0.0.1:0", Version: "1.6.0", Logger: quiet(),
		Audit:       auditLog{audit.Status{Chain: "gw-1"}},
		VerifyEvery: time.Hour,
		Verify: func(context.Context) Verification {
			runs.Add(1)
			return Verification{At: time.Now(), OK: true, Files: 1, Entries: 5, SignedThrough: 5}
		},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Shutdown(context.Background()) }()
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runs.Load() != 1 {
		t.Fatalf("the log was verified %d times at start, want once", runs.Load())
	}
	for range 10 {
		page := get(t, s.Handler(), http.MethodGet, "localhost", "/").body
		if !strings.Contains(page, "Verifies") {
			t.Fatal("the page does not show the verification")
		}
		if !strings.Contains(page, "1 file;") || !strings.Contains(page, "through entry 5 of 5") {
			t.Fatalf("the verification reads wrong:\n%s", page)
		}
	}
	if got := runs.Load(); got != 1 {
		t.Errorf("ten page loads made %d verifications, want none beyond the one at start", got-1)
	}
}
