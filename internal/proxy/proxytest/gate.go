package proxytest

import (
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"
)

// These are the counterexamples from spec/tla/Multipart.tla, replayed against a
// real provider. Each one is an interleaving TLC produced for a *broken* set of
// rules; the point of the test is that the rules as implemented survive it.
//
// spec/tla/README.md writes each trace out step by step, and the hook names in
// hooks.go are the model's action names, so a test below can be read next to the
// trace it comes from.

// Gate holds a request at a coordination point until the test lets it through.
type Gate struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

// NewGate returns a closed gate.
func NewGate() *Gate {
	return &Gate{reached: make(chan struct{}), release: make(chan struct{})}
}

// Wait is called from the hook, inside the request being held.
func (g *Gate) Wait() {
	g.once.Do(func() { close(g.reached) })
	<-g.release
}

// Await blocks the test until the request has reached the point.
func (g *Gate) Await(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Open lets the held request continue.
func (g *Gate) Open() { close(g.release) }

// MustRead fetches an object and returns its plaintext, failing on any error.
func (h *Harness) MustRead(t *testing.T, key, what string) []byte {
	t.Helper()
	resp := h.Do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: GET returned %d: %s", what, resp.StatusCode, ReadBody(t, resp))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: reading the body: %v", what, err)
	}
	return body
}

// UploadOnePart uploads a single part and returns its ETag.
func (h *Harness) UploadOnePart(t *testing.T, key, token string, body []byte) string {
	t.Helper()
	etag, resp := h.MpuPart(t, key, token, 1, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("part upload returned %d: %s", resp.StatusCode, ReadBody(t, resp))
	}
	return etag
}

// DiscardLogger keeps gc's own logging out of the test output; these tests
// deliberately provoke the situations it warns about.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
