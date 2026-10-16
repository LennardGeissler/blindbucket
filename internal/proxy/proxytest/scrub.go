package proxytest

import (
	"io"
	"log/slog"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/scrub"
)

// ScrubConfig configures a scrub of prefix against what the gateway wrote,
// with the gateway's own chunk size and name encryption.
func (h *Harness) ScrubConfig(prefix string) scrub.Config {
	return scrub.Config{
		Upstream: h.Upstream, Keys: h.Keyring, Bucket: Bucket, Prefix: prefix,
		Log2ChunkSize: h.config.Log2ChunkSize, Names: h.config.Names, Concurrency: 4,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// Scrub runs cfg and fails the test if the run itself fails.
func (h *Harness) Scrub(t *testing.T, cfg scrub.Config) *scrub.Result {
	t.Helper()
	result, err := scrub.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("scrub.Run: %v", err)
	}
	return result
}

// ScrubPrefix is a prefix of the test's own, ending on '/', so that a scrub
// sees this test's objects and nothing else.
func ScrubPrefix(t *testing.T) string {
	t.Helper()
	return TestKey(t, "")
}
