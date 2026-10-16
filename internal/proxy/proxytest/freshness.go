package proxytest

import (
	"path/filepath"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/freshness"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
)

// Rollback is the one attack in THREAT_MODEL §5 that the object format cannot
// catch on its own: the bytes are genuine, the wrap is bound to the right
// identity, every tag verifies. Only an index that remembers can tell.
//
// These run against a real provider, and the rollback is performed the way a
// provider would perform it -- by putting an earlier version's bytes and
// metadata back, outside the gateway. A fake upstream would prove nothing here,
// because what is being tested is whether genuine old data is refused.

// NewIndex opens an empty index in the test's own temporary directory.
func NewIndex(t *testing.T) *freshness.Local {
	t.Helper()
	key := make([]byte, freshness.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	index, err := freshness.Open(freshness.Options{
		Path: filepath.Join(t.TempDir(), "freshness.idx"),
		Key:  key,
	})
	if err != nil {
		t.Fatalf("freshness.Open: %v", err)
	}
	t.Cleanup(func() { _ = index.Close() })
	return index
}

// WithFreshness turns rollback detection on for one test.
func WithFreshness(t *testing.T) func(*proxy.Config) {
	t.Helper()
	index := NewIndex(t)
	return func(c *proxy.Config) { c.Freshness = index }
}
