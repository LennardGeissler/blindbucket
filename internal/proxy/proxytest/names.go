package proxytest

import (
	"crypto/rand"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
)

// WithEncryptedNames turns object-name encryption on for a harness, and hands
// back the encrypter so a test can check what the provider was addressed with.
func WithEncryptedNames(t *testing.T) (func(*proxy.Config), *names.Encrypter) {
	t.Helper()
	key := make([]byte, names.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	enc, err := names.New(key)
	if err != nil {
		t.Fatalf("names.New: %v", err)
	}
	return func(cfg *proxy.Config) { cfg.Names = enc }, enc
}
