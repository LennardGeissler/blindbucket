package keys

import (
	"crypto/rand"
	"fmt"
)

// FreshnessKeySize is the length of the key behind the rollback index.
//
// It matches freshness.KeySize. The constant is repeated rather than imported
// for the reason NameKeySize is: internal/freshness depends on nothing in this
// package and the dependency should not be created in the other direction.
const FreshnessKeySize = 32

// FreshnessKey is the secret behind the rollback-detection index of
// docs/adr/ADR-018-rollback-detection.md.
//
// The index keys on a keyed hash of each object's identity rather than on the
// name itself. That is what this key is for, and it is the whole of what it is
// for: nothing in the index is ever read back as a name. ADR-015 encrypts names
// in the bucket and ADR-016 encrypts them in the audit log, and an index writing
// them plainly would put on the gateway's own disk precisely what both of those
// hide -- so the names are hashed, and hashed under a key so that whoever steals
// the file alone cannot test a dictionary against it.
//
// Like a name key and unlike a KEK, it does not rotate. Every entry in the index
// is keyed under it, so changing it does not re-key the index -- it empties it,
// and every object falls back to trust on first use. That is a recoverable loss
// rather than a dangerous one, but it is a loss, and it is the reason this is one
// key per keyring rather than one per KEK generation.
//
// It is independent of the name key and of the audit key. An entry in the index,
// an entry in the log and the name of an object in the bucket are three
// different opaque strings for the same object.
type FreshnessKey struct {
	secret [FreshnessKeySize]byte
}

// NewFreshnessKey generates a fresh index key.
func NewFreshnessKey() (*FreshnessKey, error) {
	var k FreshnessKey
	if _, err := rand.Read(k.secret[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

// FreshnessKeyFromSecret adopts an existing index key.
func FreshnessKeyFromSecret(secret []byte) (*FreshnessKey, error) {
	if len(secret) != FreshnessKeySize {
		return nil, fmt.Errorf("keys: freshness key is %d bytes, want %d",
			len(secret), FreshnessKeySize)
	}
	var k FreshnessKey
	copy(k.secret[:], secret)
	return &k, nil
}

// Secret returns a copy of the key. The caller owns it and should wipe it.
func (k *FreshnessKey) Secret() []byte {
	out := make([]byte, FreshnessKeySize)
	copy(out, k.secret[:])
	return out
}

// Wipe zeroes the key.
func (k *FreshnessKey) Wipe() { clear(k.secret[:]) }
