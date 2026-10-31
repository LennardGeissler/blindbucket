package keys

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// tenantAuditNameInfo is the HKDF info of a tenant's audit name key (FORMAT.md
// section 14.5).
const tenantAuditNameInfo = "blindbucket/v1/tenant-audit-name"

// NameKeySize is the length of the key that encrypts object names.
//
// It matches names.KeySize. The constant is repeated rather than imported
// because internal/crypto/names depends on nothing in this package and the
// dependency should not be created in the other direction either.
const NameKeySize = 32

// NameKey is the key that maps object names to the names a provider stores them
// under, as designed in docs/adr/ADR-015-object-name-encryption.md.
//
// It is one per keyring and, unlike a KEK, it does not rotate. Rotation replaces
// the key that wraps data keys and must leave stored names untouched: a rotation
// that changed them would rename every object in the bucket at once, and leave
// every one of them unreadable until it had been rewritten. Changing this key is
// therefore a migration -- a rewrite of every object's key -- and not a rotation.
// ADR-015 records that asymmetry as a deliberate property of the hierarchy.
//
// It is also independent of the audit log's name key, which AuditKey derives for
// itself. An entry in a log and the name of an object in the bucket are
// different opaque strings for the same object, so that a log and a bucket
// listing cannot be correlated by whoever holds one but not the other.
type NameKey struct {
	secret [NameKeySize]byte
}

// NewNameKey generates a fresh name key.
func NewNameKey() (*NameKey, error) {
	var k NameKey
	if _, err := rand.Read(k.secret[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

// NameKeyFromSecret adopts an existing name key.
func NameKeyFromSecret(secret []byte) (*NameKey, error) {
	if len(secret) != NameKeySize {
		return nil, fmt.Errorf("keys: name key is %d bytes, want %d",
			len(secret), NameKeySize)
	}
	var k NameKey
	copy(k.secret[:], secret)
	return &k, nil
}

// Secret returns a copy of the key. The caller owns it and should wipe it.
func (k *NameKey) Secret() []byte {
	out := make([]byte, NameKeySize)
	copy(out, k.secret[:])
	return out
}

// AuditNameKey derives the key that encrypts the names in audit entries about
// a tenant's buckets (FORMAT.md section 14.5), from that tenant's name key. It
// is derived rather than kept so that a tenant's entries are shredded with its
// name key: once the tenant is destroyed, no key reads their names. The caller
// owns the result and should wipe it.
func (k *NameKey) AuditNameKey() ([]byte, error) {
	return hkdf.Key(sha256.New, k.secret[:], nil, tenantAuditNameInfo, KeySize)
}

// Wipe zeroes the key.
func (k *NameKey) Wipe() { clear(k.secret[:]) }
