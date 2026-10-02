package keys

import "crypto/subtle"

// Equal reports whether two keyrings hold the same keys: the same KEKs under
// the same ids with the same creation dates, the same active one, and the same
// audit, name and freshness keys, each present in both or in neither.
//
// It exists for `blindbucket reseal`, which replaces a keyring file only after
// opening what it wrote with the new root-key source and finding it Equal to
// what it read. That is the check that catches a source which can seal but not
// unseal -- an encrypt-only key policy -- before the only copy is gone. The
// root key, and with it how the file is sealed, is deliberately not compared:
// changing it is the point.
//
// Secrets are compared in constant time. Nothing here is reachable by an
// attacker, but a comparison of key material written any other way would be the
// one exception in the package, and an exception is what gets copied.
func (r *Keyring) Equal(o *Keyring) bool {
	if r == o {
		return true
	}
	if r == nil || o == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	o.mu.RLock()
	defer o.mu.RUnlock()

	if r.active != o.active || len(r.keks) != len(o.keks) || len(r.created) != len(o.created) {
		return false
	}
	for kid, kek := range r.keks {
		other, ok := o.keks[kid]
		if !ok || subtle.ConstantTimeCompare(kek[:], other[:]) != 1 {
			return false
		}
		if !r.created[kid].Equal(o.created[kid]) {
			return false
		}
	}
	return sameSecret(r.audit, o.audit, func(k *AuditKey) []byte { return k.secret[:] }) &&
		sameSecret(r.name, o.name, func(k *NameKey) []byte { return k.secret[:] }) &&
		sameSecret(r.freshness, o.freshness, func(k *FreshnessKey) []byte { return k.secret[:] })
}

// sameSecret compares two optional keys: both absent, or both present with the
// same secret.
func sameSecret[K any](a, b *K, secret func(*K) []byte) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return subtle.ConstantTimeCompare(secret(a), secret(b)) == 1
}
