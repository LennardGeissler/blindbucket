package proxy

import (
	"errors"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// storedKey maps a client's object key to the key the provider stores it under.
//
// The identity when name encryption is off, which is what lets every call site
// use it unconditionally. The mapping is deterministic and needs no lookup, so
// this is a pure function of the key -- the property ADR-015 chose determinism
// for, and the reason a point lookup stays a point lookup.
//
// The plaintext key is what the caller keeps for everything that is not an
// address: the associated data binding the wrapped data key (FORMAT section 6.1)
// stays over the plaintext key, so the envelope is unchanged by whether names
// are encrypted, and an object does not have to be rewritten to move between the
// two. What does have to be rewritten is where it lives.
func (p *Proxy) storedKey(key string) (string, *s3api.Error) {
	if p.names == nil || key == "" {
		return key, nil
	}
	stored, err := p.names.EncryptKey(key)
	if err != nil {
		if errors.Is(err, names.ErrTooLong) {
			return "", s3api.ErrKeyTooLong.WithMessage(
				"this key is within S3's 1024-byte limit but its encrypted form is not; " +
					"encryption grows a key by a factor set by how many '/'-separated " +
					"segments it has, so a deep path of short segments reaches the limit " +
					"much sooner than a shallow one")
		}
		return "", s3api.ErrInternal
	}
	return stored, nil
}

// nameEncryptionGate refuses operations that have not been taught what an
// encrypted name means, and returns nil for the rest.
//
// A whitelist rather than a blacklist. An operation added to the router later is
// refused here until somebody has decided what its key should be, which is the
// direction it is safe to be wrong in: a refusal is visible, while an operation
// that addressed the provider with a plaintext key while everything else used an
// encrypted one would write objects nothing could find again.
func (p *Proxy) nameEncryptionGate(op s3api.Operation) *s3api.Error {
	if p.names == nil {
		return nil
	}
	switch op {
	case s3api.OpPutObject, s3api.OpGetObject, s3api.OpHeadObject, s3api.OpDeleteObject:
		return nil
	// Bucket-level operations carry no object key at all.
	case s3api.OpListBuckets, s3api.OpHeadBucket, s3api.OpCreateBucket,
		s3api.OpDeleteBucket, s3api.OpGetBucketLocation:
		return nil
	}
	return s3api.ErrNotImplemented.WithMessage(
		"%s is not available while object-name encryption is on. Listing, multipart, "+
			"copy and tagging each need their own answer to what an encrypted name "+
			"means -- listing most of all, because the provider sorts by the stored "+
			"key and an unsorted listing makes some clients delete objects that "+
			"exist. See ADR-015 and ADR-017.", op)
}
