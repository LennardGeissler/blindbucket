package keys

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Associated-data prefixes. Each one domain-separates a wrapping context so that
// a blob wrapped for one purpose cannot be unwrapped as another.
const (
	aadObjectPrefix = "blindbucket/v1/dek"
	aadFilePrefix   = "blindbucket/v1/dek-file"
	aadKEKPrefix    = "blindbucket/v1/kek"
	aadAuditPrefix  = "blindbucket/v1/audit-secret"
	aadNamePrefix   = "blindbucket/v1/name-key"
	aadFreshPrefix  = "blindbucket/v1/freshness-key"
)

// auditAAD is the associated data binding the audit secret to its purpose.
//
// It has no variable part. An audit secret is one per keyring, not one per key
// id, so there is nothing to bind it to beyond the context itself -- and the
// fixed prefix is what stops a wrapped audit secret being unwrapped as a KEK, or
// the reverse.
func auditAAD() []byte { return []byte(aadAuditPrefix) }

// nameAAD is the associated data binding the object-name key to its purpose.
//
// Fixed, for the same reason auditAAD is: there is one name key per keyring and
// nothing to bind it to beyond the context. What the prefix buys is that a
// wrapped name key cannot be unwrapped as a KEK or as an audit secret, which
// matters more here than elsewhere -- the three are the same length, so without
// domain separation the only thing distinguishing them would be where in the
// file they were found.
func nameAAD() []byte { return []byte(aadNamePrefix) }

// freshnessAAD is the associated data binding the rollback-index key to its
// purpose.
//
// Fixed, like the two above, and for the same reason: one per keyring, nothing
// to bind it to beyond the context. The prefix is what stops the four 32-byte
// secrets a keyring can hold -- a KEK, an audit secret, a name key and now this
// -- being unwrapped as one another.
func freshnessAAD() []byte { return []byte(aadFreshPrefix) }

// MaxKIDLen bounds a key identifier.
//
// The bound is normative rather than cosmetic: it is what keeps the object and
// file associated-data encodings unambiguous. Both start with the 18 bytes
// "blindbucket/v1/dek"; the object form continues with uint16_be(len(kid)) while
// the file form continues with the ASCII bytes "-fi". Confusing the two would
// require a kid of length 0x2D66, which this bound forbids. See docs/FORMAT.md
// sections 3.1 and 6.2.
const MaxKIDLen = 64

// ErrKIDInvalid reports a key identifier outside the permitted shape.
var ErrKIDInvalid = errors.New("keys: invalid key id")

// ValidateKID reports whether kid is a permitted key identifier.
func ValidateKID(kid string) error {
	if len(kid) == 0 || len(kid) > MaxKIDLen {
		return fmt.Errorf("%w: length %d outside 1..%d", ErrKIDInvalid, len(kid), MaxKIDLen)
	}
	for i := range len(kid) {
		c := kid[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return fmt.Errorf("%w: %q contains a character outside [A-Za-z0-9._-]", ErrKIDInvalid, kid)
		}
	}
	return nil
}

// appendLP appends x prefixed by its uint16 big-endian length.
//
// Length prefixes are what make a concatenation of variable-length fields
// unambiguous: without them bucket "ab" with key "c" and bucket "a" with key
// "bc" would produce identical associated data, and an active provider could
// swap the two objects undetected.
func appendLP(dst []byte, x string) ([]byte, error) {
	if len(x) > 0xffff {
		return nil, fmt.Errorf("keys: field of %d bytes exceeds the length prefix", len(x))
	}
	//nolint:gosec // the length is rejected above if it exceeds 0xffff.
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(x)))
	return append(dst, x...), nil
}

// ObjectAAD builds the associated data binding a wrapped DEK to one object.
//
// Because bucket and key are authenticated here, unwrapping fails if the storage
// provider moves an object's body and metadata to a different key.
func ObjectAAD(kid, bucket, key string) ([]byte, error) {
	if err := ValidateKID(kid); err != nil {
		return nil, err
	}
	aad := make([]byte, 0, len(aadObjectPrefix)+6+len(kid)+len(bucket)+len(key))
	aad = append(aad, aadObjectPrefix...)
	var err error
	for _, field := range []string{kid, bucket, key} {
		if aad, err = appendLP(aad, field); err != nil {
			return nil, err
		}
	}
	return aad, nil
}

// FileAAD builds the associated data for the local BBF1 file format, which has
// no bucket or key to bind to.
func FileAAD(kid string) ([]byte, error) {
	if err := ValidateKID(kid); err != nil {
		return nil, err
	}
	aad := append([]byte(nil), aadFilePrefix...)
	return appendLP(aad, kid)
}

// kekAAD builds the associated data for a KEK wrapped under the root key.
func kekAAD(kid string) ([]byte, error) {
	if err := ValidateKID(kid); err != nil {
		return nil, err
	}
	aad := append([]byte(nil), aadKEKPrefix...)
	return appendLP(aad, kid)
}
