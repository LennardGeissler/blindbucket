// Package tags seals an object's tag set into the sidecar that holds it
// (docs/FORMAT.md section 17, ADR-037).
//
// A tag set never reaches the provider in plaintext. It is sealed under a key
// derived from the object's own data key, so a sidecar opens only for the
// object version it was written for, and it is stored under a name derived from
// the object's wrapped data key, so anything that can read the object's
// metadata can find it -- gc included, without the keyring.
package tags

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Magic opens every sidecar.
	Magic = "BBT1"
	// Prefix is where sidecars live, beside the manifests.
	Prefix = ".blindbucket/t/"
	// MaxTags is S3's limit on one tag set, and the format's.
	MaxTags = 10
	// NonceSize is the AES-GCM nonce length.
	NonceSize = 12

	info      = "blindbucket/v1/tags"
	aadPrefix = "blindbucket/v1/tags"
	dekSize   = 32
)

var (
	// ErrMalformed reports bytes that are not a canonical sidecar or tag set.
	ErrMalformed = errors.New("tags: malformed")
	// ErrOpen reports a sidecar that does not open: altered, or not this
	// object version's.
	ErrOpen = errors.New("tags: the sidecar does not open for this object")
	// ErrInvalidTag reports a tag set S3 would refuse.
	ErrInvalidTag = errors.New("tags: invalid tag")
)

// Tag is one key and its value.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// BindingID names the sidecar of one object version: the first 16 bytes of the
// SHA-256 of the wrapped data key as stored in bb-dek, in unpadded base64url.
// Every write mints a new data key, so every version has its own.
func BindingID(wrappedDEK string) string {
	sum := sha256.Sum256([]byte(wrappedDEK))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// PrefixFor is where the sidecars of the object at storedKey live.
func PrefixFor(storedKey string) string {
	sum := sha256.Sum256([]byte(storedKey))
	return Prefix + hex.EncodeToString(sum[:]) + "/"
}

// Path is the sidecar of one object version.
func Path(storedKey, wrappedDEK string) string {
	return PrefixFor(storedKey) + BindingID(wrappedDEK)
}

// Encode writes a tag set canonically: sorted by key, bytewise, each key once.
// An empty set encodes as a single zero byte.
func Encode(set []Tag) ([]byte, error) {
	if len(set) > MaxTags {
		return nil, fmt.Errorf("%w: %d tags, at most %d", ErrMalformed, len(set), MaxTags)
	}
	sorted := slices.Clone(set)
	slices.SortFunc(sorted, func(a, b Tag) int { return strings.Compare(a.Key, b.Key) })
	out := []byte{byte(len(sorted))} //nolint:gosec // at most MaxTags, checked above.
	for i, t := range sorted {
		if t.Key == "" {
			return nil, fmt.Errorf("%w: an empty key", ErrMalformed)
		}
		if i > 0 && sorted[i-1].Key == t.Key {
			return nil, fmt.Errorf("%w: the key %q twice", ErrMalformed, t.Key)
		}
		var err error
		if out, err = appendLP(out, t.Key); err != nil {
			return nil, err
		}
		if out, err = appendLP(out, t.Value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Decode reads a tag set and refuses one that is not canonical: a decoder that
// accepted two spellings of one set would let a sidecar mean two things.
func Decode(b []byte) ([]Tag, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: no count", ErrMalformed)
	}
	n := int(b[0])
	if n > MaxTags {
		return nil, fmt.Errorf("%w: %d tags, at most %d", ErrMalformed, n, MaxTags)
	}
	rest := b[1:]
	set := make([]Tag, 0, n)
	for range n {
		var key, value string
		var err error
		if key, rest, err = readLP(rest); err != nil {
			return nil, err
		}
		if value, rest, err = readLP(rest); err != nil {
			return nil, err
		}
		if key == "" {
			return nil, fmt.Errorf("%w: an empty key", ErrMalformed)
		}
		if len(set) > 0 && strings.Compare(set[len(set)-1].Key, key) >= 0 {
			return nil, fmt.Errorf("%w: keys not in strictly ascending order", ErrMalformed)
		}
		set = append(set, Tag{Key: key, Value: value})
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after the last tag", ErrMalformed, len(rest))
	}
	return set, nil
}

// Seal encrypts a tag set for the object version whose data key is dek. bucket
// and key are the ones the client named, as in the data key's own associated
// data, so the seal reads the same with names encrypted or not.
func Seal(dek []byte, bucket, key string, set []Tag) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return sealWithNonce(dek, bucket, key, set, nonce)
}

func sealWithNonce(dek []byte, bucket, key string, set []Tag, nonce [NonceSize]byte) ([]byte, error) {
	plain, err := Encode(set)
	if err != nil {
		return nil, err
	}
	aead, aad, err := setup(dek, bucket, key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(Magic), nonce[:]...)
	return aead.Seal(out, nonce[:], plain, aad), nil
}

// Open decrypts a sidecar for the object version whose data key is dek. A
// sidecar that does not open is ErrOpen, which the caller treats as tampering:
// its name already says which version it belongs to.
func Open(dek []byte, bucket, key string, body []byte) ([]Tag, error) {
	if len(body) < len(Magic)+NonceSize || !bytes.Equal(body[:len(Magic)], []byte(Magic)) {
		return nil, fmt.Errorf("%w: not a %s sidecar", ErrMalformed, Magic)
	}
	aead, aad, err := setup(dek, bucket, key)
	if err != nil {
		return nil, err
	}
	nonce := body[len(Magic) : len(Magic)+NonceSize]
	plain, err := aead.Open(nil, nonce, body[len(Magic)+NonceSize:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return Decode(plain)
}

// setup derives the tag key from the data key and builds the associated data.
// The info label separates it from the segment subkeys, which the same data key
// derives with another (FORMAT.md section 4.2).
func setup(dek []byte, bucket, key string) (cipher.AEAD, []byte, error) {
	if len(dek) != dekSize {
		return nil, nil, fmt.Errorf("tags: a data key of %d bytes, want %d", len(dek), dekSize)
	}
	tagKey, err := hkdf.Key(sha256.New, dek, nil, info, dekSize)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(tagKey)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	aad := []byte(aadPrefix)
	if aad, err = appendLP(aad, bucket); err != nil {
		return nil, nil, err
	}
	if aad, err = appendLP(aad, key); err != nil {
		return nil, nil, err
	}
	return aead, aad, nil
}

// Validate applies S3's rules for a tag set, which the gateway enforces before
// it stores one so that a client gets S3's answer: at most ten tags, each key
// once, a key of 1 to 128 characters and a value of up to 256, letters,
// numbers, spaces and + - = . _ : / @, and no key in the reserved aws: prefix.
func Validate(set []Tag) error {
	if len(set) > MaxTags {
		return fmt.Errorf("%w: %d tags; an object may have at most %d", ErrInvalidTag, len(set), MaxTags)
	}
	seen := make(map[string]bool, len(set))
	for _, t := range set {
		switch n := utf8.RuneCountInString(t.Key); {
		case !utf8.ValidString(t.Key) || !utf8.ValidString(t.Value):
			return fmt.Errorf("%w: not valid UTF-8", ErrInvalidTag)
		case n == 0 || n > 128:
			return fmt.Errorf("%w: the key %q is %d characters; a key is 1 to 128", ErrInvalidTag, t.Key, n)
		}
		if n := utf8.RuneCountInString(t.Value); n > 256 {
			return fmt.Errorf("%w: the value of %q is %d characters; a value is at most 256", ErrInvalidTag, t.Key, n)
		}
		if strings.HasPrefix(strings.ToLower(t.Key), "aws:") {
			return fmt.Errorf("%w: the key %q uses the reserved aws: prefix", ErrInvalidTag, t.Key)
		}
		if seen[t.Key] {
			return fmt.Errorf("%w: the key %q is given twice", ErrInvalidTag, t.Key)
		}
		seen[t.Key] = true
		for _, s := range []string{t.Key, t.Value} {
			if i := strings.IndexFunc(s, notTagRune); i >= 0 {
				r, _ := utf8.DecodeRuneInString(s[i:])
				return fmt.Errorf("%w: %q holds %q, which a tag may not", ErrInvalidTag, s, r)
			}
		}
	}
	return nil
}

func notTagRune(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.Is(unicode.Zs, r) &&
		!strings.ContainsRune("+-=._:/@", r)
}

func appendLP(dst []byte, x string) ([]byte, error) {
	if len(x) > 0xffff {
		return nil, fmt.Errorf("%w: a field of %d bytes exceeds the length prefix", ErrMalformed, len(x))
	}
	//nolint:gosec // the length is rejected above if it exceeds 0xffff.
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(x)))
	return append(dst, x...), nil
}

func readLP(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, fmt.Errorf("%w: a length prefix cut short", ErrMalformed)
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return "", nil, fmt.Errorf("%w: a field cut short", ErrMalformed)
	}
	return string(b[2 : 2+n]), b[2+n:], nil
}
