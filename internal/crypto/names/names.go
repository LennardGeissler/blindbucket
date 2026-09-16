// Package names maps object keys to the keys the storage provider sees.
//
// The mapping is specified normatively in docs/FORMAT.md section 15, pinned by
// the known-answer vectors in testdata/vectors/names_v1.json, and implemented a
// second time in ref/python/names_ref.py -- which is what checks that the SIV
// composition below was written down correctly, rather than merely written down
// consistently.
//
// It is the encryption of object names described in ADR-015. A key is split on
// "/" and each segment is encrypted on its own, so that "a/b/" stays a prefix
// of "a/b/c.txt" after encryption and prefix listing keeps working. The
// separators are the only part of a key that survives in clear.
//
// # Why deterministic
//
// A client asks for one object by name and must reach it in one request. The
// mapping from plaintext key to stored key is therefore a function of the key
// alone, with no index and no lookup -- which forces it to be deterministic,
// every segment including the last. Randomising the leaf would hide more (two
// objects called report.pdf in one directory are visibly the same name) and
// would make every read a search. ADR-015 records that trade; it is the first
// thing to understand about this package, and the reason it cannot simply be
// improved.
//
// # The construction
//
// Deterministic encryption needs an IV derived from the plaintext rather than
// from chance. This is the SIV paradigm (Rogaway and Shrimpton; RFC 5297), with
// HMAC-SHA256 as the PRF in place of AES-CMAC:
//
//	IV  = HMAC-SHA256(prfKey, lp(context) || lp(segment))[:ivSize]
//	out = IV || AES-CTR(encKey, IV, segment)
//
// Decryption recomputes the IV over the recovered plaintext and compares it in
// constant time, which makes the construction authenticated as well as
// deterministic.
//
// Composing a published construction from standard primitives is what this
// project already does for the segment format -- STREAM over AES-GCM -- and it
// is held to the same standard here: known-answer vectors, and an independent
// implementation to check the composition was written down correctly. The
// alternative, the usual Go SIV library, has no release tags, has not moved
// since 2018 and depends on a module last touched in 2016; ADR-015 has the
// reasoning.
package names

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	// KeySize is the length of the name key.
	KeySize = 32
	// ivSize is the length of the synthetic IV kept in front of each segment.
	// Sixteen bytes is AES-CTR's block size and RFC 5297's SIV length.
	ivSize = 16

	// MaxStoredKey is S3's limit on a key, in bytes. A plaintext key that would
	// exceed it once encrypted is refused rather than truncated.
	MaxStoredKey = 1024

	prfInfo = "blindbucket/v1/name-prf"
	encInfo = "blindbucket/v1/name-enc"
)

// encoding renders a segment's ciphertext into characters an S3 key accepts.
//
// Base32 rather than the shorter base64url, deliberately. Two base64url strings
// can differ only in case, and a store that folds case -- a MinIO on a
// case-insensitive filesystem, an S3 gateway over SMB -- would then map two
// distinct objects onto one key and lose one of them. Base32's alphabet has no
// case pairs, so the mapping survives a case-folding store. It costs about 1.6x
// in length against base64url's 1.33x.
//
// That 1.6x is the encoding alone, and it is not the expansion a key sees. Each
// segment also carries a 16-byte synthetic IV, so what drives the total is the
// number of segments rather than the length: a key that is one long segment
// expands 1.64x and may be 624 bytes, while a path of four-character segments
// expands 8x and may be 128. BenchmarkKeyExpansion measures the four shapes; an
// earlier version of ADR-015 quoted only the 1.6x and so named the best case as
// though it were the rule.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrName reports a stored key this keyring did not produce: not valid base32,
// too short to hold an IV, or an IV that does not match the plaintext it
// decrypts to.
var ErrName = errors.New("names: stored key is not one this gateway wrote")

// ErrTooLong reports a key whose encrypted form exceeds what S3 accepts.
var ErrTooLong = errors.New("names: key is too long once encrypted")

// Encrypter maps object keys in both directions.
//
// It holds a key that does not rotate with the KEKs. Rotation replaces the key
// that wraps data keys and must leave stored names alone, because changing them
// would rename every object at once; changing the name key is instead a rewrite
// of every key, which is a migration and not a rotation. See ADR-015.
type Encrypter struct {
	prfKey []byte
	encKey []byte
}

// New derives an Encrypter from the keyring's name key.
func New(nameKey []byte) (*Encrypter, error) {
	if len(nameKey) != KeySize {
		return nil, fmt.Errorf("names: name key is %d bytes, want %d", len(nameKey), KeySize)
	}
	prfKey, err := hkdf.Key(sha256.New, nameKey, nil, prfInfo, KeySize)
	if err != nil {
		return nil, err
	}
	encKey, err := hkdf.Key(sha256.New, nameKey, nil, encInfo, KeySize)
	if err != nil {
		return nil, err
	}
	return &Encrypter{prfKey: prfKey, encKey: encKey}, nil
}

// EncryptKey maps a plaintext object key to the key the provider stores it
// under.
//
// Empty segments are preserved rather than collapsed: "a//b" and "a/b" are
// different keys in S3, and a mapping that merged them would let one object
// overwrite another.
func (e *Encrypter) EncryptKey(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	segments := strings.Split(plain, "/")
	out := make([]string, len(segments))

	// The context is the plaintext path up to this segment, so that the same
	// name under two directories encrypts differently.
	offset := 0
	for i, segment := range segments {
		context := plain[:offset]
		sealed, err := e.sealSegment(context, segment)
		if err != nil {
			return "", err
		}
		out[i] = sealed
		offset += len(segment) + 1
	}

	stored := strings.Join(out, "/")
	if len(stored) > MaxStoredKey {
		return "", fmt.Errorf("%w: %d bytes encrypts to %d, the maximum is %d",
			ErrTooLong, len(plain), len(stored), MaxStoredKey)
	}
	return stored, nil
}

// DecryptKey reverses EncryptKey.
func (e *Encrypter) DecryptKey(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	segments := strings.Split(stored, "/")
	out := make([]string, len(segments))

	var plain strings.Builder
	for i, segment := range segments {
		context := plain.String()
		opened, err := e.openSegment(context, segment)
		if err != nil {
			return "", err
		}
		out[i] = opened
		plain.WriteString(opened)
		plain.WriteByte('/')
	}
	return strings.Join(out, "/"), nil
}

// EncryptPrefix maps a listing prefix.
//
// It reports whether the prefix ends on a segment boundary. One that does not
// -- "photos/2026" against a segment "2026-01" -- has no encrypted form that is
// a prefix of anything, because a partial segment does not encrypt to a partial
// ciphertext. A caller that gets false must list the parent and filter on
// decrypted names instead; it must not pass the returned value upstream.
func (e *Encrypter) EncryptPrefix(prefix string) (stored string, whole bool, err error) {
	if prefix == "" {
		return "", true, nil
	}
	if !strings.HasSuffix(prefix, "/") {
		// The last segment is partial. Its parent is still translatable, and a
		// caller can narrow the upstream listing to that and filter the rest
		// itself; with no parent there is nothing to narrow to.
		i := strings.LastIndex(prefix, "/")
		if i < 0 {
			return "", false, nil
		}
		encrypted, err := e.EncryptKey(prefix[:i])
		if err != nil {
			return "", false, err
		}
		return encrypted + "/", false, nil
	}

	encrypted, err := e.EncryptKey(strings.TrimSuffix(prefix, "/"))
	if err != nil {
		return "", false, err
	}
	return encrypted + "/", true, nil
}

// sealSegment encrypts one path segment under its context.
func (e *Encrypter) sealSegment(context, segment string) (string, error) {
	iv := e.syntheticIV(context, segment)
	block, err := aes.NewCipher(e.encKey)
	if err != nil {
		return "", err
	}
	out := make([]byte, ivSize+len(segment))
	copy(out, iv)
	cipher.NewCTR(block, iv).XORKeyStream(out[ivSize:], []byte(segment))
	return encoding.EncodeToString(out), nil
}

// openSegment reverses sealSegment and checks the synthetic IV.
func (e *Encrypter) openSegment(context, segment string) (string, error) {
	raw, err := encoding.DecodeString(segment)
	if err != nil {
		return "", fmt.Errorf("%w: segment is not valid base32", ErrName)
	}
	// Base32 is not injective unless canonicality is enforced. A 17-byte
	// segment is 136 bits and occupies 28 characters, which hold 140 -- and
	// the decoder ignores the four spare bits, so 16 spellings decode to the
	// same bytes. Left alone that means several stored keys naming one object,
	// which is an object the gateway would believe it had seen twice. Found by
	// FuzzDecryptKey, which exists for exactly this.
	if encoding.EncodeToString(raw) != segment {
		return "", fmt.Errorf("%w: segment is not canonically encoded", ErrName)
	}
	if len(raw) < ivSize {
		return "", fmt.Errorf("%w: segment is shorter than an IV", ErrName)
	}

	block, err := aes.NewCipher(e.encKey)
	if err != nil {
		return "", err
	}
	iv, body := raw[:ivSize], raw[ivSize:]
	plain := make([]byte, len(body))
	cipher.NewCTR(block, iv).XORKeyStream(plain, body)

	// The IV is a PRF of the plaintext, so recomputing it over what came out
	// authenticates the segment. Constant time, because a caller may be
	// probing with keys it did not write.
	want := e.syntheticIV(context, string(plain))
	if subtle.ConstantTimeCompare(iv, want) != 1 {
		return "", fmt.Errorf("%w: segment fails its own check", ErrName)
	}
	return string(plain), nil
}

// syntheticIV derives the IV from the segment and the path that precedes it.
//
// Both inputs are length-prefixed. Without that, context "a/b" with segment "c"
// and context "a" with segment "b/c" would hash identically, and two different
// keys could collide onto one stored key.
func (e *Encrypter) syntheticIV(context, segment string) []byte {
	mac := hmac.New(sha256.New, e.prfKey)
	writeLP(mac, context)
	writeLP(mac, segment)
	return mac.Sum(nil)[:ivSize]
}

// writeLP writes a length-prefixed string, matching lp() in docs/FORMAT.md §1.
func writeLP(mac interface{ Write([]byte) (int, error) }, s string) {
	var length [2]byte
	//nolint:gosec // callers bound segments well below 65535 bytes.
	binary.BigEndian.PutUint16(length[:], uint16(len(s)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(s))
}
