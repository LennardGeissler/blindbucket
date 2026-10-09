package upload

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// Part ETags carry the salt of the segment they name.
//
// The problem they solve is stated in THREAT_MODEL §5.2: a client that retries
// a part produces two valid segments under the same part number, and the
// manifest -- which records only a number and a size -- cannot say which of
// them the object was completed from. A provider may then serve either, and
// every authentication tag still verifies.
//
// Recording the salt in the manifest fixes that, because FORMAT.md §4.1 already
// requires a fresh salt per attempt. The difficulty is getting the salt to the
// completion: the gateway is stateless, the instance that completes an upload
// may never have seen the part, and a part of an open upload cannot be read
// back from the provider -- it is not an object until the upload completes.
//
// So the salt travels the only path that connects the two: the client. The part
// ETag the gateway answers with carries it, the client echoes that ETag at
// completion exactly as S3 requires, and the gateway reads the salt back out.
// It is the same trick as the upload token (ADR-006), one level down.
//
// Measured against the AWS CLI, boto3, mc and rclone: all four treat a part
// ETag as opaque and echo it unchanged.
const (
	// tagSeparator divides the provider's own ETag from the sealed suffix. It
	// is a character an ETag never contains, and it keeps the provider's hex
	// in front so anything that eyeballs the value still sees what it expects.
	tagSeparator = "."
	// partTagInfo domain-separates the key sealing part tags from the one
	// sealing upload tokens, both of which come from the same KEK.
	partTagInfo = "blindbucket/v1/part-tag"
)

// ErrPartTag reports a part ETag that is missing, malformed or not the one this
// gateway issued for that part.
var ErrPartTag = errors.New("upload: part tag is not valid")

// SealPartTag renders the ETag the client is given for a part.
//
// The sealed suffix authenticates the part number alongside the salt, so a
// client that returns the tag of part 3 as part 4 is refused rather than
// recorded. It is not confidentiality -- the salt is in the segment header the
// provider already holds -- it is integrity, so that a garbled tag becomes an
// error at completion instead of a manifest that names a segment which does not
// exist and an object that fails at its first read.
func SealPartTag(
	ctx context.Context, provider keys.KeyProvider, kid, providerETag string,
	partNumber int, salt [stream.SaltSize]byte,
) (string, error) {
	aead, err := partTagAEAD(ctx, provider, kid)
	if err != nil {
		return "", err
	}

	plain := make([]byte, 0, stream.SaltSize)
	plain = append(plain, salt[:]...)

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plain, partTagAAD(partNumber))

	return quote(unquote(providerETag) + tagSeparator +
		base64.RawURLEncoding.EncodeToString(sealed)), nil
}

// OpenPartTag recovers the salt a client echoed back, and the provider's own
// ETag alongside it.
func OpenPartTag(
	ctx context.Context, provider keys.KeyProvider, kid, clientETag string, partNumber int,
) (etag string, salt [stream.SaltSize]byte, err error) {
	value := unquote(clientETag)
	head, suffix, found := strings.Cut(value, tagSeparator)
	if !found {
		return "", salt, fmt.Errorf("%w: part %d carries no salt", ErrPartTag, partNumber)
	}

	sealed, err := base64.RawURLEncoding.DecodeString(suffix)
	if err != nil {
		return "", salt, fmt.Errorf("%w: part %d has an unreadable tag", ErrPartTag, partNumber)
	}
	aead, err := partTagAEAD(ctx, provider, kid)
	if err != nil {
		return "", salt, err
	}
	if len(sealed) < aead.NonceSize() {
		return "", salt, fmt.Errorf("%w: part %d has a truncated tag", ErrPartTag, partNumber)
	}

	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, partTagAAD(partNumber))
	if err != nil {
		// Either forged, or genuine but for a different part number. Both mean
		// the same thing to whoever sent it.
		return "", salt, fmt.Errorf("%w: part %d", ErrPartTag, partNumber)
	}
	if len(plain) != stream.SaltSize {
		return "", salt, fmt.Errorf("%w: part %d", ErrPartTag, partNumber)
	}
	copy(salt[:], plain)
	return quote(head), salt, nil
}

// partTagAAD binds a sealed tag to its part number.
func partTagAAD(partNumber int) []byte {
	var aad [4]byte
	//nolint:gosec // part numbers are bounded to 1..10000 by the router.
	binary.BigEndian.PutUint32(aad[:], uint32(partNumber))
	return aad[:]
}

// partTagAEAD derives the key that seals part tags under the named KEK.
//
// It is the upload token's key put through HKDF with its own info string,
// rather than the token key itself: the two seal different things with
// different nonce spaces, and one key doing both would make a nonce collision
// between them a possibility that has to be reasoned about instead of one that
// cannot arise.
func partTagAEAD(ctx context.Context, provider keys.KeyProvider, kid string) (cipher.AEAD, error) {
	tk, err := provider.TokenKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	defer clear(tk)

	sub, err := hkdf.Key(sha256.New, tk, nil, partTagInfo, keys.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(sub)

	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func quote(s string) string   { return `"` + s + `"` }
func unquote(s string) string { return strings.Trim(s, `"`) }
