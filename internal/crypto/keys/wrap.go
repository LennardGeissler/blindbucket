package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const (
	// wrapNonceSize is the AES-GCM nonce prepended to every wrapped key.
	wrapNonceSize = 12
	// wrapTagSize is the AES-GCM tag appended by Seal.
	wrapTagSize = 16
	// WrappedDEKSize is the exact size of a wrapped data key: nonce, key and tag.
	// It is 80 characters of unpadded base64url in object metadata.
	WrappedDEKSize = wrapNonceSize + KeySize + wrapTagSize
	// maxSealed bounds what sealKey wraps. A secret is 32 bytes; the largest
	// thing it seals is a keyring's directory (docs/FORMAT.md section 18.3),
	// which at this size would list tens of thousands of tenants.
	maxSealed = 1 << 20
)

// sealKey wraps plain under kek, binding it to aad.
//
// The nonce is random rather than a counter: there is no shared state between
// proxy instances to count with, and at 96 bits the collision probability stays
// negligible for any realistic number of objects under one KEK.
func sealKey(kek, plain, aad []byte) ([]byte, error) {
	if len(plain) > maxSealed {
		return nil, fmt.Errorf("keys: refusing to seal %d bytes, at most %d", len(plain), maxSealed)
	}
	aead, err := newWrapAEAD(kek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, wrapNonceSize, wrapNonceSize+len(plain)+wrapTagSize)
	if _, err := rand.Read(out[:wrapNonceSize]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[:wrapNonceSize], plain, aad), nil
}

// openKey reverses sealKey. Every failure reports ErrUnwrap without detail.
func openKey(kek, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) < wrapNonceSize+wrapTagSize {
		return nil, fmt.Errorf("%w: wrapped key is %d bytes, too short to be one", ErrUnwrap, len(wrapped))
	}
	aead, err := newWrapAEAD(kek)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, wrapped[:wrapNonceSize], wrapped[wrapNonceSize:], aad)
	if err != nil {
		return nil, ErrUnwrap
	}
	return plain, nil
}

func newWrapAEAD(kek []byte) (cipher.AEAD, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("keys: key-encryption key is %d bytes, want %d", len(kek), KeySize)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncodeWrapped renders a wrapped key for object metadata: unpadded base64url,
// which is safe in an HTTP header and in an S3 user-metadata value.
func EncodeWrapped(wrapped []byte) string {
	return base64.RawURLEncoding.EncodeToString(wrapped)
}

// DecodeWrapped parses the output of EncodeWrapped.
func DecodeWrapped(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("keys: wrapped key is not valid base64url: %w", err)
	}
	return b, nil
}
