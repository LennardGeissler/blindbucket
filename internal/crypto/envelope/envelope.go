// Package envelope implements the local BBF1 file format: a small envelope
// naming the key that protects the file, followed by exactly one segment.
//
// It is what `blindbucket encrypt` and `blindbucket decrypt` produce and consume.
// The format exists so the crypto core can be exercised, reviewed and fuzzed
// without a running proxy or any object storage. See docs/FORMAT.md section 9.
package envelope

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// Magic marks a blindbucket file.
var Magic = [4]byte{'B', 'B', 'F', '1'}

// Version is the envelope version this package reads and writes.
const Version = 1

// fixedPrefixSize covers the magic, the version byte and the key id's length
// prefix -- everything that must be read before the key id itself.
const fixedPrefixSize = len(Magic) + 1 + 2

// ErrNotBlindbucketFile reports input that is not a BBF1 file at all, as opposed
// to one that is damaged. The distinction matters for the error a user sees:
// pointing decrypt at the wrong file is a different mistake from a corrupted one.
var ErrNotBlindbucketFile = errors.New("envelope: not a blindbucket file")

// Encrypt seals everything from src into dst as one blindbucket file.
//
// A fresh data key is drawn for the file and wrapped under the provider's active
// KEK, bound to that key's id. Nothing is buffered: memory stays proportional to
// the chunk size regardless of how large src is.
func Encrypt(ctx context.Context, dst io.Writer, src io.Reader, provider keys.KeyProvider, log2C uint8) error {
	kid := provider.ActiveKID()
	if err := keys.ValidateKID(kid); err != nil {
		return err
	}
	aad, err := keys.FileAAD(kid)
	if err != nil {
		return err
	}

	dek, err := keys.NewDEK()
	if err != nil {
		return fmt.Errorf("envelope: generating a data key: %w", err)
	}
	defer dek.Wipe()

	wrapped, err := provider.Wrap(ctx, kid, dek.Bytes(), aad)
	if err != nil {
		return fmt.Errorf("envelope: wrapping the data key: %w", err)
	}

	header := make([]byte, 0, fixedPrefixSize+len(kid)+len(wrapped))
	header = append(header, Magic[:]...)
	header = append(header, Version)
	//nolint:gosec // ValidateKID above bounds the length at MaxKIDLen.
	header = binary.BigEndian.AppendUint16(header, uint16(len(kid)))
	header = append(header, kid...)
	header = append(header, wrapped...)
	if _, err := dst.Write(header); err != nil {
		return err
	}

	w, err := stream.NewEncryptWriter(dst, dek.Bytes(), stream.SegmentParams{Log2ChunkSize: log2C})
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		// Deliberately not closing: an aborted stream must not be completed into
		// a valid segment.
		return err
	}
	return w.Close()
}

// Decrypt reads a blindbucket file from src and writes its plaintext to dst.
//
// No plaintext is written until the first chunk has been verified, so a wrong
// key or a damaged file produces an error and an untouched dst rather than a
// partially written one.
func Decrypt(ctx context.Context, dst io.Writer, src io.Reader, provider keys.KeyProvider) error {
	kid, wrapped, err := readHeader(src)
	if err != nil {
		return err
	}

	aad, err := keys.FileAAD(kid)
	if err != nil {
		return err
	}
	dek, err := provider.Unwrap(ctx, kid, wrapped, aad)
	if err != nil {
		return fmt.Errorf("envelope: unwrapping the data key for %q: %w", kid, err)
	}
	defer clear(dek)

	// AnyChunkSize: a file states its own chunk size in the segment header, and
	// there is nothing else to check it against.
	r, err := stream.NewDecryptReader(src, dek, stream.SegmentParams{Log2ChunkSize: stream.AnyChunkSize})
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	if err := r.VerifyFirst(); err != nil {
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}

// KeyID reports which key a file was encrypted under, without decrypting it.
// It is what lets tooling decide whether a file needs rewrapping.
func KeyID(src io.Reader) (string, error) {
	kid, _, err := readHeader(src)
	return kid, err
}

// Header is a BBF1 envelope read without any key material.
type Header struct {
	// KeyID is the identifier of the key the file's data key is wrapped under.
	KeyID string
	// Size is how many bytes the envelope occupies, which is where the file's
	// single segment begins (docs/FORMAT.md section 9).
	Size int64
}

// DecodeHeader reads a BBF1 envelope from src and reports it, without decrypting
// anything and without needing a keyring.
//
// It is the same reading that Decrypt does to find the key id, exported for
// `blindbucket inspect`. The envelope is not authenticated on its own, but its
// key id is bound: the wrapped data key is sealed with the key id in its
// associated data (docs/FORMAT.md section 6.2), so an id that has been altered
// stops the file decrypting rather than quietly redirecting it to another key.
func DecodeHeader(src io.Reader) (Header, error) {
	kid, wrapped, err := readHeader(src)
	if err != nil {
		return Header{}, err
	}
	return Header{
		KeyID: kid,
		Size:  int64(fixedPrefixSize + len(kid) + len(wrapped)),
	}, nil
}

func readHeader(src io.Reader) (kid string, wrapped []byte, err error) {
	prefix := make([]byte, fixedPrefixSize)
	if _, err := io.ReadFull(src, prefix); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "", nil, fmt.Errorf("%w: shorter than an envelope header", ErrNotBlindbucketFile)
		}
		return "", nil, err
	}
	if string(prefix[:len(Magic)]) != string(Magic[:]) {
		return "", nil, fmt.Errorf("%w: bad magic %q", ErrNotBlindbucketFile, prefix[:len(Magic)])
	}
	if v := prefix[len(Magic)]; v != Version {
		return "", nil, fmt.Errorf("envelope: unsupported file version %d, this build reads %d", v, Version)
	}

	kidLen := int(binary.BigEndian.Uint16(prefix[len(Magic)+1:]))
	if kidLen == 0 || kidLen > keys.MaxKIDLen {
		return "", nil, fmt.Errorf("envelope: key id length %d outside 1..%d", kidLen, keys.MaxKIDLen)
	}

	rest := make([]byte, kidLen+keys.WrappedDEKSize)
	if _, err := io.ReadFull(src, rest); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "", nil, fmt.Errorf("envelope: truncated header")
		}
		return "", nil, err
	}

	kid = string(rest[:kidLen])
	if err := keys.ValidateKID(kid); err != nil {
		return "", nil, err
	}
	return kid, rest[kidLen:], nil
}
