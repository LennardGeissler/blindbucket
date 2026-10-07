package stream

import (
	"crypto/rand"
	"encoding/binary"
)

// header is the parsed form of a 32-byte segment header.
type header struct {
	params SegmentParams
	salt   [SaltSize]byte
	// raw holds the header exactly as it appears on the wire. Every chunk in the
	// segment is sealed with these bytes as associated data, so they are kept
	// verbatim rather than re-serialised: the associated data must be what was
	// read, not what a second encoding pass would produce.
	raw [HeaderSize]byte
}

// SaltFromHeader reads the salt out of a raw 32-byte segment header.
//
// The header is associated data of every chunk in its segment, so a caller that
// has authenticated any chunk has also authenticated this value.
func SaltFromHeader(raw []byte) ([SaltSize]byte, bool) {
	var salt [SaltSize]byte
	if len(raw) < HeaderSize {
		return salt, false
	}
	copy(salt[:], raw[offSalt:offSalt+SaltSize])
	return salt, true
}

// Header is a segment header that has been read without any key material.
type Header struct {
	// Magic and Version are the marker and version byte as they appear in the
	// bytes rather than as the package constants. A tool that prints the format
	// should print what it found: today DecodeHeader refuses every version but the
	// one it knows, so the two agree, and the day a second version becomes
	// readable the constant would still report 1.
	Magic   [len(Magic)]byte
	Version byte
	// Params are the chunk size, the multipart flag and the part index, as the
	// header claims them.
	Params SegmentParams
	// Salt is the per-segment salt that separates this segment's subkey from every
	// other segment's.
	Salt [SaltSize]byte
}

// DecodeHeader validates and decodes a 32-byte segment header without any key
// material.
//
// The fields it returns are what the header claims, not what has been verified:
// the header only becomes authentic once a chunk sealed with it has been
// authenticated, which is step 4 of docs/FORMAT.md section 5.2. A caller that
// needs trust rather than reporting goes through NewDecryptReader.
//
// It exists so that `blindbucket inspect` reports the fields the decoder reads
// instead of carrying a second copy of section 4.1's offsets, where a change to
// one could silently disagree with the other. That is also why the magic and the
// version are returned rather than reached for as constants: the same argument
// that removes the offsets from the CLI removes them from the report.
func DecodeHeader(b []byte) (Header, error) {
	h, err := parseHeader(b)
	if err != nil {
		return Header{}, err
	}
	var magic [len(Magic)]byte
	copy(magic[:], h.raw[offMagic:])
	return Header{
		Magic:   magic,
		Version: h.raw[offVersion],
		Params:  h.params,
		Salt:    h.salt,
	}, nil
}

// newHeader builds a header for p with a freshly generated salt.
//
// The salt is what separates one segment's subkey from every other segment's.
// It must never be reused, including across retries of the same part number;
// see docs/FORMAT.md section 11.
func newHeader(p SegmentParams) (header, error) {
	if err := p.Validate(); err != nil {
		return header{}, err
	}
	var salt [SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return header{}, err
	}
	return newHeaderWithSalt(p, salt)
}

// newHeaderWithSalt builds a header with a caller-supplied salt. It exists for
// known-answer tests, which must fix every input to pin down the ciphertext.
func newHeaderWithSalt(p SegmentParams, salt [SaltSize]byte) (header, error) {
	if err := p.Validate(); err != nil {
		return header{}, err
	}

	h := header{params: p, salt: salt}
	copy(h.raw[offMagic:], Magic[:])
	h.raw[offVersion] = Version
	h.raw[offLog2C] = p.Log2ChunkSize
	if p.Multipart {
		h.raw[offFlags] = flagMultipart
	}
	h.raw[offReserved] = 0
	binary.BigEndian.PutUint32(h.raw[offIndex:], p.Index)
	copy(h.raw[offSalt:], salt[:])
	return h, nil
}

// parseHeader validates and decodes a 32-byte segment header.
//
// Every field is checked before the caller can derive a buffer size from it. At
// this point the header is still unauthenticated -- it only becomes trustworthy
// once the first chunk verifies -- so a header claiming log2C = 30 must be
// rejected here rather than allowed to coerce a 1 GiB allocation. See
// docs/FORMAT.md section 5.2.
func parseHeader(b []byte) (header, error) {
	if len(b) != HeaderSize {
		return header{}, integrityf(KindHeader, "header is %d bytes, want %d", len(b), HeaderSize)
	}
	if string(b[offMagic:offMagic+len(Magic)]) != string(Magic[:]) {
		return header{}, integrityf(KindHeader, "bad magic %q", b[offMagic:offMagic+len(Magic)])
	}
	if v := b[offVersion]; v != Version {
		return header{}, integrityf(KindHeader, "unsupported format version %d", v)
	}

	log2C := b[offLog2C]
	if err := ValidateLog2ChunkSize(log2C); err != nil {
		return header{}, integrityf(KindHeader, "%v", err)
	}
	if r := b[offReserved]; r != 0 {
		return header{}, integrityf(KindHeader, "reserved byte is %#02x, want 0x00", r)
	}
	if f := b[offFlags]; f&^flagMultipart != 0 {
		return header{}, integrityf(KindHeader, "undefined flag bits set: %#02x", f)
	}

	p := SegmentParams{
		Log2ChunkSize: log2C,
		Multipart:     b[offFlags]&flagMultipart != 0,
		Index:         binary.BigEndian.Uint32(b[offIndex:]),
	}
	if err := p.Validate(); err != nil {
		return header{}, integrityf(KindHeader, "%v", err)
	}

	h := header{params: p}
	copy(h.raw[:], b)
	copy(h.salt[:], b[offSalt:])
	return h, nil
}

// requireParams reports whether the header describes the segment the caller
// expected.
//
// This is the check that catches a provider presenting a multipart object as a
// single-part one, or serving part 7 where part 3 was requested. It is also
// enforced cryptographically -- these fields are in the associated data of every
// chunk -- but failing here produces a precise error before any decryption work.
func (h header) requireParams(want SegmentParams) error {
	switch {
	case want.Log2ChunkSize != AnyChunkSize && h.params.Log2ChunkSize != want.Log2ChunkSize:
		return integrityf(KindHeader, "chunk size 2^%d, want 2^%d",
			h.params.Log2ChunkSize, want.Log2ChunkSize)
	case h.params.Multipart != want.Multipart:
		return integrityf(KindHeader, "multipart flag is %t, want %t",
			h.params.Multipart, want.Multipart)
	case h.params.Index != want.Index:
		return integrityf(KindHeader, "segment index %d, want %d", h.params.Index, want.Index)
	}
	return nil
}

// aad returns the associated data every chunk of this segment is sealed with.
func (h header) aad() []byte { return h.raw[:] }

// chunkSize returns the plaintext chunk size of this segment.
func (h header) chunkSize() int { return 1 << h.params.Log2ChunkSize }
