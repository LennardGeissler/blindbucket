package verify

import (
	"fmt"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

// Layout is the ciphertext geometry of a multipart object.
//
// A multipart object is the concatenation of one segment per part, so every
// part's ciphertext offset follows from the plaintext sizes in the manifest and
// the chunk size. That arithmetic is what makes a range request on a multipart
// object cost the chunks it touches rather than the whole object.
//
// The fields are read by the proxy's range planning and must not be changed
// after NewLayout.
type Layout struct {
	Parts []manifest.Part
	// Sealed[i] is the ciphertext size of part i's segment.
	Sealed []int64
	// CipherStart[i] and PlainStart[i] are part i's offsets within the object.
	CipherStart []int64
	PlainStart  []int64

	TotalCipher int64
	TotalPlain  int64
	Log2C       uint8
	// hasSalts reports that the manifest names which attempt each part is, so
	// the segment headers can be checked against it. False for a manifest
	// written before BBM2, where there is nothing to check against and an
	// all-zero salt must not be mistaken for one.
	hasSalts bool
}

// NewLayout computes the geometry of the parts a manifest describes.
func NewLayout(parts []manifest.Part, log2C uint8, hasSalts bool) (*Layout, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: the manifest lists no parts", manifest.ErrVerify)
	}
	l := &Layout{
		Parts:       parts,
		hasSalts:    hasSalts,
		Sealed:      make([]int64, len(parts)),
		CipherStart: make([]int64, len(parts)),
		PlainStart:  make([]int64, len(parts)),
		Log2C:       log2C,
	}
	for i, part := range parts {
		sealed, err := stream.SealedSize(part.PlainSize, log2C)
		if err != nil {
			return nil, fmt.Errorf("%w: part %d has an impossible size: %w",
				manifest.ErrVerify, part.Number, err)
		}
		l.Sealed[i] = sealed
		l.CipherStart[i] = l.TotalCipher
		l.PlainStart[i] = l.TotalPlain
		l.TotalCipher += sealed
		l.TotalPlain += part.PlainSize
	}
	return l, nil
}

// CheckSalt refuses a segment that is not the attempt the manifest names.
//
// A client that retries a part leaves two valid segments under the same part
// number, both authentic. Without this, a provider could serve either one and
// every tag would verify -- THREAT_MODEL section 5.2. The salt is in the
// authenticated header, so a provider cannot fake it without breaking every
// chunk in the segment; it can only substitute a whole genuine segment, which
// is exactly what this catches.
func (l *Layout) CheckSalt(i int, got [stream.SaltSize]byte) error {
	if !l.hasSalts {
		return nil
	}
	if got != l.Parts[i].Salt {
		return fmt.Errorf(
			"%w: part %d is a different attempt than the manifest names",
			manifest.ErrVerify, l.Parts[i].Number)
	}
	return nil
}

// Salts returns the part salts in part order, for the freshness tag of ADR-018.
//
// Empty when the manifest predates BBM2 and records none. Nothing can be said
// about such an object's identity, and an all-zero salt per part would be a
// confident wrong answer rather than an absent one.
func (l *Layout) Salts() [][stream.SaltSize]byte {
	if !l.hasSalts {
		return nil
	}
	out := make([][stream.SaltSize]byte, len(l.Parts))
	for i := range l.Parts {
		out[i] = l.Parts[i].Salt
	}
	return out
}

// CheckAgainst verifies the manifest's geometry against the object the provider
// actually stores.
//
// The manifest is authenticated and the stored size is not, so a mismatch means
// the provider is serving something other than the object this manifest
// describes -- a truncated object, or parts from elsewhere. Either way it is an
// integrity failure and not a size to be worked around.
func (l *Layout) CheckAgainst(storedCipher int64) error {
	if storedCipher != l.TotalCipher {
		return fmt.Errorf("%w: the object is %d bytes of ciphertext, the manifest describes %d",
			manifest.ErrVerify, storedCipher, l.TotalCipher)
	}
	return nil
}

// Locate returns the index of the part holding a plaintext offset.
func (l *Layout) Locate(offset int64) int {
	// Linear from the front is fine: the list is at most 10000 entries and this
	// runs once per range request, not per chunk.
	for i := len(l.Parts) - 1; i >= 0; i-- {
		if offset >= l.PlainStart[i] {
			return i
		}
	}
	return 0
}
