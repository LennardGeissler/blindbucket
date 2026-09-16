package freshness

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// KeySize is the length of the index key. It matches keys.FreshnessKeySize.
	KeySize = 32

	// TagSize is the length of a recorded tag.
	//
	// Sixteen bytes is not a birthday bound. An attacker cannot choose salts --
	// the gateway generates them -- so the question is second preimage over
	// values they do not control, and 128 bits is far past what that needs.
	TagSize = 16

	// SaltSize is the length of a segment salt, from FORMAT.md §4.1.
	//
	// Repeated rather than imported from internal/crypto/stream, which this
	// package otherwise has no reason to depend on. TestSaltSizeMatchesTheStreamFormat
	// is what keeps the two from drifting.
	SaltSize = 20

	// MaxParts is the largest number of salts a tag may cover, from the S3 limit
	// on parts in a multipart upload.
	MaxParts = 10000
)

// tagInfo domain-separates the tag hash from every other SHA-256 in the project.
const tagInfo = "blindbucket/v1/freshness-tag"

// ErrNoSalts reports a tag derivation with nothing to derive from.
var ErrNoSalts = errors.New("freshness: an object has at least one segment salt")

// Tag identifies one write of one object.
//
// It is a hash over the object's segment salts in part order -- a single salt
// for a single-part object, one per part for a multipart one. FORMAT.md §4.1
// requires each to be freshly generated per segment, including for every retried
// attempt at the same part number, so the salts already distinguish one write
// from another and this only has to write them down. ADR-014 made the same
// observation one level lower, where a manifest records a part's salt to catch a
// substituted attempt within an upload.
type Tag [TagSize]byte

// IsZero reports whether the tag is the zero value, which no derivation produces
// and which the record format uses for a tombstone.
func (t Tag) IsZero() bool { return t == Tag{} }

// String renders the tag for logs and errors. It is truncated: the whole point
// of the index is that its contents name no object, and a full tag in a log line
// is a correlator between the log and the index.
func (t Tag) String() string { return fmt.Sprintf("%x…", t[:4]) }

// TagFromSalts derives the tag of an object from its segment salts, in part
// order.
//
// The count is hashed in first so that the salts of one object cannot be read as
// the salts of another with a different split -- the same reason FORMAT.md §1
// length-prefixes everything. The salts themselves are fixed width, so nothing
// further is needed between them.
func TagFromSalts(salts [][SaltSize]byte) (Tag, error) {
	if len(salts) == 0 {
		return Tag{}, ErrNoSalts
	}
	if len(salts) > MaxParts {
		return Tag{}, fmt.Errorf("freshness: %d salts exceeds the %d-part limit",
			len(salts), MaxParts)
	}
	h := sha256.New()
	h.Write([]byte(tagInfo))
	var n [4]byte
	//nolint:gosec // bounded by MaxParts above.
	binary.BigEndian.PutUint32(n[:], uint32(len(salts)))
	h.Write(n[:])
	for i := range salts {
		h.Write(salts[i][:])
	}
	var t Tag
	copy(t[:], h.Sum(nil))
	return t, nil
}
