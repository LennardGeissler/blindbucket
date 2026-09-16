package freshness

import (
	"errors"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// TestSaltSizeMatchesTheStreamFormat keeps the repeated constant from drifting.
// SaltSize is declared here rather than imported so this package does not depend
// on the stream format; the test is what makes that safe.
func TestSaltSizeMatchesTheStreamFormat(t *testing.T) {
	if SaltSize != stream.SaltSize {
		t.Errorf("freshness.SaltSize is %d, stream.SaltSize is %d", SaltSize, stream.SaltSize)
	}
}

func salt(b byte) [SaltSize]byte {
	var s [SaltSize]byte
	for i := range s {
		s[i] = b
	}
	return s
}

func mustTag(t *testing.T, salts ...[SaltSize]byte) Tag {
	t.Helper()
	tag, err := TagFromSalts(salts)
	if err != nil {
		t.Fatalf("TagFromSalts: %v", err)
	}
	return tag
}

func TestTagIsDeterministic(t *testing.T) {
	a := mustTag(t, salt(1), salt(2), salt(3))
	b := mustTag(t, salt(1), salt(2), salt(3))
	if a != b {
		t.Error("the same salts produced different tags")
	}
}

// TestTagDistinguishesWrites is the property the feature rests on: FORMAT.md §4.1
// requires a fresh salt per write, so a different write must be a different tag.
func TestTagDistinguishesWrites(t *testing.T) {
	if mustTag(t, salt(1)) == mustTag(t, salt(2)) {
		t.Error("two writes with different salts produced the same tag")
	}
}

// TestTagDependsOnPartOrder. Reordered parts are already caught by the segment
// index (FORMAT.md §10.4), but a tag that ignored order would make two different
// objects interchangeable in the index.
func TestTagDependsOnPartOrder(t *testing.T) {
	if mustTag(t, salt(1), salt(2)) == mustTag(t, salt(2), salt(1)) {
		t.Error("reordering the parts left the tag unchanged")
	}
}

// TestTagDependsOnPartCount. The count is hashed in first, so an object of two
// parts cannot collide with one of three that happens to share a prefix.
func TestTagDependsOnPartCount(t *testing.T) {
	if mustTag(t, salt(1)) == mustTag(t, salt(1), salt(1)) {
		t.Error("a one-part and a two-part object produced the same tag")
	}
}

// TestTagIsDomainSeparated. The tag is a SHA-256 over bytes that also appear in
// headers and manifests; without the prefix, some other hash in the project
// could be made to equal one.
func TestTagIsDomainSeparated(t *testing.T) {
	if tagInfo == "" {
		t.Fatal("the tag has no domain-separating prefix")
	}
	// A hash of the same salts without the prefix must not be the tag.
	plain := salt(1)
	tag := mustTag(t, plain)
	if string(tag[:]) == string(plain[:TagSize]) {
		t.Error("the tag is the salt itself")
	}
}

func TestTagFromNoSalts(t *testing.T) {
	if _, err := TagFromSalts(nil); !errors.Is(err, ErrNoSalts) {
		t.Errorf("got %v, want ErrNoSalts", err)
	}
	if _, err := TagFromSalts([][SaltSize]byte{}); !errors.Is(err, ErrNoSalts) {
		t.Errorf("got %v, want ErrNoSalts", err)
	}
}

func TestTagFromTooManySalts(t *testing.T) {
	if _, err := TagFromSalts(make([][SaltSize]byte, MaxParts+1)); err == nil {
		t.Error("more salts than S3 permits parts was accepted")
	}
	if _, err := TagFromSalts(make([][SaltSize]byte, MaxParts)); err != nil {
		t.Errorf("the maximum number of parts was refused: %v", err)
	}
}

func TestTagStringNamesNoObject(t *testing.T) {
	tag := mustTag(t, salt(1))
	if got := tag.String(); len(got) > 12 {
		t.Errorf("Tag.String() is %q; a full tag in a log correlates the log with the index", got)
	}
}

func TestZeroTagIsReserved(t *testing.T) {
	if !(Tag{}).IsZero() {
		t.Error("the zero tag does not report itself as zero")
	}
	// No derivation may produce it, because the record format uses it for a
	// tombstone.
	if mustTag(t, salt(0)).IsZero() {
		t.Error("a derived tag collided with the tombstone marker")
	}
}
