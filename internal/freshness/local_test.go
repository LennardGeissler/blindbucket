package freshness

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func testStore(t *testing.T) (*Local, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "freshness.idx")
	key := testKey(t)
	l, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path, key
}

func tagOf(t *testing.T, b byte) Tag {
	t.Helper()
	var salt [SaltSize]byte
	for i := range salt {
		salt[i] = b
	}
	tag, err := TagFromSalts([][SaltSize]byte{salt})
	if err != nil {
		t.Fatalf("TagFromSalts: %v", err)
	}
	return tag
}

// TestTrustOnFirstUse is the bound ADR-018 rests on: an index that has never seen
// an object says so and records it, and every later read is checked.
func TestTrustOnFirstUse(t *testing.T) {
	l, _, _ := testStore(t)
	first := tagOf(t, 1)

	v, err := l.Check("bucket", "photos/a.jpg", first)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v != Unknown {
		t.Fatalf("first sighting: %v, want unknown", v)
	}
	if !v.OK() {
		t.Error("an unknown object must not block a read")
	}

	v, err = l.Check("bucket", "photos/a.jpg", first)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v != Fresh {
		t.Errorf("second sighting of the same write: %v, want fresh", v)
	}
}

// TestRollbackIsDetected is the whole feature.
func TestRollbackIsDetected(t *testing.T) {
	l, _, _ := testStore(t)
	old, current := tagOf(t, 1), tagOf(t, 2)

	if err := l.Record("bucket", "photos/a.jpg", old); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Record("bucket", "photos/a.jpg", current); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// The provider serves the earlier write back.
	v, err := l.Check("bucket", "photos/a.jpg", old)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v != Stale {
		t.Errorf("a rolled-back object: %v, want stale", v)
	}
	if v.OK() {
		t.Error("a stale object must block a read")
	}
}

// TestSuppressedDeleteIsDetected. Without a tombstone, a provider could ignore a
// DeleteObject and keep serving the object with nothing in the index to disagree.
func TestSuppressedDeleteIsDetected(t *testing.T) {
	l, _, _ := testStore(t)
	tag := tagOf(t, 1)

	if err := l.Record("bucket", "photos/a.jpg", tag); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Forget("bucket", "photos/a.jpg"); err != nil {
		t.Fatalf("Forget: %v", err)
	}

	v, err := l.Check("bucket", "photos/a.jpg", tag)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v != Deleted {
		t.Errorf("an object the index recorded as deleted: %v, want deleted", v)
	}
	if v.OK() {
		t.Error("a deleted object must block a read")
	}
}

// TestIndexSurvivesARestart: a gateway that restarts must not forget, or every
// restart would be a window in which a rollback is recorded as the truth.
func TestIndexSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	key := testKey(t)
	tag := tagOf(t, 7)

	l, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := l.Record("bucket", "photos/a.jpg", tag); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Forget("bucket", "photos/gone.jpg"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if v, _ := reopened.Check("bucket", "photos/a.jpg", tag); v != Fresh {
		t.Errorf("after a restart: %v, want fresh", v)
	}
	if v, _ := reopened.Check("bucket", "photos/a.jpg", tagOf(t, 8)); v != Stale {
		t.Errorf("a rollback after a restart: %v, want stale", v)
	}
	if v, _ := reopened.Check("bucket", "photos/gone.jpg", tag); v != Deleted {
		t.Errorf("a tombstone after a restart: %v, want deleted", v)
	}
	if got := reopened.Stats(); got.Objects != 1 || got.Tombstones != 1 {
		t.Errorf("stats after a restart: %+v, want 1 object and 1 tombstone", got)
	}
}

// TestTornTailKeepsEverythingBeforeIt. A process killed mid-append leaves a
// partial record. Everything before it is intact by construction -- fixed width,
// checksummed -- and dropping the whole index because of the last 20 bytes would
// turn a crash into a total loss of detection.
func TestTornTailKeepsEverythingBeforeIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	key := testKey(t)

	l, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 5 {
		if err := l.Record("bucket", string(rune('a'+i)), tagOf(t, byte(i))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Cut the last record in half.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if err := os.Truncate(path, info.Size()-recordSize/2); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	reopened, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("a torn tail must not fail the open: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if got := reopened.Stats().Objects; got != 4 {
		t.Errorf("replayed %d objects, want the 4 before the tear", got)
	}
	if v, _ := reopened.Check("bucket", "a", tagOf(t, 0)); v != Fresh {
		t.Errorf("an object before the tear: %v, want fresh", v)
	}
	// And the one that was torn away is back to trust on first use, not wrong.
	if v, _ := reopened.Check("bucket", "e", tagOf(t, 99)); v != Unknown {
		t.Errorf("the object lost to the tear: %v, want unknown", v)
	}
}

// TestCorruptRecordStopsTheReplay. A record that does not checksum is not
// replayed as if it were valid -- that would be the index asserting something
// about an object on the strength of damaged bytes.
func TestCorruptRecordStopsTheReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	key := testKey(t)

	l, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 4 {
		if err := l.Record("bucket", string(rune('a'+i)), tagOf(t, byte(i))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Flip a bit inside the third record's tag.
	raw[headerSize+2*recordSize+20] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reopened, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if got := reopened.Stats().Objects; got != 2 {
		t.Errorf("replayed %d objects, want the 2 before the damaged record", got)
	}
}

// TestAFileThatIsNotAnIndexIsRefused. A path pointing at the wrong file is a
// configuration mistake, and overwriting whatever is there would be the wrong
// direction to be wrong in.
func TestAFileThatIsNotAnIndexIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-an-index")
	if err := os.WriteFile(path, []byte("this is somebody else's file, thanks"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Open(Options{Path: path, Key: testKey(t)}); !errors.Is(err, ErrDamaged) {
		t.Errorf("got %v, want ErrDamaged", err)
	}
}

// TestCompactionShrinksTheFileAndKeepsTheAnswers. Overwriting one object a
// million times must not leave a million records behind.
func TestCompactionShrinksTheFileAndKeepsTheAnswers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	key := testKey(t)
	l, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	// One object, overwritten past the compaction floor.
	var last Tag
	for i := range compactFloor + 200 {
		last = tagOf(t, byte(i%251))
		if err := l.Record("bucket", "hot", last); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	// A second object, so compaction has more than one entry to carry over.
	other := tagOf(t, 252)
	if err := l.Record("bucket", "cold", other); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if got := l.Stats().Records; got > compactFloor {
		t.Errorf("the index holds %d records for 2 objects; compaction did not run", got)
	}
	if v, _ := l.Check("bucket", "hot", last); v != Fresh {
		t.Errorf("after compaction: %v, want fresh", v)
	}
	if v, _ := l.Check("bucket", "cold", other); v != Fresh {
		t.Errorf("after compaction: %v, want fresh", v)
	}
	// And the compacted file must survive a restart.
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := Open(Options{Path: path, Key: key})
	if err != nil {
		t.Fatalf("reopening a compacted index: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if v, _ := reopened.Check("bucket", "hot", last); v != Fresh {
		t.Errorf("after compaction and a restart: %v, want fresh", v)
	}
}

// TestExpiredTombstonesAreDropped. Tombstones are the one entry that does not
// shrink when the bucket does, so they expire -- and past that a suppressed
// delete stops being detectable, which is a limit worth having a test say out
// loud.
func TestExpiredTombstonesAreDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	key := testKey(t)
	l, err := Open(Options{Path: path, Key: key, TombstoneRetention: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Timestamps have second granularity, so the clock is moved rather than
	// waited on: a retention worth testing is measured in days.
	clock := time.Now().Unix()
	l.now = func() int64 { return clock }

	if err := l.Forget("bucket", "gone"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if v, _ := l.Check("bucket", "gone", tagOf(t, 1)); v != Deleted {
		t.Fatalf("a fresh tombstone: %v, want deleted", v)
	}

	clock += int64((48 * time.Hour).Seconds())
	// Drive a compaction.
	for i := range compactFloor + 200 {
		if err := l.Record("bucket", "hot", tagOf(t, byte(i%251))); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	if got := l.Stats().Tombstones; got != 0 {
		t.Errorf("%d tombstones survived past their retention, want 0", got)
	}
	if v, _ := l.Check("bucket", "gone", tagOf(t, 1)); v != Unknown {
		t.Errorf("after the tombstone expired: %v, want unknown", v)
	}
}

// TestTheIndexHoldsNoNames. ADR-015 encrypts names in the bucket and ADR-016
// encrypts them in the log; an index writing them plainly would put on the
// gateway's own disk exactly what both of those hide.
func TestTheIndexHoldsNoNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	l, err := Open(Options{Path: path, Key: testKey(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const secret = "payroll/2026/salaries.xlsx"
	if err := l.Record("confidential", secret, tagOf(t, 1)); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, want := range []string{secret, "payroll", "salaries", "confidential", ".xlsx"} {
		if bytes.Contains(raw, []byte(want)) {
			t.Errorf("the index file contains %q in clear", want)
		}
	}
}

// TestADifferentKeyReadsNothing. The name hashes are keyed, so an index opened
// under another keyring is not wrong about objects -- it simply knows none of
// them, which is the recoverable failure rather than the dangerous one.
func TestADifferentKeyReadsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	tag := tagOf(t, 1)

	l, err := Open(Options{Path: path, Key: testKey(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := l.Record("bucket", "photos/a.jpg", tag); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	other, err := Open(Options{Path: path, Key: testKey(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = other.Close() }()
	if v, _ := other.Check("bucket", "photos/a.jpg", tag); v != Unknown {
		t.Errorf("under a different key: %v, want unknown", v)
	}
}

// TestBucketAndKeyAreUnambiguous. Without length prefixes the two fields
// concatenate, and bucket "a" with key "bc" then hashes to the same bytes as
// bucket "ab" with key "c" -- two different objects sharing one index entry, so
// that writing either would make the other read as rolled back.
//
// The pair matters: an earlier version of this test used "a"+"b/c" against
// "a/b"+"c", which concatenate to "ab/c" and "a/bc" and therefore do not collide
// even with the prefixes removed. It passed against the bug it was meant to
// catch.
func TestBucketAndKeyAreUnambiguous(t *testing.T) {
	l, _, _ := testStore(t)
	first, second := tagOf(t, 1), tagOf(t, 2)

	if err := l.Record("a", "bc", first); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if v, _ := l.Check("ab", "c", second); v != Unknown {
		t.Errorf("a different object read as the first: %v, want unknown", v)
	}
	// And the first object is untouched by the second having been recorded.
	if v, _ := l.Check("a", "bc", first); v != Fresh {
		t.Errorf("the first object after the second was seen: %v, want fresh", v)
	}
}

func TestConcurrentUse(t *testing.T) {
	l, _, _ := testStore(t)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				key := string(rune('a'+w)) + string(rune('0'+i%10))
				tag := tagOf(t, byte(i))
				if err := l.Record("bucket", key, tag); err != nil {
					t.Errorf("Record: %v", err)
					return
				}
				if _, err := l.Check("bucket", key, tag); err != nil {
					t.Errorf("Check: %v", err)
					return
				}
				if err := l.Forget("bucket", key); err != nil {
					t.Errorf("Forget: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestOpenRejectsAWrongKeyLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.idx")
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := Open(Options{Path: path, Key: make([]byte, n)}); err == nil {
			t.Errorf("a %d-byte key was accepted", n)
		}
	}
}

func TestClosedStoreRefuses(t *testing.T) {
	l, _, _ := testStore(t)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := l.Check("bucket", "k", tagOf(t, 1)); err == nil {
		t.Error("a closed index answered a check")
	}
	if err := l.Record("bucket", "k", tagOf(t, 1)); err == nil {
		t.Error("a closed index accepted a record")
	}
	if err := l.Close(); err != nil {
		t.Errorf("closing twice: %v", err)
	}
}
