package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// This file is the adversarial half of the audit log's tests. Each case takes a
// genuine log, does to it what an attacker who reached the file would do, and
// asserts what a verifier says afterwards -- including the one case where the
// honest answer is that it says nothing (TestTruncationPastTheLastCheckpoint).

// writeLog produces a signed log with n entries and returns its lines.
func writeLog(t *testing.T, key *keys.AuditKey, n int) (path string, lines [][]byte) {
	t.Helper()
	w, path := openWriter(t, key)
	for i := range n {
		if err := w.Append(event("PutObject", "photos", "object"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path, readLines(t, path)
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return bytes.SplitAfter(bytes.TrimRight(data, "\n"), []byte("\n"))
}

// mustNotVerify asserts that a reassembled log is rejected, and says what was
// done to it if it is not.
func mustNotVerify(t *testing.T, key *keys.AuditKey, lines [][]byte, attack string) {
	t.Helper()
	_, err := Verify(bytes.NewReader(join(lines)), VerifyOptions{PublicKey: testPublic(t, key)})
	if err == nil {
		t.Fatalf("%s went undetected", attack)
	}
	t.Logf("%s: %v", attack, err)
}

func join(lines [][]byte) []byte {
	var out bytes.Buffer
	for _, line := range lines {
		out.Write(line)
		if !bytes.HasSuffix(line, []byte("\n")) {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// indexOfEntry returns the position of the nth entry line.
func indexOfEntry(t *testing.T, lines [][]byte, n int) int {
	t.Helper()
	seen := 0
	for i, line := range lines {
		if !bytes.Contains(line, []byte(`"type":"entry"`)) {
			continue
		}
		if seen == n {
			return i
		}
		seen++
	}
	t.Fatalf("no entry %d in a log of %d lines", n, len(lines))
	return -1
}

func TestAttackEditAnEntry(t *testing.T) {
	key := testKey(t, 20)
	_, lines := writeLog(t, key, 6)

	// Change what an entry says happened, leaving its hash alone.
	i := indexOfEntry(t, lines, 2)
	lines[i] = bytes.Replace(lines[i], []byte(`"status":200`), []byte(`"status":403`), 1)
	mustNotVerify(t, key, lines, "editing an entry's status")
}

func TestAttackEditAndRehash(t *testing.T) {
	key := testKey(t, 21)
	_, lines := writeLog(t, key, 6)

	// The thorough version: edit the entry *and* recompute its own hash, which
	// is what an attacker who read this package would do. It fails at the next
	// entry, whose hash covers this one.
	i := indexOfEntry(t, lines, 2)
	var record Record
	if err := json.Unmarshal(bytes.TrimRight(lines[i], "\n"), &record); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	record.Entry.Op = "DeleteObject"

	head := parseHeadLine(t, lines[0])
	prev := prevHashOf(t, lines, i, head)
	hash, err := record.Entry.chainHashOf(head.Chain, prev)
	if err != nil {
		t.Fatalf("chainHashOf: %v", err)
	}
	record.Entry.Hash = hash
	lines[i] = marshalTest(t, record)

	mustNotVerify(t, key, lines, "editing an entry and recomputing its hash")
}

func TestAttackRemoveAnEntry(t *testing.T) {
	key := testKey(t, 22)
	_, lines := writeLog(t, key, 6)

	i := indexOfEntry(t, lines, 3)
	mustNotVerify(t, key, append(lines[:i:i], lines[i+1:]...), "removing an entry")
}

func TestAttackReorderTwoEntries(t *testing.T) {
	key := testKey(t, 23)
	_, lines := writeLog(t, key, 6)

	i, j := indexOfEntry(t, lines, 1), indexOfEntry(t, lines, 2)
	lines[i], lines[j] = lines[j], lines[i]
	mustNotVerify(t, key, lines, "reordering two entries")
}

func TestAttackDuplicateAnEntry(t *testing.T) {
	key := testKey(t, 24)
	_, lines := writeLog(t, key, 6)

	i := indexOfEntry(t, lines, 2)
	doubled := append([][]byte{}, lines[:i+1]...)
	doubled = append(doubled, lines[i])
	doubled = append(doubled, lines[i+1:]...)
	mustNotVerify(t, key, doubled, "duplicating an entry")
}

// TestAttackSpliceFromAnotherChain is why the chain id is hashed into every
// entry: a genuine, correctly signed record from one log must not be
// transplantable into another.
func TestAttackSpliceFromAnotherChain(t *testing.T) {
	key := testKey(t, 25)
	_, target := writeLog(t, key, 6)
	_, donor := writeLog(t, key, 6)

	i := indexOfEntry(t, target, 3)
	j := indexOfEntry(t, donor, 3)
	target[i] = donor[j]
	mustNotVerify(t, key, target, "splicing an entry from another chain written by the same key")
}

// TestAttackResignWithAnotherKey is the whole-log forgery: rewrite everything,
// sign it with a key you control, and present it as the original.
func TestAttackResignWithAnotherKey(t *testing.T) {
	genuine, forger := testKey(t, 26), testKey(t, 27)

	// A complete, internally consistent log written by the attacker's key.
	forged, _ := writeLog(t, forger, 6)
	data, err := os.ReadFile(forged) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// It verifies against the attacker's key, which is the point of the attack.
	if _, err := Verify(bytes.NewReader(data), VerifyOptions{
		PublicKey: testPublic(t, forger),
	}); err != nil {
		t.Fatalf("the forged log should be internally consistent: %v", err)
	}
	// And is rejected against the key the operator actually published.
	if _, err := Verify(bytes.NewReader(data), VerifyOptions{
		PublicKey: testPublic(t, genuine),
	}); err == nil {
		t.Fatal("a log signed by another key verified against the real one")
	}
}

// TestAttackSwapThePublicKeyInTheHead covers the halfway version of the above:
// leave the entries, claim a different signer.
func TestAttackSwapThePublicKeyInTheHead(t *testing.T) {
	key, other := testKey(t, 28), testKey(t, 29)
	_, lines := writeLog(t, key, 4)

	head := parseHeadLine(t, lines[0])
	head.PublicKey = base64.StdEncoding.EncodeToString(testPublic(t, other))
	lines[0] = marshalTest(t, Record{Type: TypeHead, Head: head})

	mustNotVerify(t, key, lines, "swapping the public key in the head")
}

func TestAttackForgeACheckpoint(t *testing.T) {
	key, forger := testKey(t, 30), testKey(t, 31)
	_, lines := writeLog(t, key, 4)

	head := parseHeadLine(t, lines[0])
	last := lines[len(lines)-1]
	var record Record
	if err := json.Unmarshal(bytes.TrimRight(last, "\n"), &record); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if record.Checkpoint == nil {
		t.Fatal("the log does not end in a checkpoint")
	}

	msg, err := record.Checkpoint.signedMessage(head.Chain)
	if err != nil {
		t.Fatalf("signedMessage: %v", err)
	}
	signer, err := forger.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	record.Checkpoint.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, msg))
	lines[len(lines)-1] = marshalTest(t, record)

	mustNotVerify(t, key, lines, "re-signing a checkpoint with another key")
}

func TestAttackMoveACheckpoint(t *testing.T) {
	key := testKey(t, 32)
	_, lines := writeLog(t, key, 6)

	// A genuine, correctly signed checkpoint, moved to a point in the chain it
	// does not describe.
	last := lines[len(lines)-1]
	i := indexOfEntry(t, lines, 2)
	moved := append([][]byte{}, lines[:i]...)
	moved = append(moved, last)
	moved = append(moved, lines[i:len(lines)-1]...)
	mustNotVerify(t, key, moved, "moving a signed checkpoint to another point in the chain")
}

// TestAttackTruncateBeforeACheckpoint is the truncation that *is* caught: the
// checkpoint that follows asserts a state the shortened chain never reached.
func TestAttackTruncateBeforeACheckpoint(t *testing.T) {
	key := testKey(t, 33)
	path := filepath.Join(t.TempDir(), "audit.log")

	cfg := testConfig(t, key, path)
	cfg.CheckpointEvery = 8
	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := range 8 {
		if err := w.Append(event("PutObject", "b", "object"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	i := indexOfEntry(t, lines, 5)
	mustNotVerify(t, key, append(lines[:i:i], lines[i+1:]...),
		"removing an entry that a later checkpoint covers")
}

// TestTruncationPastTheLastCheckpoint asserts the limit rather than a
// protection, and is here so that the limit cannot be quietly lost.
//
// Entries written after the last checkpoint are chained but not signed. An
// attacker holding the file can drop them, and the result is a shorter log that
// verifies perfectly -- which is exactly what ADR-016 says under "Negative" and
// what a checkpoint published elsewhere is the answer to.
func TestTruncationPastTheLastCheckpoint(t *testing.T) {
	key := testKey(t, 34)
	path := filepath.Join(t.TempDir(), "audit.log")

	cfg := testConfig(t, key, path)
	cfg.CheckpointEvery = 1000 // no checkpoint will be reached
	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = w.file.Close() })
	for i := range 6 {
		if err := w.Append(event("PutObject", "b", "object"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Checkpoint(); err != nil { // signs entries 1..6
		t.Fatalf("Checkpoint: %v", err)
	}
	for i := range 4 { // entries 7..10, chained but never signed
		if err := w.Append(event("GetObject", "b", "later"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	w.mu.Lock()
	if err := w.buf.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	w.mu.Unlock()

	lines := readLines(t, path)
	full, err := Verify(bytes.NewReader(join(lines)), VerifyOptions{PublicKey: testPublic(t, key)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if full.Entries != 10 || full.SignedThrough != 6 {
		t.Fatalf("the log holds %d entries signed through %d, want 10 and 6",
			full.Entries, full.SignedThrough)
	}

	// Drop everything after the checkpoint.
	cut := 0
	for i, line := range lines {
		if bytes.Contains(line, []byte(`"type":"checkpoint"`)) {
			cut = i + 1
		}
	}
	short, err := Verify(bytes.NewReader(join(lines[:cut])), VerifyOptions{
		PublicKey: testPublic(t, key),
	})
	if err != nil {
		t.Fatalf("the truncated log is expected to verify, and did not: %v", err)
	}
	if short.Entries != 6 {
		t.Fatalf("the truncated log holds %d entries, want 6", short.Entries)
	}

	// What a verifier can still say is *how much* was signed. That number, held
	// against a checkpoint recorded elsewhere, is what closes the window.
	if short.SignedThrough != 6 {
		t.Errorf("signed through %d, want 6", short.SignedThrough)
	}
	t.Log("truncation past the last checkpoint is undetectable from the file alone, " +
		"as ADR-016 states; the verifier reports SignedThrough so it can be compared " +
		"against a checkpoint held off-host")
}

// TestReRenderedJSONStillVerifies is the other side of hashing fields rather
// than bytes: a record re-serialised with different key order or spacing means
// the same thing and still verifies, so a log that passed through a JSON tool is
// not falsely accused.
func TestReRenderedJSONStillVerifies(t *testing.T) {
	key := testKey(t, 35)
	_, lines := writeLog(t, key, 4)

	i := indexOfEntry(t, lines, 1)
	var generic map[string]any
	if err := json.Unmarshal(bytes.TrimRight(lines[i], "\n"), &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// encoding/json sorts map keys, so this re-renders the line in a different
	// byte order than it was written in.
	rerendered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Equal(bytes.TrimRight(lines[i], "\n"), rerendered) {
		t.Skip("the re-rendered line is byte-identical; nothing is being tested")
	}
	lines[i] = append(rerendered, '\n')

	if _, err := Verify(bytes.NewReader(join(lines)), VerifyOptions{
		PublicKey: testPublic(t, key),
	}); err != nil {
		t.Errorf("a re-rendered but unchanged record failed to verify: %v", err)
	}
}

// TestUnknownFieldsAreRejected stops a record carrying anything a verifier does
// not hash.
func TestUnknownFieldsAreRejected(t *testing.T) {
	key := testKey(t, 36)
	_, lines := writeLog(t, key, 3)

	i := indexOfEntry(t, lines, 1)
	smuggled := bytes.Replace(bytes.TrimRight(lines[i], "\n"),
		[]byte(`{"seq"`), []byte(`{"note":"anything at all","seq"`), 1)
	lines[i] = append(smuggled, '\n')
	mustNotVerify(t, key, lines, "smuggling an unhashed field into an entry")
}

func TestVerifyWithoutAKeyChecksTheChainOnly(t *testing.T) {
	key := testKey(t, 37)
	_, lines := writeLog(t, key, 4)

	result, err := Verify(bytes.NewReader(join(lines)), VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify without a key: %v", err)
	}
	if result.SignaturesChecked {
		t.Error("SignaturesChecked is true although no key was given")
	}
	if result.SignedThrough != 0 {
		t.Errorf("SignedThrough is %d without a key, want 0", result.SignedThrough)
	}

	// The chain is still checked, which is the whole value of the keyless mode.
	i := indexOfEntry(t, lines, 1)
	lines[i] = bytes.Replace(lines[i], []byte(`"status":200`), []byte(`"status":500`), 1)
	if _, err := Verify(bytes.NewReader(join(lines)), VerifyOptions{}); err == nil {
		t.Error("an edited entry passed a keyless verification")
	}
}

// helpers -------------------------------------------------------------------

func parseHeadLine(t *testing.T, line []byte) *Head {
	t.Helper()
	var record Record
	if err := json.Unmarshal(bytes.TrimRight(line, "\n"), &record); err != nil {
		t.Fatalf("Unmarshal head: %v", err)
	}
	if record.Head == nil {
		t.Fatal("the first line is not a head record")
	}
	return record.Head
}

// prevHashOf returns the chain hash immediately before line i.
func prevHashOf(t *testing.T, lines [][]byte, i int, head *Head) string {
	t.Helper()
	prev := head.Hash
	for _, line := range lines[1:i] {
		var record Record
		if err := json.Unmarshal(bytes.TrimRight(line, "\n"), &record); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if record.Entry != nil {
			prev = record.Entry.Hash
		}
	}
	return prev
}

func marshalTest(t *testing.T, record Record) []byte {
	t.Helper()
	line, err := marshalLine(record)
	if err != nil {
		t.Fatalf("marshalLine: %v", err)
	}
	return line
}

// TestHostileValuesAreRejected covers the fields that are cast to fixed-width
// unsigned integers for the hash, where a negative value would wrap
// consistently and therefore verify.
func TestHostileValuesAreRejected(t *testing.T) {
	key := testKey(t, 38)
	cases := []struct {
		name, from, to string
	}{
		{"negative bytes", `"bytes":4096`, `"bytes":-1`},
		{"negative status", `"status":200`, `"status":-1`},
		{"absurd status", `"status":200`, `"status":100000`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, lines := writeLog(t, key, 3)
			i := indexOfEntry(t, lines, 1)
			if !bytes.Contains(lines[i], []byte(tc.from)) {
				t.Fatalf("the entry does not contain %s", tc.from)
			}
			lines[i] = bytes.Replace(lines[i], []byte(tc.from), []byte(tc.to), 1)
			mustNotVerify(t, key, lines, tc.name)
		})
	}
}
