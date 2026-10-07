package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/envelope"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

// The header offsets of docs/FORMAT.md section 4.1, spelled out here rather than
// taken from the package: a test that pokes a hostile header through the offsets
// the parser itself uses would only prove that the two agree, which is not the
// thing section 5.2's rules need to be checked against.
const (
	offVersion  = 4
	offLog2C    = 5
	offFlags    = 6
	offReserved = 7
	offIndex    = 8
)

// inspectFile writes a payload through the CLI's own encrypt, so what the tests
// read is what a user would have on disk rather than what a test authored.
func inspectFile(t *testing.T, plain []byte) string {
	t.Helper()
	keyring := setupKeyring(t, "2026-09")
	dir := t.TempDir()

	in := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(in, plain, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	path := filepath.Join(dir, "cipher.bb")
	if _, _, err := runCLI(t, "encrypt", "--keyring", keyring, "-i", in, "-o", path); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return path
}

// writeSegment seals a raw segment, which is what the proxy stores per part and
// what a file exposes once its envelope is stripped.
func writeSegment(t *testing.T, params stream.SegmentParams, plain []byte) []byte {
	t.Helper()
	dek := make([]byte, stream.KeySize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var out bytes.Buffer
	w, err := stream.NewEncryptWriter(&out, dek, params)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.Bytes()
}

// segmentFile writes a raw segment where the CLI can reach it.
func segmentFile(t *testing.T, params stream.SegmentParams, plain []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "segment.bin")
	if err := os.WriteFile(path, writeSegment(t, params, plain), 0o600); err != nil {
		t.Fatalf("write segment: %v", err)
	}
	return path
}

// line returns the value of one label from inspect's output, so that an assertion
// about a field does not depend on where that field sits in the listing.
func line(t *testing.T, output, label string) string {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSpace(output), "\n") {
		if rest, ok := strings.CutPrefix(l, label); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("inspect printed no %q line:\n%s", label, output)
	return ""
}

func TestInspectReportsAFileWrittenByEncrypt(t *testing.T) {
	plain := bytes.Repeat([]byte{0xa5}, 300_000) // five chunks at the default size
	path := inspectFile(t, plain)

	stdout, stderr, err := runCLI(t, "inspect", path)
	if err != nil {
		t.Fatalf("inspect: %v (stderr %q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("a diagnostic that succeeded wrote to stderr: %q", stderr)
	}

	sealed, err := stream.SealedSize(int64(len(plain)), stream.DefaultLog2ChunkSize)
	if err != nil {
		t.Fatalf("SealedSize: %v", err)
	}

	for _, want := range []struct{ label, value string }{
		{"format", "file (BBF1)"},
		{"key id", "2026-09"},
		{"magic", "BLBK"},
		{"version", "1"},
		{"chunk size", fmt.Sprintf("%d (log2 = %d)", 1<<stream.DefaultLog2ChunkSize, stream.DefaultLog2ChunkSize)},
		{"multipart", "no"},
		{"part index", "0"},
		{"ciphertext", fmt.Sprintf("%d bytes", sealed)},
		{"plaintext", fmt.Sprintf("%d bytes (derived)", len(plain))},
	} {
		if got := line(t, stdout, want.label); got != want.value {
			t.Errorf("%s = %q, want %q", want.label, got, want.value)
		}
	}

	// The envelope is the only part of the file that is not the segment, and both
	// sizes are reported, so their sum has to be the length on disk. That is the
	// check which keeps `ciphertext` from quietly meaning two different things on
	// the two input formats.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var envelopeBytes int64
	if _, err := fmt.Sscanf(line(t, stdout, "envelope"), "%d bytes", &envelopeBytes); err != nil {
		t.Fatalf("envelope line is not a byte count: %v", err)
	}
	if got := envelopeBytes + sealed; got != int64(len(data)) {
		t.Errorf("envelope %d + segment %d = %d, but the file holds %d",
			envelopeBytes, sealed, got, len(data))
	}
}

// A plaintext that is an exact multiple of the chunk size is the boundary the
// format's own history says a decoder gets wrong (docs/FORMAT.md section 5.2), so
// the derived size is checked either side of it rather than only in the middle.
func TestInspectDerivesSizesAcrossTheChunkBoundary(t *testing.T) {
	c := 1 << stream.MinLog2ChunkSize
	for _, size := range []int{0, 1, c - 1, c, c + 1, 2 * c, 3*c - 1} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			path := segmentFile(t,
				stream.SegmentParams{Log2ChunkSize: stream.MinLog2ChunkSize},
				bytes.Repeat([]byte{0x5a}, size))
			stdout, stderr, err := runCLI(t, "inspect", path)
			if err != nil {
				t.Fatalf("inspect: %v (stderr %q)", err, stderr)
			}
			if got := line(t, stdout, "plaintext"); got != fmt.Sprintf("%d bytes (derived)", size) {
				t.Errorf("plaintext = %q, want %d bytes (derived)", got, size)
			}
		})
	}
}

// A part is identified by its index, and nothing about a multipart segment needs
// a key to say which part it is: this is the listing that answers "which part of
// the object did the provider give me back".
func TestInspectReportsAMultipartSegment(t *testing.T) {
	const part = 7
	path := segmentFile(t, stream.SegmentParams{
		Log2ChunkSize: stream.DefaultLog2ChunkSize,
		Multipart:     true,
		Index:         part,
	}, bytes.Repeat([]byte{0x11}, 100_000))

	stdout, stderr, err := runCLI(t, "inspect", path)
	if err != nil {
		t.Fatalf("inspect: %v (stderr %q)", err, stderr)
	}
	if got := line(t, stdout, "format"); got != "segment (BLBK)" {
		t.Errorf("format = %q, want segment (BLBK)", got)
	}
	if got := line(t, stdout, "multipart"); got != "yes" {
		t.Errorf("multipart = %q, want yes", got)
	}
	if got := line(t, stdout, "part index"); got != fmt.Sprintf("%d", part) {
		t.Errorf("part index = %q, want %d", got, part)
	}
	if strings.Contains(stdout, "key id") {
		t.Errorf("a raw segment carries no envelope, so it cannot name a key:\n%s", stdout)
	}
	// A part is one segment of an object whose other segments may follow it in the
	// same bytes, so the length says nothing about this part and the size is left
	// unsaid rather than guessed at.
	if got := line(t, stdout, "plaintext"); got != "not derived" {
		t.Errorf("plaintext = %q, want not derived", got)
	}
	if !strings.Contains(stdout, "manifest") {
		t.Errorf("the report should say where the part count lives:\n%s", stdout)
	}
}

// Two parts of one object, concatenated the way the provider stores them, are the
// input that makes the refusal above load-bearing: the arithmetic accepts the
// length and returns a confident number 16 bytes too high. Without the multipart
// guard this test prints 8208 and passes nothing.
func TestInspectDoesNotDeriveASizeFromConcatenatedParts(t *testing.T) {
	const (
		log2C    = stream.MinLog2ChunkSize
		partSize = 1 << log2C
		parts    = 2
	)
	dek := make([]byte, stream.KeySize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var object bytes.Buffer
	for part := 1; part <= parts; part++ {
		segment := writeSegment(t,
			stream.SegmentParams{Log2ChunkSize: log2C, Multipart: true, Index: uint32(part)},
			bytes.Repeat([]byte{0x2b}, partSize))
		object.Write(segment)
	}

	path := filepath.Join(t.TempDir(), "object.bin")
	if err := os.WriteFile(path, object.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stdout, _, err := runCLI(t, "inspect", path)
	if err != nil {
		t.Fatalf("a whole object is a legitimate thing to inspect: %v", err)
	}
	if got := line(t, stdout, "plaintext"); got != "not derived" {
		t.Errorf("plaintext = %q, want not derived", got)
	}
	// The one number that is a fact about the input survives.
	if got := line(t, stdout, "ciphertext"); got != fmt.Sprintf("%d bytes", object.Len()) {
		t.Errorf("ciphertext = %q, want the %d bytes the input holds", got, object.Len())
	}
	if strings.Contains(stdout, fmt.Sprintf("%d bytes (derived)", parts*partSize)) {
		t.Errorf("the object's true size should not be arrived at by accident:\n%s", stdout)
	}
}

// Every rule of docs/FORMAT.md section 5.2 exists because the header is
// attacker-controlled and not yet authenticated. Each case must be refused, and
// must be refused by name: an operator comparing two files cannot act on
// "integrity failure".
func TestInspectRefusesEveryHeaderRuleSectionFivePointTwoStates(t *testing.T) {
	params := stream.SegmentParams{
		Log2ChunkSize: stream.DefaultLog2ChunkSize,
		Multipart:     true,
		Index:         3,
	}
	plain := bytes.Repeat([]byte{0x7f}, 1000)

	cases := []struct {
		name  string
		set   func(b []byte)
		wants string
	}{
		{
			name:  "a magic that is neither format",
			set:   func(b []byte) { copy(b, []byte("XXXX")) },
			wants: "want BBF1 for a file or BLBK for a segment",
		},
		{
			name:  "a version this build does not know",
			set:   func(b []byte) { b[offVersion] = 2 },
			wants: "unsupported format version 2",
		},
		{
			name:  "a chunk size above the permitted range",
			set:   func(b []byte) { b[offLog2C] = 30 },
			wants: "outside 12..20",
		},
		{
			name:  "a chunk size below the permitted range",
			set:   func(b []byte) { b[offLog2C] = 11 },
			wants: "outside 12..20",
		},
		{
			name:  "a reserved byte that is not zero",
			set:   func(b []byte) { b[offReserved] = 0x01 },
			wants: "reserved byte is 0x01",
		},
		{
			name:  "an undefined flag bit",
			set:   func(b []byte) { b[offFlags] |= 0x02 },
			wants: "undefined flag bits set: 0x03",
		},
		{
			// The consistency constraints of section 4.1: these are headers that
			// parse into nothing, which is why the decoder is not allowed to like them.
			name: "a single-part segment carrying a part number",
			set: func(b []byte) {
				b[offFlags] = 0
				b[offIndex+3] = 4
			},
			wants: "single-part segment must have index 0",
		},
		{
			name: "a multipart segment with no part number",
			set: func(b []byte) {
				b[offFlags] = 0x01
				b[offIndex+3] = 0
			},
			wants: "multipart segment index 0 outside 1..10000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segment := writeSegment(t, params, plain)
			tc.set(segment)

			path := filepath.Join(t.TempDir(), "poked.bin")
			if err := os.WriteFile(path, segment, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			stdout, _, err := runCLI(t, "inspect", path)
			if err == nil {
				t.Fatalf("inspect accepted a header it must refuse, and printed:\n%s", stdout)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error does not name the check that failed\n got: %q\nwant it to contain: %q", err, tc.wants)
			}
		})
	}
}

// Inputs that stop before a header is the hostile case a parser written against a
// struct would panic on, and a diagnostic that panics is worse than one that says
// nothing.
func TestInspectRefusesInputsThatStopBeforeAHeader(t *testing.T) {
	fileTruncatedInsideHeader := func(t *testing.T) []byte {
		t.Helper()
		data, err := os.ReadFile(inspectFile(t, bytes.Repeat([]byte{1}, 100)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		hdr, err := envelope.DecodeHeader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("DecodeHeader: %v", err)
		}
		return data[:hdr.Size+4]
	}

	cases := []struct {
		name  string
		build func(t *testing.T) []byte
		wants string
	}{
		{
			name:  "no input at all",
			build: func(*testing.T) []byte { return nil },
			wants: "too few to hold a format marker",
		},
		{
			name:  "two bytes",
			build: func(*testing.T) []byte { return []byte{0x00, 0x01} },
			wants: "too few to hold a format marker",
		},
		{
			name: "a segment header with bytes missing",
			build: func(t *testing.T) []byte {
				return writeSegment(t,
					stream.SegmentParams{Log2ChunkSize: stream.DefaultLog2ChunkSize},
					make([]byte, 10))[:20]
			},
			wants: "fewer than the segment header's 32",
		},
		{
			name:  "a file whose segment never started",
			build: fileTruncatedInsideHeader,
			wants: "of the segment header's 32 bytes follow its envelope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.bin")
			if err := os.WriteFile(path, tc.build(t), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			stdout, _, err := runCLI(t, "inspect", path)
			if err == nil {
				t.Fatalf("inspect accepted %s, and printed:\n%s", tc.name, stdout)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error does not say what is missing\n got: %q\nwant it to contain: %q", err, tc.wants)
			}
		})
	}
}

// Section 9 of docs/FORMAT.md forbids a file's segment from being a multipart
// part, and Decrypt asks for single-part index 0, so a file whose header
// contradicts that is a file that will not open. The command exists to say so
// before anyone tries to open it.
func TestInspectRefusesAFileWhoseSegmentClaimsToBeAPart(t *testing.T) {
	data, err := os.ReadFile(inspectFile(t, bytes.Repeat([]byte{2}, 5000)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	hdr, err := envelope.DecodeHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	data[hdr.Size+offFlags] = 0x01
	data[hdr.Size+offIndex+3] = 9

	broken := filepath.Join(t.TempDir(), "lying.bb")
	if err := os.WriteFile(broken, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stdout, _, err := runCLI(t, "inspect", broken)
	if err == nil {
		t.Fatalf("a file whose segment claims to be part 9 is not a file decrypt can open:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "single-part with index 0") || !strings.Contains(err.Error(), "index=9") {
		t.Errorf("the error does not say which rule the file breaks: %q", err)
	}
}

// A manifest is the other BB-prefixed thing an operator finds in a bucket, and it
// is the input this command cannot report. Naming it is the difference between a
// dead end and a next step; "bad magic" would be a lie, since the magic is one
// this project wrote.
func TestInspectNamesAMultipartManifestRatherThanCallingItBadMagic(t *testing.T) {
	for _, magic := range [][4]byte{manifest.Magic, manifest.MagicV1} {
		t.Run(string(magic[:]), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.bin")
			head := append([]byte{}, magic[:]...)
			head = append(head, make([]byte, 300)...)
			if err := os.WriteFile(path, head, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, _, err := runCLI(t, "inspect", path)
			if err == nil {
				t.Fatal("inspect reported a manifest as if it were a segment")
			}
			if !strings.Contains(err.Error(), "multipart manifest") {
				t.Errorf("the error should name the format: %q", err)
			}
			if strings.Contains(err.Error(), "bad magic") {
				t.Errorf("the magic is valid, it is simply not this command's: %q", err)
			}
		})
	}
}

// A regular file has a length and a pipe does not, so the command measures the two
// differently. The same bytes must still produce the same report, or the
// diagnostic says two different things about one object depending on how it was
// reached.
func TestInspectReadsStdinAsCarefullyAsAFile(t *testing.T) {
	path := inspectFile(t, bytes.Repeat([]byte{0x3c}, 200_000))
	fromFile, _, err := runCLI(t, "inspect", path)
	if err != nil {
		t.Fatalf("inspect of a file: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fromPipe := inspectStdin(t, data)

	for _, label := range []string{"format", "key id", "envelope", "salt", "ciphertext", "plaintext"} {
		if got, want := line(t, fromPipe, label), line(t, fromFile, label); got != want {
			t.Errorf("%s differs between a file and the same bytes piped in: %q vs %q", label, got, want)
		}
	}
}

// inspectStdin runs the command with os.Stdin holding data, which is the only way
// to reach the counting a pipe forces.
func inspectStdin(t *testing.T, data []byte) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = w.Write(data)
		_ = w.Close()
	}()

	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; _ = r.Close() })

	var runErr error
	out := captureStdout(t, func() { runErr = run(t.Context(), []string{"inspect", "-"}) })
	if runErr != nil {
		t.Fatalf("inspect of stdin: %v", runErr)
	}
	return out
}

// Trailing bytes are the corruption a length check catches and a field check
// cannot: the header is sound, and the size says somebody appended to the
// ciphertext. The header still gets reported, because it is how the operator finds
// the object whose length is wrong.
func TestInspectRefusesACiphertextWhoseLengthNoEncoderProduces(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra int
	}{
		{"one byte appended", 1},
		{"a tag's worth appended", stream.TagSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An exact multiple of the chunk size: that is the one length whose
			// remainder says "no encoder wrote this", and the reason the sizes below
			// stay inside the forbidden band. Append more than a tag and the length
			// becomes reproducible as a different plaintext, which is what
			// TestInspectReportsOnlyWhatLengthCanKnow pins down.
			path := segmentFile(t,
				stream.SegmentParams{Log2ChunkSize: stream.MinLog2ChunkSize},
				bytes.Repeat([]byte{0x9d}, 1<<stream.MinLog2ChunkSize))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			grown := filepath.Join(t.TempDir(), "grown.bin")
			if err := os.WriteFile(grown, append(data, make([]byte, tc.extra)...), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			stdout, _, err := runCLI(t, "inspect", grown)
			if err == nil {
				t.Fatalf("inspect accepted a segment with %d bytes appended:\n%s", tc.extra, stdout)
			}
			if !strings.Contains(err.Error(), "no plaintext length corresponds to") {
				t.Errorf("the error does not say the length is the problem: %q", err)
			}
			if !strings.Contains(stdout, "salt") {
				t.Errorf("the header fields were withheld along with the size:\n%s", stdout)
			}
		})
	}
}

// Length arithmetic is not a checksum. Thirty-two bytes appended to a segment
// whose plaintext is an exact multiple of the chunk size is also a valid segment
// of a longer plaintext, and nothing in a header says which it was: only the
// authentication tags do. The command reports the size it derived and claims
// nothing beyond it, which is the limit its usage text states -- this test pins
// that the limit is the one that was written down rather than a silent wrong
// answer.
func TestInspectReportsOnlyWhatLengthCanKnow(t *testing.T) {
	const (
		log2C = stream.MinLog2ChunkSize
		plain = 1 << log2C // an exact multiple of the chunk size
	)
	path := segmentFile(t, stream.SegmentParams{Log2ChunkSize: log2C}, bytes.Repeat([]byte{0x9d}, plain))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	grown := filepath.Join(t.TempDir(), "grown.bin")
	if err := os.WriteFile(grown, append(data, make([]byte, 2*stream.TagSize)...), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, _, err := runCLI(t, "inspect", grown)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	// 2*TagSize extra bytes make it look like one more chunk of TagSize plaintext.
	wanted := plain + 2*stream.TagSize - stream.TagSize
	if got := line(t, stdout, "plaintext"); got != fmt.Sprintf("%d bytes (derived)", wanted) {
		t.Errorf("plaintext = %q, want the size a segment of that length would hold (%d)", got, wanted)
	}
}

// The limit the test above demonstrates is the limit the usage text promises, so
// this checks the promise is still made. A comment about a limitation is worth
// what a test would pay for it: drop the sentence from the usage text and this
// fails.
func TestInspectStatesTheLimitItDemonstrates(t *testing.T) {
	_, stderr, err := runCLI(t, "inspect", "-h")
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h should ask for help, got %v", err)
	}
	for _, phrase := range []string{"not proof of integrity", "what the headers claim"} {
		if !strings.Contains(stderr, phrase) {
			t.Errorf("the usage text no longer states that %s\n%s", phrase, stderr)
		}
	}
}

// One argument is the whole interface, and a second path silently ignored would
// report the first file while the operator meant the other.
func TestInspectRefusesMoreThanOneFile(t *testing.T) {
	first := inspectFile(t, []byte("first"))
	second := inspectFile(t, []byte("second and longer"))

	stdout, stderr, err := runCLI(t, "inspect", first, second)
	if !errors.Is(err, errUsage) {
		t.Fatalf("a wrong argument count is a usage failure, so it must leave as one: %v", err)
	}
	if stdout != "" {
		t.Errorf("a command line that was wrong reported a file anyway:\n%s", stdout)
	}
	if !strings.Contains(stderr, "inspect takes one file, got 2 arguments") {
		t.Errorf("the message naming the mistake was lost on the way to the usage text: %q", stderr)
	}
}

// A terminal for stdin is the case where no bytes will ever arrive for the asking,
// which is a wrong invocation rather than a failed one: it has to leave the way the
// other wrong invocations leave, with the reason printed above the usage text rather
// than in place of it. `stdinIsTerminal` exists because this cannot be reached by
// lying about stdin -- under `go test` it is a pipe, as exit_test.go notes.
func TestInspectRefusesATerminalForStdin(t *testing.T) {
	restore := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = restore })

	stdout, stderr, err := runCLI(t, "inspect")
	if !errors.Is(err, errUsage) {
		t.Fatalf("waiting for input that cannot come is a usage failure, so it must leave as one: %v", err)
	}
	if stdout != "" {
		t.Errorf("a command that read nothing reported a file anyway:\n%s", stdout)
	}
	if !strings.Contains(stderr, "no file given and stdin is a terminal") {
		t.Errorf("the message naming the mistake was lost on the way to the usage text: %q", stderr)
	}
}
