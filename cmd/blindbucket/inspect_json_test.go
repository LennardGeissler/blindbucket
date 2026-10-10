package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/envelope"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
)

var inspectJSONFields = []string{"chunk_size_bytes", "ciphertext_bytes", "envelope_bytes", "format", "kid", "log2_chunk_size", "multipart", "part_index", "plaintext_bytes", "salt", "version"}

func jsonKind(v any) string {
	if v == nil {
		return "null"
	}
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	default:
		return "other"
	}
}

func assertKinds(t *testing.T, doc map[string]any, want map[string]string) {
	t.Helper()
	for k, w := range want {
		v, ok := doc[k]
		if !ok {
			t.Errorf("field %s is absent, want kind %s", k, w)
			continue
		}
		if got := jsonKind(v); got != w {
			t.Errorf("field %s is kind %s, want %s", k, got, w)
		}
	}
}

func rawSalt(t *testing.T, data []byte, headerStart int) string {
	t.Helper()
	return hex.EncodeToString(data[headerStart+12 : headerStart+32])
}

func withStdin(t *testing.T, data []byte) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = w.Write(data)
		_ = w.Close()
	}()
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})

	oldIsTerm := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = oldIsTerm })
}

// Every document has the same eleven keys whatever the input; a field that does not apply is null, not missing.
func TestMarshalInspectJSON(t *testing.T) {
	kid := "test-kid"
	envBytes := int64(100)
	ptBytes := int64(300)

	cases := []struct {
		name string
		doc  inspectJSON
		want map[string]string
	}{
		{
			name: "file-shaped",
			doc: inspectJSON{
				Format:          "file",
				KID:             &kid,
				EnvelopeBytes:   &envBytes,
				Version:         1,
				ChunkSizeBytes:  1024,
				Log2ChunkSize:   10,
				Multipart:       false,
				PartIndex:       0,
				Salt:            strings.Repeat("a", 40),
				CiphertextBytes: 400,
				PlaintextBytes:  &ptBytes,
			},
			want: map[string]string{
				"format": "string", "kid": "string", "envelope_bytes": "number",
				"version": "number", "chunk_size_bytes": "number", "log2_chunk_size": "number",
				"multipart": "bool", "part_index": "number", "salt": "string",
				"ciphertext_bytes": "number", "plaintext_bytes": "number",
			},
		},
		{
			name: "raw single-part",
			doc: inspectJSON{
				Format:          "segment",
				KID:             nil,
				EnvelopeBytes:   nil,
				Version:         1,
				ChunkSizeBytes:  1024,
				Log2ChunkSize:   10,
				Multipart:       false,
				PartIndex:       0,
				Salt:            strings.Repeat("a", 40),
				CiphertextBytes: 400,
				PlaintextBytes:  &ptBytes,
			},
			want: map[string]string{
				"format": "string", "kid": "null", "envelope_bytes": "null",
				"version": "number", "chunk_size_bytes": "number", "log2_chunk_size": "number",
				"multipart": "bool", "part_index": "number", "salt": "string",
				"ciphertext_bytes": "number", "plaintext_bytes": "number",
			},
		},
		{
			name: "multipart",
			doc: inspectJSON{
				Format:          "segment",
				KID:             nil,
				EnvelopeBytes:   nil,
				Version:         1,
				ChunkSizeBytes:  1024,
				Log2ChunkSize:   10,
				Multipart:       true,
				PartIndex:       7,
				Salt:            strings.Repeat("a", 40),
				CiphertextBytes: 400,
				PlaintextBytes:  nil,
			},
			want: map[string]string{
				"format": "string", "kid": "null", "envelope_bytes": "null",
				"version": "number", "chunk_size_bytes": "number", "log2_chunk_size": "number",
				"multipart": "bool", "part_index": "number", "salt": "string",
				"ciphertext_bytes": "number", "plaintext_bytes": "null",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshalInspectJSON(tc.doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.HasSuffix(string(b), "\n") {
				t.Errorf("%s: does not end in newline", tc.name)
			}
			doc := decodeFields(t, b)
			assertFields(t, doc, inspectJSONFields)
			assertKinds(t, doc, tc.want)
		})
	}

	t.Run("hostile kid", func(t *testing.T) {
		hostile := "kid\"\n<&>\u2028\xff"
		doc := inspectJSON{
			Format:          "file",
			KID:             &hostile,
			EnvelopeBytes:   &envBytes,
			Version:         1,
			ChunkSizeBytes:  1024,
			Log2ChunkSize:   10,
			Multipart:       false,
			PartIndex:       0,
			Salt:            strings.Repeat("a", 40),
			CiphertextBytes: 400,
			PlaintextBytes:  &ptBytes,
		}
		b, err := marshalInspectJSON(doc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		d := decodeFields(t, b)
		assertFields(t, d, inspectJSONFields)
	})
}

// A file adds the key id and the envelope size; the salt is read back from the raw header bytes so the test does not rely on the parser it checks.
func TestInspectJSONFile(t *testing.T) {
	path := inspectFile(t, bytes.Repeat([]byte{1}, 300_000))
	stdout, stderr, err := runCLI(t, "inspect", "--json", path)
	if err != nil {
		t.Fatalf("inspect --json failed: %v", err)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	doc := decodeFields(t, []byte(stdout))
	assertFields(t, doc, inspectJSONFields)
	assertKinds(t, doc, map[string]string{
		"format": "string", "kid": "string", "envelope_bytes": "number",
		"version": "number", "chunk_size_bytes": "number", "log2_chunk_size": "number",
		"multipart": "bool", "part_index": "number", "salt": "string",
		"ciphertext_bytes": "number", "plaintext_bytes": "number",
	})
	if doc["format"] != "file" {
		t.Errorf("format: got %v", doc["format"])
	}
	if doc["kid"] != "2026-09" {
		t.Errorf("kid: got %v", doc["kid"])
	}
	if doc["version"] != float64(1) {
		t.Errorf("version: got %v", doc["version"])
	}
	if doc["chunk_size_bytes"] != float64(1<<stream.DefaultLog2ChunkSize) {
		t.Errorf("chunk_size_bytes: got %v", doc["chunk_size_bytes"])
	}
	if doc["log2_chunk_size"] != float64(stream.DefaultLog2ChunkSize) {
		t.Errorf("log2_chunk_size: got %v", doc["log2_chunk_size"])
	}
	if doc["multipart"] != false {
		t.Errorf("multipart: got %v", doc["multipart"])
	}
	if doc["part_index"] != float64(0) {
		t.Errorf("part_index: got %v", doc["part_index"])
	}
	sealedSize, err := stream.SealedSize(300_000, stream.DefaultLog2ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if doc["ciphertext_bytes"] != float64(sealedSize) {
		t.Errorf("ciphertext_bytes: got %v", doc["ciphertext_bytes"])
	}
	if doc["plaintext_bytes"] != float64(300_000) {
		t.Errorf("plaintext_bytes: got %v", doc["plaintext_bytes"])
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	envSize := int(doc["envelope_bytes"].(float64))
	if envSize+int(sealedSize) != len(b) {
		t.Errorf("total size mismatch")
	}
	if doc["salt"] != rawSalt(t, b, envSize) {
		t.Errorf("salt mismatch")
	}
	if len(doc["salt"].(string)) != 40 {
		t.Errorf("salt len: got %d", len(doc["salt"].(string)))
	}
}

// A raw segment has no envelope, so kid and envelope_bytes are present and null; a non-default chunk size proves that value is not hard-coded.
func TestInspectJSONSinglePartSegment(t *testing.T) {
	path := segmentFile(t, stream.SegmentParams{Log2ChunkSize: 13}, bytes.Repeat([]byte{2}, 100))
	stdout, stderr, err := runCLI(t, "inspect", "--json", path)
	if err != nil {
		t.Fatalf("inspect --json failed: %v", err)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	doc := decodeFields(t, []byte(stdout))
	assertFields(t, doc, inspectJSONFields)
	assertKinds(t, doc, map[string]string{
		"format": "string", "kid": "null", "envelope_bytes": "null",
		"version": "number", "chunk_size_bytes": "number", "log2_chunk_size": "number",
		"multipart": "bool", "part_index": "number", "salt": "string",
		"ciphertext_bytes": "number", "plaintext_bytes": "number",
	})
	if doc["format"] != "segment" {
		t.Errorf("format = %v", doc["format"])
	}
	if doc["chunk_size_bytes"] != float64(8192) {
		t.Errorf("chunk_size_bytes = %v", doc["chunk_size_bytes"])
	}
	if doc["log2_chunk_size"] != float64(13) {
		t.Errorf("log2_chunk_size = %v", doc["log2_chunk_size"])
	}
	if doc["multipart"] != false {
		t.Errorf("multipart = %v", doc["multipart"])
	}
	if doc["part_index"] != float64(0) {
		t.Errorf("part_index = %v", doc["part_index"])
	}
	if doc["plaintext_bytes"] != float64(100) {
		t.Errorf("plaintext_bytes = %v", doc["plaintext_bytes"])
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc["ciphertext_bytes"] != float64(len(b)) {
		t.Errorf("ciphertext_bytes = %v", doc["ciphertext_bytes"])
	}
	if doc["salt"] != rawSalt(t, b, 0) {
		t.Errorf("salt = %v", doc["salt"])
	}
}

// A part's length cannot be read as one segment, so plaintext_bytes is null while the part index is reported as stored.
func TestInspectJSONMultipartSegment(t *testing.T) {
	path := segmentFile(t, stream.SegmentParams{Log2ChunkSize: 12, Multipart: true, Index: 7}, bytes.Repeat([]byte{3}, 100))
	stdout, stderr, err := runCLI(t, "inspect", "--json", path)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	doc := decodeFields(t, []byte(stdout))
	assertFields(t, doc, inspectJSONFields)
	assertKinds(t, doc, map[string]string{
		"format": "string", "kid": "null", "envelope_bytes": "null",
		"version": "number", "chunk_size_bytes": "number", "log2_chunk_size": "number",
		"multipart": "bool", "part_index": "number", "salt": "string",
		"ciphertext_bytes": "number", "plaintext_bytes": "null",
	})
	if doc["multipart"] != true {
		t.Errorf("multipart = %v", doc["multipart"])
	}
	if doc["part_index"] != float64(7) {
		t.Errorf("part_index = %v", doc["part_index"])
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc["ciphertext_bytes"] != float64(len(b)) {
		t.Errorf("ciphertext_bytes = %v", doc["ciphertext_bytes"])
	}
	if doc["salt"] != rawSalt(t, b, 0) {
		t.Errorf("salt = %v", doc["salt"])
	}
}

// An empty single-part object is the one input whose plaintext size is 0; null means "not derived" and never competes with it.
func TestInspectJSONEmptySinglePartIsZeroNotNull(t *testing.T) {
	path := segmentFile(t, stream.SegmentParams{Log2ChunkSize: 12}, nil)
	stdout, _, err := runCLI(t, "inspect", "--json", path)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	doc := decodeFields(t, []byte(stdout))
	assertFields(t, doc, inspectJSONFields)
	if jsonKind(doc["plaintext_bytes"]) != "number" || doc["plaintext_bytes"] != float64(0) {
		t.Errorf("plaintext_bytes = %v (kind %s)", doc["plaintext_bytes"], jsonKind(doc["plaintext_bytes"]))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc["ciphertext_bytes"] != float64(len(b)) {
		t.Errorf("ciphertext_bytes = %v", doc["ciphertext_bytes"])
	}
}

// The same bytes must give the same document whether they arrive as a path or on a pipe.
func TestInspectJSONFromStdinMatchesPath(t *testing.T) {
	path := segmentFile(t, stream.SegmentParams{Log2ChunkSize: 12}, bytes.Repeat([]byte{4}, 100))
	stdoutPath, stderrPath, err := runCLI(t, "inspect", "--json", path)
	if err != nil {
		t.Fatalf("run path failed: %v", err)
	}
	if stderrPath != "" {
		t.Errorf("path stderr not empty: %s", stderrPath)
	}
	docPath := decodeFields(t, []byte(stdoutPath))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	withStdin(t, b)
	stdoutStdin, stderrStdin, err := runCLI(t, "inspect", "--json", "-")
	if err != nil {
		t.Fatalf("run stdin failed: %v", err)
	}
	if stderrStdin != "" {
		t.Errorf("stdin stderr not empty: %s", stderrStdin)
	}
	docStdin := decodeFields(t, []byte(stdoutStdin))

	if !reflect.DeepEqual(docPath, docStdin) {
		t.Errorf("path vs stdin mismatch: %v vs %v", docPath, docStdin)
	}
}

// A consumer that reads only stdout must not be able to mistake a refusal for a result: every refusal leaves stdout empty and says the same thing as the table path.
func TestInspectJSONRefusalsPrintNothing(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) string
		wants string
	}{
		{
			name: "impossible length 1 byte",
			build: func(t *testing.T) string {
				b := writeSegment(t, stream.SegmentParams{Log2ChunkSize: stream.MinLog2ChunkSize}, bytes.Repeat([]byte{1}, 1<<stream.MinLog2ChunkSize))
				b = append(b, 0)
				path := filepath.Join(t.TempDir(), "impossible1.bb")
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "no plaintext length corresponds to",
		},
		{
			name: "impossible length tag",
			build: func(t *testing.T) string {
				b := writeSegment(t, stream.SegmentParams{Log2ChunkSize: stream.MinLog2ChunkSize}, bytes.Repeat([]byte{1}, 1<<stream.MinLog2ChunkSize))
				b = append(b, make([]byte, stream.TagSize)...)
				path := filepath.Join(t.TempDir(), "impossible2.bb")
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "no plaintext length corresponds to",
		},
		{
			name: "bad magic",
			build: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "badmagic.bb")
				if err := os.WriteFile(path, append([]byte("NOPE"), make([]byte, 40)...), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "want BBF1 for a file or BLBK for a segment",
		},
		{
			name: "manifest BBM1",
			build: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "manifest1.bb")
				if err := os.WriteFile(path, append(manifest.MagicV1[:], make([]byte, 300)...), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "multipart manifest",
		},
		{
			name: "manifest BBM2",
			build: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "manifest2.bb")
				if err := os.WriteFile(path, append(manifest.Magic[:], make([]byte, 300)...), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "multipart manifest",
		},
		{
			name: "input shorter than a magic",
			build: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "short.bb")
				if err := os.WriteFile(path, []byte{1, 2}, 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "too few to hold a format marker",
		},
		{
			name: "truncated segment header",
			build: func(t *testing.T) string {
				b := writeSegment(t, stream.SegmentParams{Log2ChunkSize: stream.DefaultLog2ChunkSize}, nil)
				path := filepath.Join(t.TempDir(), "trunc.bb")
				if err := os.WriteFile(path, b[:20], 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wants: "fewer than the segment header's",
		},
		{
			name: "a file whose segment claims to be a part",
			build: func(t *testing.T) string {
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

				path := filepath.Join(t.TempDir(), "lying.bb")
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				return path
			},
			wants: "single-part with index 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.build(t)
			stdoutJ, _, errJ := runCLI(t, "inspect", "--json", path)
			if errJ == nil {
				t.Fatalf("expected error for --json")
			}
			if errors.Is(errJ, errUsage) {
				t.Fatalf("expected non-usage error for --json")
			}
			if stdoutJ != "" {
				t.Errorf("--json stdout not empty: %q", stdoutJ)
			}
			if !strings.Contains(errJ.Error(), tc.wants) {
				t.Errorf("--json error %q does not contain %q", errJ.Error(), tc.wants)
			}

			stdoutT, _, errT := runCLI(t, "inspect", path)
			if errT == nil {
				t.Fatalf("expected error for table")
			}
			if errJ.Error() != errT.Error() {
				t.Errorf("error mismatch: json=%q, table=%q", errJ.Error(), errT.Error())
			}

			if strings.HasPrefix(tc.name, "impossible length") {
				if stdoutT == "" || !strings.Contains(stdoutT, "format") {
					t.Errorf("table stdout does not contain format fields: %q", stdoutT)
				}

				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}

				withStdin(t, b)
				stdoutS, _, errS := runCLI(t, "inspect", "--json", "-")
				if errS == nil {
					t.Fatalf("stdin expected error for --json")
				}
				if stdoutS != "" {
					t.Errorf("stdin --json stdout not empty: %q", stdoutS)
				}
			}
		})
	}
}

// A wrong argument count is a usage failure and reports nothing on stdout.
func TestInspectJSONUsageErrors(t *testing.T) {
	stdout, _, err := runCLI(t, "inspect", "--json", "a", "b")
	if !errors.Is(err, errUsage) {
		t.Errorf("err = %v, want errUsage", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

// without --json the output is the table it always was.
func TestInspectTableUnchangedWithoutJSONFlag(t *testing.T) {
	path := inspectFile(t, bytes.Repeat([]byte{1}, 300_000))
	stdout, _, err := runCLI(t, "inspect", path)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Errorf("printed JSON")
	}
	if got := line(t, stdout, "format"); got != "file (BBF1)" {
		t.Errorf("format = %q, want file (BBF1)", got)
	}
	if got := line(t, stdout, "plaintext"); got != "300000 bytes (derived)" {
		t.Errorf("plaintext = %q", got)
	}
	saltLine := line(t, stdout, "salt")
	if saltLine == "" || len(saltLine) == 40 {
		t.Errorf("salt line looks wrong: %q", saltLine)
	}
}

// The stability rule and the null semantics are in -h, which is where a script author looks.
func TestInspectHelpMentionsJSON(t *testing.T) {
	stdout, stderr, err := runCLI(t, "inspect", "-h")
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	out := stderr
	if out == "" {
		out = stdout
	}
	out = strings.Join(strings.Fields(out), " ")
	if !strings.Contains(out, "--json") {
		t.Errorf("help missing --json: %s", out)
	}
	if !strings.Contains(out, "null") {
		t.Errorf("help missing null explanation: %s", out)
	}
	if !strings.Contains(out, "prints nothing to stdout") {
		t.Errorf("help missing 'prints nothing to stdout': %s", out)
	}
}

// The exact bytes are the interface: a renamed, reordered or retyped field changes these strings, and ADR-021 says that is a breaking change.
func TestMarshalInspectJSONExactDocument(t *testing.T) {
	salt := strings.Repeat("a", 40)
	kid, env, plain := "test-kid", int64(100), int64(300)
	for _, tc := range []struct {
		name string
		doc  inspectJSON
		want string
	}{
		{
			"file",
			inspectJSON{Format: "file", KID: &kid, EnvelopeBytes: &env, Version: 1,
				ChunkSizeBytes: 1024, Log2ChunkSize: 10, Salt: salt, CiphertextBytes: 400,
				PlaintextBytes: &plain},
			`{"format":"file","kid":"test-kid","envelope_bytes":100,"version":1,` +
				`"chunk_size_bytes":1024,"log2_chunk_size":10,"multipart":false,"part_index":0,` +
				`"salt":"` + salt + `","ciphertext_bytes":400,"plaintext_bytes":300}` + "\n",
		},
		{
			"part",
			inspectJSON{Format: "segment", Version: 1, ChunkSizeBytes: 1024, Log2ChunkSize: 10,
				Multipart: true, PartIndex: 7, Salt: salt, CiphertextBytes: 400},
			`{"format":"segment","kid":null,"envelope_bytes":null,"version":1,` +
				`"chunk_size_bytes":1024,"log2_chunk_size":10,"multipart":true,"part_index":7,` +
				`"salt":"` + salt + `","ciphertext_bytes":400,"plaintext_bytes":null}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := marshalInspectJSON(tc.doc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("%s: the document changed\n got: %s\nwant: %s", tc.name, got, tc.want)
			}
		})
	}
}
