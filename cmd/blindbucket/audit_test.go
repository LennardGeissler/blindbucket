package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

// writeAuditLog writes a log the way the gateway does, signed with the audit
// key of the given keyring, and returns the paths of the files it produced,
// oldest first.
func writeAuditLog(t *testing.T, keyring string, entries, checkpointEvery int, rotateBytes int64) []string {
	t.Helper()
	ring, err := openKeyring(t.Context(), keyring, config.Keys{Provider: "file"}, &passphraseFlags{})
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	key, ok := ring.AuditKey()
	if !ok {
		t.Fatal("the keyring has no audit key")
	}
	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("name key: %v", err)
	}

	dir := t.TempDir()
	w, err := audit.Open(audit.Config{
		Path:               filepath.Join(dir, "audit.log"),
		Signer:             signer,
		NameKey:            nameKey,
		CheckpointEvery:    checkpointEvery,
		CheckpointInterval: time.Hour,
		RotateBytes:        rotateBytes,
	})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	for i := range entries {
		if err := w.Append(audit.Event{
			Op: "PutObject", Bucket: "backups", Key: "2026/09/db.sql.zst",
			Client: "backup-job", Status: 200, Bytes: int64(1000 + i),
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// The live file is the newest; archives sort before it by name.
	slices.SortFunc(paths, func(a, b string) int {
		switch {
		case filepath.Base(a) == "audit.log":
			return 1
		case filepath.Base(b) == "audit.log":
			return -1
		}
		return strings.Compare(a, b)
	})
	return paths
}

func auditPubkey(t *testing.T, keyring string, extra ...string) string {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		err = run(t.Context(), append([]string{"audit", "pubkey", "--keyring", keyring}, extra...))
	})
	if err != nil {
		t.Fatalf("audit pubkey: %v", err)
	}
	return strings.TrimSpace(out)
}

// auditVerify runs `audit verify` and returns what it printed and its error.
func auditVerify(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		err = run(t.Context(), append([]string{"audit", "verify"}, args...))
	})
	return out, err
}

var lastCheckpoint = regexp.MustCompile(`last checkpoint: (\d+:[0-9a-f]+)`)

// dropLastLine removes the final record of a log: the checkpoint Close wrote.
// What remains is chained but unsigned past the previous checkpoint, which is
// exactly what someone holding the file can produce without trace.
func dropLastLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	trimmed := bytes.TrimSuffix(data, []byte("\n"))
	cut := bytes.LastIndexByte(trimmed, '\n')
	if err := os.WriteFile(path, trimmed[:cut+1], 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestAuditPubkeyRecordedMatchesDerived(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")

	recorded := auditPubkey(t, keyring)
	derived := auditPubkey(t, keyring, "--open")
	if recorded != derived {
		t.Errorf("the recorded key %s is not the one the keyring derives, %s", recorded, derived)
	}
	raw, err := base64.StdEncoding.DecodeString(recorded)
	if err != nil || len(raw) != 32 {
		t.Errorf("pubkey printed %q, want a base64 Ed25519 key", recorded)
	}
}

func TestAuditVerifyWithThePublicKey(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 5, 2, 0)
	pub := auditPubkey(t, keyring)

	out, err := auditVerify(t, "--public-key", pub, logs[0])
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(out, "chain and signatures verified") {
		t.Errorf("no verdict in:\n%s", out)
	}
	if !strings.Contains(out, "5 entries") {
		t.Errorf("entry count missing from:\n%s", out)
	}
	// Names are encrypted in the log, and a public key cannot read them.
	if strings.Contains(out, "db.sql.zst") {
		t.Error("a verification with the public key alone printed a plaintext name")
	}

	// The key may also come from a file, which is how it is meant to be kept.
	keyFile := filepath.Join(t.TempDir(), "audit.pub")
	if err := os.WriteFile(keyFile, []byte(pub+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if out, err := auditVerify(t, "--public-key", keyFile, logs[0]); err != nil {
		t.Fatalf("verify with a key file: %v\n%s", err, out)
	}
}

func TestAuditVerifyWithTheKeyringPrintsNames(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 3, 10, 0)

	out, err := auditVerify(t, "--keyring", keyring, "--print", logs[0])
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if got := strings.Count(out, "backups/2026/09/db.sql.zst"); got != 3 {
		t.Errorf("printed %d decrypted entries, want 3:\n%s", got, out)
	}
	if !strings.Contains(out, "backup-job") || !strings.Contains(out, "1002 bytes") {
		t.Errorf("entry details missing from:\n%s", out)
	}
}

func TestAuditVerifyWithoutAKeySaysSo(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 3, 10, 0)

	out, err := auditVerify(t, logs[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Without a key the chain is checked and the signatures are not; saying
	// "verified" there would claim what was not checked.
	if !strings.Contains(out, "SIGNATURES NOT CHECKED") || strings.Contains(out, "signatures verified") {
		t.Errorf("an unkeyed verification did not say what it skipped:\n%s", out)
	}
}

func TestAuditVerifyRefusesAnEditedLog(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 5, 2, 0)
	pub := auditPubkey(t, keyring)

	data, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Rewrite what one request moved. The line stays well-formed JSON; only
	// the chain can tell.
	edited := bytes.Replace(data, []byte(`"bytes":1001`), []byte(`"bytes":9001`), 1)
	if bytes.Equal(edited, data) {
		t.Fatal("the test did not find the field it edits")
	}
	if err := os.WriteFile(logs[0], edited, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for name, args := range map[string][]string{
		"with the public key": {"--public-key", pub, logs[0]},
		"without a key":       {logs[0]},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := auditVerify(t, args...)
			if err == nil {
				t.Fatalf("an edited log verified:\n%s", out)
			}
			if !strings.Contains(out, "NOT VERIFIED") || strings.Contains(out, "chain and signatures verified") {
				t.Errorf("the verdict does not say the log failed:\n%s", out)
			}
		})
	}
}

func TestAuditVerifyRefusesAnotherKeyringsKey(t *testing.T) {
	logs := writeAuditLog(t, setupKeyring(t, "ours"), 3, 1, 0)
	theirs := auditPubkey(t, setupKeyring(t, "theirs"))

	if out, err := auditVerify(t, "--public-key", theirs, logs[0]); err == nil {
		t.Fatalf("a log verified against a key that did not sign it:\n%s", out)
	}
}

func TestAuditVerifyReportsAnUnsignedTail(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	pub := auditPubkey(t, keyring)

	t.Run("entries past the last checkpoint", func(t *testing.T) {
		logs := writeAuditLog(t, keyring, 5, 3, 0)
		dropLastLine(t, logs[0])

		out, err := auditVerify(t, "--public-key", pub, logs[0])
		if err != nil {
			t.Fatalf("verify: %v\n%s", err, out)
		}
		if !strings.Contains(out, "2 entries past the last checkpoint are chained but not signed") {
			t.Errorf("the unsigned tail was not reported:\n%s", out)
		}
	})

	t.Run("no checkpoint at all", func(t *testing.T) {
		logs := writeAuditLog(t, keyring, 3, 0, 0)
		dropLastLine(t, logs[0])

		out, err := auditVerify(t, "--public-key", pub, logs[0])
		if err != nil {
			t.Fatalf("verify: %v\n%s", err, out)
		}
		if !strings.Contains(out, "NOTHING IS SIGNED") || strings.Contains(out, "signatures verified") {
			t.Errorf("a log without a checkpoint was reported as signed:\n%s", out)
		}
	})
}

// TestAuditVerifyExpectClosesTheTruncationWindow is ADR-016's answer to the
// unsigned tail: a checkpoint recorded elsewhere, which a shortened file can no
// longer reach.
func TestAuditVerifyExpectClosesTheTruncationWindow(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	pub := auditPubkey(t, keyring)
	logs := writeAuditLog(t, keyring, 5, 3, 0)

	out, err := auditVerify(t, "--public-key", pub, logs[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	m := lastCheckpoint.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no checkpoint in:\n%s", out)
	}
	recorded := m[1]

	if out, err := auditVerify(t, "--public-key", pub, "--expect", recorded, logs[0]); err != nil ||
		!strings.Contains(out, "matches the checkpoint recorded elsewhere") {
		t.Fatalf("the log did not match its own checkpoint: %v\n%s", err, out)
	}

	seq, _, _ := strings.Cut(recorded, ":")
	wrongHash := seq + ":" + strings.Repeat("0", 64)
	if _, err := auditVerify(t, "--public-key", pub, "--expect", wrongHash, logs[0]); err == nil ||
		!strings.Contains(err.Error(), "not the same log") {
		t.Errorf("a different checkpoint at the same entry was accepted: %v", err)
	}

	// The attack: remove the final checkpoint and the entries it signed. The
	// rest verifies on its own; only the recorded checkpoint gives it away.
	dropLastLine(t, logs[0])
	if _, err := auditVerify(t, "--public-key", pub, logs[0]); err != nil {
		t.Fatalf("the shortened log should verify on its own: %v", err)
	}
	if _, err := auditVerify(t, "--public-key", pub, "--expect", recorded, logs[0]); err == nil ||
		!strings.Contains(err.Error(), "entries have been removed from the end") {
		t.Errorf("a truncated log passed --expect: %v", err)
	}

	// Comparing against unverified checkpoints would mean nothing.
	if _, err := auditVerify(t, "--expect", recorded, logs[0]); err == nil {
		t.Error("--expect was accepted without a key")
	}
}

func TestAuditVerifyOrdersRotatedFilesByTheirHeads(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	pub := auditPubkey(t, keyring)
	logs := writeAuditLog(t, keyring, 40, 4, 2048)
	if len(logs) < 3 {
		t.Fatalf("expected the log to rotate at least twice, got %d files", len(logs))
	}

	// Given newest first, as a shell glob might; the heads decide the order.
	reversed := slices.Clone(logs)
	slices.Reverse(reversed)
	out, err := auditVerify(t, append([]string{"--public-key", pub}, reversed...)...)
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if !strings.Contains(out, "chain and signatures verified") {
		t.Errorf("no verdict in:\n%s", out)
	}

	t.Run("a gap in the chain", func(t *testing.T) {
		// Leaving out a middle file leaves two files that continue nothing given.
		gapped := []string{logs[0], logs[len(logs)-1]}
		if _, err := auditVerify(t, append([]string{"--public-key", pub}, gapped...)...); err == nil ||
			!strings.Contains(err.Error(), "do not form one chain") {
			t.Errorf("files with a gap between them were accepted: %v", err)
		}
	})

	t.Run("one file twice", func(t *testing.T) {
		if _, err := auditVerify(t, "--public-key", pub, logs[0], logs[0]); err == nil ||
			!strings.Contains(err.Error(), "are both chain") {
			t.Errorf("the same file given twice was accepted: %v", err)
		}
	})
}

func TestAuditCommandLineMistakes(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 1, 1, 0)
	pub := auditPubkey(t, keyring)
	short := base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no subcommand":           {[]string{"audit"}, ""},
		"help":                    {[]string{"audit", "help"}, ""},
		"unknown subcommand":      {[]string{"audit", "frobnicate"}, "unknown audit subcommand"},
		"pubkey without keyring":  {[]string{"audit", "pubkey"}, "--keyring is required"},
		"verify without a log":    {[]string{"audit", "verify", "--public-key", pub}, "name at least one log file"},
		"both key sources":        {[]string{"audit", "verify", "--public-key", pub, "--keyring", keyring, logs[0]}, "not both"},
		"key is not base64":       {[]string{"audit", "verify", "--public-key", "not/base64!", logs[0]}, "neither valid base64"},
		"key of the wrong length": {[]string{"audit", "verify", "--public-key", short, logs[0]}, "want 32"},
		"expect without a colon":  {[]string{"audit", "verify", "--public-key", pub, "--expect", "7", logs[0]}, "<seq>:<hash>"},
		"expect with a bad seq":   {[]string{"audit", "verify", "--public-key", pub, "--expect", "x:ab", logs[0]}, "not a sequence number"},
		"a log that is missing":   {[]string{"audit", "verify", "--public-key", pub, filepath.Join(t.TempDir(), "gone")}, "no such file"},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			captureStderr(t, func() {
				captureStdout(t, func() { err = run(t.Context(), tc.args) })
			})
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want == "" {
				if !errors.Is(err, errUsage) {
					t.Errorf("got %v, want the usage error", err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A bucket recorded as a digest, for a name too long to encrypt, leaves the
// object key encrypted, and the key that opens it is tried on its own.
func TestDecodeNamesWithADigestedBucket(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	coder, err := names.New(key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := names.New(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := coder.EncryptKey("secret/key.txt")
	if err != nil {
		t.Fatal(err)
	}
	bucket, got := decodeNames([]*names.Encrypter{other, coder}, "h:0123abcd", encKey)
	if bucket != "h:0123abcd" || got != "secret/key.txt" {
		t.Errorf("decodeNames = %q, %q", bucket, got)
	}
}
