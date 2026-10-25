package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cryptRoundTrip encrypts and decrypts a small body through the CLI with the
// given extra flags, and returns what came back.
func cryptRoundTrip(t *testing.T, keyring string, extra ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	sealed := filepath.Join(dir, "sealed.bb")
	opened := filepath.Join(dir, "opened")
	body := []byte("round trip\n")
	if err := os.WriteFile(plain, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	args := func(command, in, out string) []string {
		return append(append([]string{command, "--keyring", keyring}, extra...), "-i", in, "-o", out)
	}
	if _, stderr, err := runCLI(t, args("encrypt", plain, sealed)...); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, stderr)
	}
	if _, stderr, err := runCLI(t, args("decrypt", sealed, opened)...); err != nil {
		t.Fatalf("decrypt: %v\n%s", err, stderr)
	}
	got, err := os.ReadFile(opened)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("decrypted %q, want %q", got, body)
	}
	return got
}

// TestCryptPassphrasePathIsUnchanged: #46 routed these two commands through
// openKeyring so a service-sealed keyring can be used with them. The passphrase
// path stays the default and must behave as it did -- no --config, no
// configuration file anywhere, same prompt and same sources.
func TestCryptPassphrasePathIsUnchanged(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	cryptRoundTrip(t, keyring)
}

// TestCryptConfigNamingTheFileProviderWorks: a passphrase keyring with a
// configuration that names no service is the same case as no configuration at
// all, and must not become an error.
func TestCryptConfigNamingTheFileProviderWorks(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	conf := filepath.Join(t.TempDir(), "blindbucket.yaml")
	body := `
upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }
clients: [{ name: c, access_key_id: k, secret_access_key: s, buckets: ["*"] }]
keys:
  provider: file
  keyring: ` + keyring + `
`
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cryptRoundTrip(t, keyring, "--config", conf)
}

// TestCryptRefusesAConfigThatDisagreesWithTheKeyring: openKeyring's rule now
// covers these commands too. A passphrase keyring with keys.provider: vault is
// a contradiction, and prompting for a passphrase anyway would ask the operator
// for something that cannot be the answer.
func TestCryptRefusesAConfigThatDisagreesWithTheKeyring(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	conf := filepath.Join(t.TempDir(), "blindbucket.yaml")
	body := `
upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }
clients: [{ name: c, access_key_id: k, secret_access_key: s, buckets: ["*"] }]
keys:
  provider: vault
  keyring: ` + keyring + `
  vault: { address: "http://127.0.0.1:1", token: t, key_name: blindbucket }
`
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, command := range []string{"encrypt", "decrypt"} {
		_, _, err := runCLI(t, command, "--keyring", keyring, "--config", conf,
			"-i", plain, "-o", filepath.Join(dir, command+".out"))
		if err == nil {
			t.Fatalf("%s accepted a configuration that disagrees with the keyring", command)
		}
		if !strings.Contains(err.Error(), "sealed with a passphrase") {
			t.Errorf("%s: the error does not name the disagreement: %v", command, err)
		}
	}
}

// TestCryptWarnsOnceAboutAnExposedKeyring: loadKeyring used to call
// warnIfExposed itself, and openKeyringFile calls it too. Going through
// openKeyring without dropping the first call would have warned twice about the
// same file, which is the kind of thing nobody notices in review.
func TestCryptWarnsOnceAboutAnExposedKeyring(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not carry the group and other bits this checks")
	}
	keyring := setupKeyring(t, "2026-09")
	if err := os.Chmod(keyring, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, stderr, err := runCLI(t, "encrypt", "--keyring", keyring,
		"-i", plain, "-o", filepath.Join(dir, "out.bb"))
	if err != nil {
		t.Fatalf("encrypt: %v\n%s", err, stderr)
	}
	if got := strings.Count(stderr, "readable beyond its owner"); got != 1 {
		t.Errorf("warned %d times about the keyring's mode, want once:\n%s", got, stderr)
	}
}
