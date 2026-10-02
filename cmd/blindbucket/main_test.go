package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

const testPassphrase = "a test passphrase, not a secret"

// setupKeyring creates a keyring through the CLI itself, so the test exercises
// the same path a user would.
func setupKeyring(t *testing.T, kid string) string {
	t.Helper()
	t.Setenv(passphraseEnv, testPassphrase)

	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := run(t.Context(), []string{"keygen", "--out", path, "--kid", kid}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return path
}

func TestCLIRoundTrip(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	dir := t.TempDir()

	plain := make([]byte, 300_000) // several chunks at the default size
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	plainPath := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cipherPath := filepath.Join(dir, "cipher.bb")
	if err := run(t.Context(), []string{"encrypt", "--keyring", keyring, "-i", plainPath, "-o", cipherPath}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cipher, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if bytes.Contains(cipher, plain[:64]) {
		t.Error("plaintext appears in the ciphertext")
	}
	if !bytes.HasPrefix(cipher, []byte("BBF1")) {
		t.Errorf("ciphertext does not start with the file magic: %x", cipher[:8])
	}

	backPath := filepath.Join(dir, "back.bin")
	if err := run(t.Context(), []string{"decrypt", "--keyring", keyring, "-i", cipherPath, "-o", backPath}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	back, err := os.ReadFile(backPath)
	if err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Error("plaintext differs after a CLI round trip")
	}
}

// TestKeygenRefusesToClobber covers the mistake with no recovery: overwriting a
// keyring destroys the keys of every object written under it.
func TestKeygenRefusesToClobber(t *testing.T) {
	keyring := setupKeyring(t, "first")

	err := run(t.Context(), []string{"keygen", "--out", keyring, "--kid", "second"})
	if err == nil {
		t.Fatal("keygen overwrote an existing keyring")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("got %v, want an error mentioning that the file exists", err)
	}

	// The original key must still be there and still be active.
	data, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	ring, err := keys.LoadKeyring(data, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if ring.ActiveKID() != "first" {
		t.Errorf("active key is %q, want %q", ring.ActiveKID(), "first")
	}
}

func TestKeygenAddRotatesTheActiveKey(t *testing.T) {
	keyring := setupKeyring(t, "2026-08")

	if err := run(t.Context(), []string{"keygen", "--out", keyring, "--kid", "2026-09", "--add"}); err != nil {
		t.Fatalf("keygen --add: %v", err)
	}

	data, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	ring, err := keys.LoadKeyring(data, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if got := ring.KIDs(); len(got) != 2 {
		t.Errorf("keyring holds %v, want both keys", got)
	}
	if ring.ActiveKID() != "2026-09" {
		t.Errorf("active key is %q, want the newly added one", ring.ActiveKID())
	}

	// The retired key must remain usable, or every object under it becomes
	// unreadable the moment a new key is added.
	if _, err := ring.Wrap(t.Context(), "2026-08", make([]byte, keys.KeySize), nil); err != nil {
		t.Errorf("the retired key is no longer usable: %v", err)
	}
}

func TestKeysRemoveNeedsForceAndRetires(t *testing.T) {
	keyring := setupKeyring(t, "2026-08")
	if err := run(t.Context(), []string{"keygen", "--out", keyring, "--kid", "2026-09", "--add"}); err != nil {
		t.Fatalf("keygen --add: %v", err)
	}

	// Removing a key is the one irreversible edit to a keyring: every object
	// still wrapped under it becomes unreadable, and nothing here can see the
	// bucket to check. The default must therefore be a refusal.
	err := run(t.Context(), []string{"keys", "remove", "--keyring", keyring, "2026-08"})
	if err == nil {
		t.Fatal("keys remove without --force was accepted")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
	if err := run(t.Context(), []string{"keys", "remove", "--keyring", keyring, "--force", "2026-09"}); err == nil {
		t.Error("removing the active key was accepted")
	}
	// A typo in the key id must read as a typo, not as a warning about data loss.
	if err := run(t.Context(), []string{"keys", "remove", "--keyring", keyring, "2026-07"}); err == nil ||
		strings.Contains(err.Error(), "--force") {
		t.Errorf("an unknown key id gave %v, want a plain not-found", err)
	}

	if err := run(t.Context(), []string{"keys", "remove", "--keyring", keyring, "--force", "2026-08"}); err != nil {
		t.Fatalf("keys remove --force: %v", err)
	}

	data, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Re-sealed under the same passphrase, and holding only the active key.
	ring, err := keys.LoadKeyring(data, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("LoadKeyring after remove: %v", err)
	}
	if got := ring.KIDs(); len(got) != 1 || got[0] != "2026-09" {
		t.Errorf("keyring holds %v, want only the active key", got)
	}

	if err := run(t.Context(), []string{"keys", "list", "--keyring", keyring}); err != nil {
		t.Errorf("keys list: %v", err)
	}
}

func TestDecryptFailsCleanly(t *testing.T) {
	keyring := setupKeyring(t, "kid")
	dir := t.TempDir()

	plainPath := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(plainPath, bytes.Repeat([]byte{7}, 100_000), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cipherPath := filepath.Join(dir, "cipher.bb")
	if err := run(t.Context(), []string{"encrypt", "--keyring", keyring, "-i", plainPath, "-o", cipherPath}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	t.Run("wrong passphrase leaves no output", func(t *testing.T) {
		t.Setenv(passphraseEnv, "not the passphrase")
		out := filepath.Join(dir, "wrong.bin")
		if err := run(t.Context(), []string{"decrypt", "--keyring", keyring, "-i", cipherPath, "-o", out}); err == nil {
			t.Fatal("decrypt succeeded with the wrong passphrase")
		}
		assertAbsent(t, out)
	})

	t.Run("tampered ciphertext leaves no output", func(t *testing.T) {
		t.Setenv(passphraseEnv, testPassphrase)
		cipher, err := os.ReadFile(cipherPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		cipher[len(cipher)/2] ^= 0x01
		tamperedPath := filepath.Join(dir, "tampered.bb")
		if err := os.WriteFile(tamperedPath, cipher, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		out := filepath.Join(dir, "tampered.bin")
		if err := run(t.Context(), []string{"decrypt", "--keyring", keyring, "-i", tamperedPath, "-o", out}); err == nil {
			t.Fatal("decrypt succeeded on a tampered file")
		}
		assertAbsent(t, out)
	})
}

func TestCommandDispatch(t *testing.T) {
	if err := run(t.Context(), []string{"version"}); err != nil {
		t.Errorf("version: %v", err)
	}
	if err := run(t.Context(), []string{"help"}); err != nil {
		t.Errorf("help: %v", err)
	}
	if err := run(t.Context(), nil); !errors.Is(err, errUsage) {
		t.Errorf("no arguments returned %v, want errUsage", err)
	}
	if err := run(t.Context(), []string{"nonsense"}); err == nil {
		t.Error("an unknown command was accepted")
	}
	if err := run(t.Context(), []string{"encrypt"}); err == nil {
		t.Error("encrypt without --keyring was accepted")
	}
	if err := run(t.Context(), []string{"keys"}); !errors.Is(err, errUsage) {
		t.Errorf("keys without a subcommand returned %v, want errUsage", err)
	}
	if err := run(t.Context(), []string{"keys", "nonsense"}); err == nil {
		t.Error("an unknown keys subcommand was accepted")
	}
}

// assertAbsent fails if path exists: a failed command must not leave a
// plausible-looking partial file for a user to mistake for a result.
func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists after a failed run", filepath.Base(path))
	}
	if left, _ := filepath.Glob(path + ".tmp*"); len(left) > 0 {
		t.Errorf("%v was left behind after a failed run", left)
	}
}
