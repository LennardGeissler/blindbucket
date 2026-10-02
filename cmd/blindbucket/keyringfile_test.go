package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The durability half of keyringfile.go -- the syncs -- has no test that could
// fail without a power cut. What can fail here is the other half: what is
// replaced, what is refused, and what is left behind.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

func assertNoTemporaries(t *testing.T, path string) {
	t.Helper()
	if left, _ := filepath.Glob(path + ".tmp*"); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestReplaceKeyringReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	writeFile(t, path, "as opened")

	if err := replaceKeyring(path, []byte("as opened"), []byte("rewritten")); err != nil {
		t.Fatalf("replaceKeyring: %v", err)
	}
	if got := readFile(t, path); got != "rewritten" {
		t.Errorf("the keyring holds %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the keyring is mode %04o, want 0600", mode)
	}
	assertNoTemporaries(t, path)
}

// TestReplaceKeyringRefusesAChangedFile is the lost update it exists to stop:
// a keygen --add lands between another command's read and its write. Written
// back regardless, the first command's version would drop the key the second
// added, and every object wrapped under it with it.
func TestReplaceKeyringRefusesAChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	writeFile(t, path, "as opened")
	writeFile(t, path, "with a key another command added")

	err := replaceKeyring(path, []byte("as opened"), []byte("without that key"))
	if !errors.Is(err, errKeyringChanged) {
		t.Fatalf("replaceKeyring returned %v, want errKeyringChanged", err)
	}
	if got := readFile(t, path); got != "with a key another command added" {
		t.Errorf("the other command's write was replaced: the keyring holds %q", got)
	}
	assertNoTemporaries(t, path)
}

func TestReplaceKeyringNeedsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := replaceKeyring(path, []byte("as opened"), []byte("rewritten")); err == nil {
		t.Fatal("a keyring that is gone was written back")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("a keyring was created where there was none")
	}
	assertNoTemporaries(t, path)
}

// TestCreateKeyringFileNeverClobbers: the refusal is the link itself, so a
// keyring that appears after keygen checked for one -- another keygen, a
// restore from backup -- still is not replaced.
func TestCreateKeyringFileNeverClobbers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	writeFile(t, path, "the only copy")

	if err := createKeyringFile(path, []byte("a new keyring")); err == nil {
		t.Fatal("an existing keyring was replaced")
	}
	if got := readFile(t, path); got != "the only copy" {
		t.Errorf("the existing keyring holds %q", got)
	}
	assertNoTemporaries(t, path)

	fresh := filepath.Join(t.TempDir(), "new.json")
	if err := createKeyringFile(fresh, []byte("a new keyring")); err != nil {
		t.Fatalf("createKeyringFile: %v", err)
	}
	if got := readFile(t, fresh); got != "a new keyring" {
		t.Errorf("the new keyring holds %q", got)
	}
	assertNoTemporaries(t, fresh)
}
