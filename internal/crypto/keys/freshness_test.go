package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestFreshnessKeySurvivesAKeyringRoundTrip(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	original, err := NewFreshnessKey()
	if err != nil {
		t.Fatalf("NewFreshnessKey: %v", err)
	}
	ring.SetFreshnessKey(original)

	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	got, ok := loaded.FreshnessKey()
	if !ok {
		t.Fatal("the freshness key did not survive the round trip")
	}
	if !bytes.Equal(got.Secret(), original.Secret()) {
		t.Error("the freshness key came back different")
	}
	if bytes.Contains(data, original.Secret()) {
		t.Error("the freshness key appears in the keyring file in clear")
	}
}

// TestKeyringWithoutAFreshnessKeyStillLoads is the compatibility property: every
// keyring written before ADR-018 has no such entry, and must keep loading.
func TestKeyringWithoutAFreshnessKeyStillLoads(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(data, []byte("freshness_key")) {
		t.Error("a keyring with no freshness key wrote the field anyway")
	}

	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if _, ok := loaded.FreshnessKey(); ok {
		t.Error("a keyring with no freshness key reported one")
	}
}

// TestFreshnessKeyDoesNotChangeTheFileVersion: adding the entry must not force
// existing keyrings through a migration.
func TestFreshnessKeyDoesNotChangeTheFileVersion(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key, err := NewFreshnessKey()
	if err != nil {
		t.Fatalf("NewFreshnessKey: %v", err)
	}
	ring.SetFreshnessKey(key)
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var file struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if file.Version != keyringVersion {
		t.Errorf("file version is %d, want %d", file.Version, keyringVersion)
	}
}

// TestFreshnessKeyIsNotUnwrappableAsSomethingElse. A keyring can hold four
// 32-byte secrets, and nothing but the associated data distinguishes them: swap
// two and the gateway would key an index off the audit secret, or stored names
// off the index key, without a single error.
func TestFreshnessKeyIsNotUnwrappableAsSomethingElse(t *testing.T) {
	rootKey, err := NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	key, err := NewFreshnessKey()
	if err != nil {
		t.Fatalf("NewFreshnessKey: %v", err)
	}
	entry, err := sealFreshness(rootKey, key)
	if err != nil {
		t.Fatalf("sealFreshness: %v", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}

	kek, err := kekAAD("2026-09")
	if err != nil {
		t.Fatalf("kekAAD: %v", err)
	}
	for _, tc := range []struct {
		as  string
		aad []byte
	}{
		{"a KEK", kek},
		{"the audit secret", auditAAD()},
		{"the name key", nameAAD()},
	} {
		if _, err := openKey(rootKey, wrapped, tc.aad); err == nil {
			t.Errorf("the freshness key unwrapped as %s", tc.as)
		}
	}

	// And the reverse: a name key accepted as an index key would tie the index
	// to the key that names objects, which ADR-018 separates on purpose.
	name, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	nameEnt, err := sealName(rootKey, name)
	if err != nil {
		t.Fatalf("sealName: %v", err)
	}
	nameWrapped, err := base64.StdEncoding.DecodeString(nameEnt.Wrapped)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if _, err := openKey(rootKey, nameWrapped, freshnessAAD()); err == nil {
		t.Error("the name key unwrapped as a freshness key")
	}
}

// TestFreshnessKeyIsUntouchedByRotation. Every entry in the index is keyed under
// this key, so a rotation that changed it would empty the index and silently
// drop every object back to trust on first use.
func TestFreshnessKeyIsUntouchedByRotation(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key, err := NewFreshnessKey()
	if err != nil {
		t.Fatalf("NewFreshnessKey: %v", err)
	}
	ring.SetFreshnessKey(key)
	before := append([]byte(nil), key.Secret()...)

	if err := ring.Generate("2026-10"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ring.SetActive("2026-10"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if err := ring.Remove("2026-09"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	after, ok := ring.FreshnessKey()
	if !ok {
		t.Fatal("rotation removed the freshness key")
	}
	if !bytes.Equal(after.Secret(), before) {
		t.Error("rotation changed the freshness key")
	}
}

func TestFreshnessKeyFromSecretRejectsAWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := FreshnessKeyFromSecret(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte secret was accepted as a freshness key", n)
		}
	}
}

func TestFreshnessKeyWipeZeroesTheSecret(t *testing.T) {
	key, err := NewFreshnessKey()
	if err != nil {
		t.Fatalf("NewFreshnessKey: %v", err)
	}
	key.Wipe()
	if !bytes.Equal(key.secret[:], make([]byte, FreshnessKeySize)) {
		t.Error("Wipe left the secret behind")
	}
}
