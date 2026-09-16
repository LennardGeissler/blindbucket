package keys

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

func TestNameKeySurvivesAKeyringRoundTrip(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	original, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	ring.SetNameKey(original)

	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	got, ok := loaded.NameKey()
	if !ok {
		t.Fatal("the name key did not survive the round trip")
	}
	if !bytes.Equal(got.Secret(), original.Secret()) {
		t.Error("the name key came back different")
	}
	if bytes.Contains(data, original.Secret()) {
		t.Error("the name key appears in the keyring file in clear")
	}
}

// TestNameKeyIsUntouchedByRotation is the property ADR-015 turns on. Rotation
// replaces the active KEK; if it also changed the name key, every object in the
// bucket would be renamed at once and none of them would be findable again.
func TestNameKeyIsUntouchedByRotation(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	name, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	ring.SetNameKey(name)
	before := name.Secret()

	// A rotation, as the CLI performs one: add a KEK, make it active, reseal.
	if err := ring.Generate("2026-10"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ring.SetActive("2026-10"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}

	if got := loaded.ActiveKID(); got != "2026-10" {
		t.Fatalf("active key is %q, want the rotated-to one", got)
	}
	after, ok := loaded.NameKey()
	if !ok {
		t.Fatal("rotation lost the name key")
	}
	if !bytes.Equal(after.Secret(), before) {
		t.Error("rotation changed the name key; every stored name would be unfindable")
	}
}

// TestKeyringWithoutANameKeyStillLoads: keyrings written before name encryption
// existed have no name key, and must keep opening.
func TestKeyringWithoutANameKeyStillLoads(t *testing.T) {
	ring := NewKeyring()
	if err := ring.Generate("2026-09"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := ring.Marshal(testPassphrase, testKDF)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	loaded, err := LoadKeyring(data, testPassphrase)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if _, ok := loaded.NameKey(); ok {
		t.Error("a keyring with no name key reported one")
	}
}

// TestNameKeyIsNotUnwrappableAsSomethingElse is what the AAD prefix buys. The
// name key, the audit secret and a KEK are all 32 bytes, so without domain
// separation the only thing telling them apart would be where in the file they
// were found.
func TestNameKeyIsNotUnwrappableAsSomethingElse(t *testing.T) {
	rootKey, err := NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	key, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	entry, err := sealName(rootKey, key)
	if err != nil {
		t.Fatalf("sealName: %v", err)
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
	} {
		if _, err := openKey(rootKey, wrapped, tc.aad); err == nil {
			t.Errorf("the name key unwrapped as %s", tc.as)
		}
	}

	// And the reverse direction, which is the one that would matter: an audit
	// secret accepted as a name key would silently key every stored name off the
	// log's key.
	audit, err := NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	auditEnt, err := sealAudit(rootKey, audit)
	if err != nil {
		t.Fatalf("sealAudit: %v", err)
	}
	auditWrapped, err := base64.StdEncoding.DecodeString(auditEnt.Wrapped)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if _, err := openKey(rootKey, auditWrapped, nameAAD()); err == nil {
		t.Error("the audit secret unwrapped as a name key")
	}
}

// TestNameKeyIsIndependentOfTheAuditNameKey: an entry in a log and the name of
// an object in the bucket must be different opaque strings for the same object,
// or holding one gives away the other.
func TestNameKeyIsIndependentOfTheAuditNameKey(t *testing.T) {
	audit, err := NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	auditName, err := audit.NameKey()
	if err != nil {
		t.Fatalf("AuditKey.NameKey: %v", err)
	}
	object, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	if bytes.Equal(auditName, object.Secret()) {
		t.Error("the audit log's name key and the object-name key are the same bytes")
	}
}

func TestNameKeyFromSecretRejectsAWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NameKeyFromSecret(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte name key was accepted", n)
		}
	}
}

func TestNameKeyWipeZeroesTheSecret(t *testing.T) {
	key, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	key.Wipe()
	if !bytes.Equal(key.Secret(), make([]byte, NameKeySize)) {
		t.Error("Wipe left key material behind")
	}
}

// TestNameKeyIsTheRightShapeForTheNamesPackage guards the one constant this
// package repeats rather than imports: NameKeySize must stay equal to
// names.KeySize, or a keyring would hand the encrypter a key it refuses.
func TestNameKeyIsTheRightShapeForTheNamesPackage(t *testing.T) {
	key, err := NewNameKey()
	if err != nil {
		t.Fatalf("NewNameKey: %v", err)
	}
	if _, err := names.New(key.Secret()); err != nil {
		t.Fatalf("the names package refused a keyring's name key: %v", err)
	}
}
