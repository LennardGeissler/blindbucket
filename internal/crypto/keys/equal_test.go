package keys

import (
	"testing"
	"time"
)

// fullKeyring is a keyring with every kind of key in it, so that a comparison
// that forgot one kind fails here.
func fullKeyring(t *testing.T) *Keyring {
	t.Helper()
	r := NewKeyring()
	for _, kid := range []string{"2026-09", "2026-10"} {
		if err := r.Generate(kid); err != nil {
			t.Fatalf("Generate: %v", err)
		}
	}
	if err := r.SetActive("2026-10"); err != nil {
		t.Fatal(err)
	}
	audit, err := NewAuditKey()
	if err != nil {
		t.Fatal(err)
	}
	name, err := NewNameKey()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewFreshnessKey()
	if err != nil {
		t.Fatal(err)
	}
	r.SetAuditKey(audit)
	r.SetNameKey(name)
	r.SetFreshnessKey(fresh)
	return r
}

// roundTrip seals a keyring under one root key and opens it again, which is
// what reseal does between a source and its target.
func roundTrip(t *testing.T, r *Keyring) *Keyring {
	t.Helper()
	root, err := NewRootKey()
	if err != nil {
		t.Fatal(err)
	}
	ref := RootKeyRef{Source: SourceVaultTransit, Ciphertext: "vault:v1:test", KeyName: "k"}
	data, err := r.MarshalWithRootKey(root, ref)
	if err != nil {
		t.Fatalf("MarshalWithRootKey: %v", err)
	}
	back, err := LoadKeyringWithRootKey(data, root)
	if err != nil {
		t.Fatalf("LoadKeyringWithRootKey: %v", err)
	}
	return back
}

func TestEqualSurvivesASealUnderAnotherRootKey(t *testing.T) {
	r := fullKeyring(t)
	if !r.Equal(roundTrip(t, r)) {
		t.Fatal("a keyring is not Equal to itself sealed and opened under another root key")
	}
}

// TestEqualNoticesEveryKindOfDifference changes one thing at a time. Each is a
// way a reseal could hand back a keyring that opens but is not the one it read.
func TestEqualNoticesEveryKindOfDifference(t *testing.T) {
	for name, change := range map[string]func(*testing.T, *Keyring){
		"a KEK missing": func(t *testing.T, r *Keyring) {
			if err := r.Remove("2026-09"); err != nil {
				t.Fatal(err)
			}
		},
		"a KEK added": func(t *testing.T, r *Keyring) {
			if err := r.Generate("2026-11"); err != nil {
				t.Fatal(err)
			}
		},
		"a KEK replaced": func(_ *testing.T, r *Keyring) {
			r.keks["2026-09"] = [KeySize]byte{1}
		},
		"another active key": func(t *testing.T, r *Keyring) {
			if err := r.SetActive("2026-09"); err != nil {
				t.Fatal(err)
			}
		},
		"another creation date": func(_ *testing.T, r *Keyring) {
			r.created["2026-09"] = r.created["2026-09"].Add(time.Hour)
		},
		"no audit key": func(_ *testing.T, r *Keyring) { r.audit = nil },
		"another name key": func(t *testing.T, r *Keyring) {
			k, err := NewNameKey()
			if err != nil {
				t.Fatal(err)
			}
			r.name = k
		},
		"no freshness key": func(_ *testing.T, r *Keyring) { r.freshness = nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := fullKeyring(t)
			other := roundTrip(t, r)
			change(t, other)
			if r.Equal(other) || other.Equal(r) {
				t.Errorf("%s went unnoticed", name)
			}
		})
	}
}

func TestEqualHandlesNil(t *testing.T) {
	r := fullKeyring(t)
	var none, alsoNone *Keyring
	if r.Equal(none) || none.Equal(r) {
		t.Error("a keyring is Equal to nil")
	}
	if !none.Equal(alsoNone) {
		t.Error("nil is not Equal to nil")
	}
}
