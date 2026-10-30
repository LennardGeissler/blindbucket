package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"testing"
	"time"
)

var updateKeyringVectors = flag.Bool("update", false, "regenerate testdata/vectors/keyring_v2.json")

const keyringVectorPath = "../../../testdata/vectors/keyring_v2.json"

// keyringVectorFile is the on-disk shape of the keyring vectors, a normative
// part of docs/FORMAT.md section 18. An implementation that opens every
// accepted file to exactly the keys, tenants and buckets listed, and refuses
// every other, implements the section.
type keyringVectorFile struct {
	Note    string          `json:"note"`
	Vectors []keyringVector `json:"vectors"`
}

type keyringVector struct {
	Name string `json:"name"`
	// DeploymentRoot and TenantRoots are root keys in hex, as a key service
	// or a passphrase would yield them. A tenant missing from TenantRoots is
	// one whose root key cannot be obtained.
	DeploymentRoot string            `json:"deployment_root"`
	TenantRoots    map[string]string `json:"tenant_roots"`
	File           string            `json:"file"`
	// Refused is set for a file a reader must refuse as a whole, and names
	// the rule of section 18.6 it breaks.
	Refused string         `json:"refused,omitempty"`
	Expect  *keyringOpened `json:"expect,omitempty"`
}

type keyringOpened struct {
	Default  openedTenant            `json:"default"`
	Tenants  map[string]openedTenant `json:"tenants"`
	Unopened []string                `json:"unopened"`
	Buckets  map[string]bucketOwner  `json:"buckets"`
}

type openedTenant struct {
	ActiveKID string            `json:"active_kid"`
	KEKs      map[string]string `json:"keks"`
	NameKey   string            `json:"name_key"`
}

type bucketOwner struct {
	Tenant    string `json:"tenant"`
	Destroyed bool   `json:"destroyed"`
}

// vkey derives fixed key material from a label.
func vkey(label string) []byte {
	sum := sha256.Sum256([]byte("blindbucket keyring vector " + label))
	return sum[:]
}

func vring(t *testing.T, label string, kids ...string) *Keyring {
	t.Helper()
	r := NewKeyring()
	for _, kid := range kids {
		if err := r.Add(kid, vkey(label+"/kek/"+kid)); err != nil {
			t.Fatal(err)
		}
	}
	nk, err := NameKeyFromSecret(vkey(label + "/name"))
	if err != nil {
		t.Fatal(err)
	}
	r.SetNameKey(nk)
	return r
}

// TenantSeal is a tenant as a vector writes it, with every field of its
// directory entry set directly, so that a vector can hold what the commands
// would only reach in several steps: a resealed tenant, an inactive one.
type TenantSeal struct {
	Name     string
	Buckets  []string
	Ring     *Keyring
	Inactive bool
	RootKey  []byte
	RootRef  *RootKeyRef
	KDF      *KDFParams
	Previous []Lock
}

// MarshalV2 writes a version 2 file from its parts.
func MarshalV2(def *Keyring, rootKey []byte, ref RootKeyRef, params *KDFParams,
	generation uint64, tenants []TenantSeal, tombstones []Tombstone,
) ([]byte, error) {
	base, err := def.buildFile(rootKey, ref, params)
	if err != nil {
		return nil, err
	}
	dir := Directory{Generation: generation, Tombstones: tombstones}
	var sections []tenantSection
	for _, t := range tenants {
		s, err := sealSection(t.Name, t.Ring, t.RootKey, t.RootRef, t.KDF)
		if err != nil {
			return nil, err
		}
		sections = append(sections, s)
		active := t.Ring.ActiveKID()
		if t.Inactive {
			active = ""
		}
		dir.Tenants = append(dir.Tenants, DirectoryTenant{
			Name: t.Name, Buckets: t.Buckets, KIDs: t.Ring.KIDs(), ActiveKID: active,
			Locks: append(slices.Clone(t.Previous), s.lock()),
		})
	}
	return writeV2(base, rootKey, sections, dir, def.KIDs())
}

var deploymentRef = RootKeyRef{Source: SourceVaultTransit, Ciphertext: "vault:v1:vector", KeyName: "bb-deployment"}

// vectorBuckets are resolved in every accepted vector, so each one shows where
// they fall under its directory.
var vectorBuckets = []string{"acme-photos", "acme", "shared-reports", "shared-reports-2", "beta-1", "globex-data", "other"}

type keyringCase struct {
	name    string
	tenants []TenantSeal
	tombs   []Tombstone
	roots   map[string][]byte // the tenant roots a reader is given
	mutate  func(t *testing.T, f map[string]any, root []byte)
	refused string
}

func keyringCases(t *testing.T) []keyringCase {
	acme := func() TenantSeal {
		return TenantSeal{
			Name: "acme", Buckets: []string{"acme-*", "shared-reports"}, Ring: vring(t, "acme", "acme-2026-10"),
			RootKey: vkey("acme/root"),
			RootRef: &RootKeyRef{Source: SourceAWSKMS, Ciphertext: "AQICAHvector", KeyName: "alias/bb-acme"},
		}
	}
	beta := func() TenantSeal {
		return TenantSeal{
			Name: "beta", Buckets: []string{"beta-*"}, Ring: vring(t, "beta", "beta-1"),
			RootKey: vkey("deployment/root"), Inactive: true,
		}
	}
	globexTomb := Tombstone{
		Name: "globex", Buckets: []string{"globex-*"}, KIDs: []string{"globex-1"},
		Locks:     []Lock{{Source: SourceVaultTransit, KeyName: "bb-globex"}},
		Destroyed: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC),
	}
	acmeRoots := map[string][]byte{"acme": vkey("acme/root")}
	resealed := acme()
	resealed.Previous = []Lock{{Source: SourceAWSKMS, KeyName: "alias/bb-acme-2025"}}
	passphrase := acme()
	passphrase.RootRef = nil
	passphrase.KDF = &KDFParams{Algorithm: "argon2id", Salt: base64.StdEncoding.EncodeToString(vkey("acme/salt")[:16]),
		Time: 3, MemoryKiB: 64 * 1024, Parallelism: 4}

	// Each refused case starts from a valid file and breaks one rule; those
	// inside the directory re-seal it, so that only the rule is broken.
	editDir := func(edit func(d map[string]any)) func(*testing.T, map[string]any, []byte) {
		return func(t *testing.T, f map[string]any, root []byte) {
			raw, _ := base64.StdEncoding.DecodeString(f["directory"].(string))
			plain, err := openKey(root, raw, []byte(aadDirectory))
			if err != nil {
				t.Fatal(err)
			}
			var d map[string]any
			if err := json.Unmarshal(plain, &d); err != nil {
				t.Fatal(err)
			}
			edit(d)
			plain, _ = json.Marshal(d)
			sealed, err := sealKey(root, plain, []byte(aadDirectory))
			if err != nil {
				t.Fatal(err)
			}
			f["directory"] = base64.StdEncoding.EncodeToString(sealed)
		}
	}
	tenant0 := func(d map[string]any) map[string]any { return d["tenants"].([]any)[0].(map[string]any) }
	section0 := func(f map[string]any) map[string]any { return f["tenants"].([]any)[0].(map[string]any) }

	return []keyringCase{
		{name: "a tenant with a lock of its own", tenants: []TenantSeal{acme()}, roots: acmeRoots},
		{name: "an inactive tenant under the deployment's lock", tenants: []TenantSeal{acme(), beta()}, roots: acmeRoots},
		{name: "a tenant whose root key cannot be obtained", tenants: []TenantSeal{acme(), beta()}, roots: nil},
		{name: "a tenant given the wrong root key", tenants: []TenantSeal{acme()},
			roots: map[string][]byte{"acme": vkey("someone else's root")}},
		{name: "a destroyed tenant", tenants: []TenantSeal{acme()}, tombs: []Tombstone{globexTomb}, roots: acmeRoots},
		{name: "only a tombstone", tombs: []Tombstone{globexTomb}},
		{name: "a resealed tenant", tenants: []TenantSeal{resealed}, roots: acmeRoots},
		{name: "a tenant sealed by a passphrase", tenants: []TenantSeal{passphrase}, roots: acmeRoots},
		// The section and its directory entry renamed together: the file is
		// consistent, and the associated data are what catch it.
		{name: "a section moved to another name", tenants: []TenantSeal{acme()},
			roots: map[string][]byte{"acme": vkey("acme/root"), "zeta": vkey("acme/root")},
			mutate: func(t *testing.T, f map[string]any, root []byte) {
				section0(f)["name"] = "zeta"
				editDir(func(d map[string]any) { tenant0(d)["name"] = "zeta" })(t, f, root)
			}},

		{name: "no directory", refused: "the directory is missing", tenants: []TenantSeal{acme()},
			mutate: func(_ *testing.T, f map[string]any, _ []byte) { delete(f, "directory") }},
		{name: "a directory under another key", refused: "the directory does not open", tenants: []TenantSeal{acme()},
			mutate: func(t *testing.T, f map[string]any, root []byte) {
				raw, _ := base64.StdEncoding.DecodeString(f["directory"].(string))
				plain, err := openKey(root, raw, []byte(aadDirectory))
				if err != nil {
					t.Fatal(err)
				}
				sealed, err := sealKey(vkey("not the deployment"), plain, []byte(aadDirectory))
				if err != nil {
					t.Fatal(err)
				}
				f["directory"] = base64.StdEncoding.EncodeToString(sealed)
			}},
		{name: "generations differ", refused: "the generations differ", tenants: []TenantSeal{acme()},
			mutate: func(_ *testing.T, f map[string]any, _ []byte) { f["generation"] = f["generation"].(float64) + 1 }},
		{name: "a tenant named default", refused: "a tenant is named default", tenants: []TenantSeal{acme()},
			mutate: func(t *testing.T, f map[string]any, root []byte) {
				section0(f)["name"] = "default"
				editDir(func(d map[string]any) { tenant0(d)["name"] = "default" })(t, f, root)
			}},
		{name: "a name both live and destroyed", refused: "a tenant name is used twice", tenants: []TenantSeal{acme()},
			mutate: editDir(func(d map[string]any) {
				d["tombstones"] = []any{map[string]any{"name": "acme", "buckets": []any{"old-acme"}, "kids": []any{"acme-1"},
					"locks": []any{map[string]any{"source": "deployment"}}, "destroyed": "2026-11-02T10:00:00Z"}}
			})},
		{name: "a key id the default tenant has", refused: "a key id is used twice", tenants: []TenantSeal{acme()},
			mutate: editDir(func(d map[string]any) {
				d["tombstones"] = []any{map[string]any{"name": "old", "buckets": []any{"old"}, "kids": []any{"2026-10"},
					"locks": []any{map[string]any{"source": "deployment"}}, "destroyed": "2026-11-02T10:00:00Z"}}
			})},
		{name: "overlapping bucket entries", refused: "bucket entries overlap", tenants: []TenantSeal{acme()},
			mutate: editDir(func(d map[string]any) {
				d["tombstones"] = []any{map[string]any{"name": "old", "buckets": []any{"acme-photos"}, "kids": []any{"old-1"},
					"locks": []any{map[string]any{"source": "deployment"}}, "destroyed": "2026-11-02T10:00:00Z"}}
			})},
		{name: "a malformed bucket entry", refused: "a bucket entry is malformed", tenants: []TenantSeal{acme()},
			mutate: editDir(func(d map[string]any) { tenant0(d)["buckets"] = []any{"Acme-*"} })},
		{name: "an active key not the tenant's", refused: "active_kid is not one of the tenant's kids", tenants: []TenantSeal{acme()},
			mutate: editDir(func(d map[string]any) { tenant0(d)["active_kid"] = "2026-10" })},
		{name: "a tenant without a section", refused: "tenants and sections do not correspond", tenants: []TenantSeal{acme()},
			mutate: func(_ *testing.T, f map[string]any, _ []byte) { f["tenants"] = []any{} }},
		{name: "a section with a key the directory does not list", refused: "a section's keys are not its tenant's kids",
			tenants: []TenantSeal{acme()},
			mutate: func(_ *testing.T, f map[string]any, _ []byte) {
				keys := section0(f)["keys"].([]any)
				extra := maps.Clone(keys[0].(map[string]any))
				extra["kid"] = "acme-extra"
				section0(f)["keys"] = append(keys, extra)
			}},
		{name: "a section without a name key", refused: "a section has no name_key", tenants: []TenantSeal{acme()},
			mutate: func(_ *testing.T, f map[string]any, _ []byte) { delete(section0(f), "name_key") }},
		{name: "a section sealed by another lock than recorded", refused: "a section does not match its last lock",
			tenants: []TenantSeal{acme()},
			mutate: editDir(func(d map[string]any) {
				tenant0(d)["locks"] = []any{map[string]any{"source": "awskms", "key_name": "alias/someone-else"}}
			})},
	}
}

func buildKeyringVector(t *testing.T, c keyringCase) keyringVector {
	t.Helper()
	root := vkey("deployment/root")
	def := vring(t, "default", "2026-09", "2026-10")
	if err := def.SetActive("2026-10"); err != nil {
		t.Fatal(err)
	}
	data, err := MarshalV2(def, root, deploymentRef, nil, 7, c.tenants, c.tombs)
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	if c.mutate != nil {
		var f map[string]any
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		c.mutate(t, f, root)
		if data, err = json.MarshalIndent(f, "", "  "); err != nil {
			t.Fatal(err)
		}
	}
	v := keyringVector{Name: c.name, DeploymentRoot: hex.EncodeToString(root), File: string(data), Refused: c.refused,
		TenantRoots: map[string]string{}}
	for name, r := range c.roots {
		v.TenantRoots[name] = hex.EncodeToString(r)
	}
	if c.refused != "" {
		return v
	}
	opened, err := OpenKeyringV2(data, root, rootsFunc(c.roots))
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	v.Expect = describe(opened)
	return v
}

func rootsFunc(roots map[string][]byte) func(string, Lock) ([]byte, error) {
	return func(name string, _ Lock) ([]byte, error) {
		if r, ok := roots[name]; ok {
			return r, nil
		}
		return nil, fmt.Errorf("no root key for %q", name)
	}
}

func describeRing(r *Keyring) openedTenant {
	out := openedTenant{ActiveKID: r.ActiveKID(), KEKs: map[string]string{}}
	for _, kid := range r.KIDs() {
		kek, _ := r.lookup(kid)
		out.KEKs[kid] = hex.EncodeToString(kek[:])
	}
	if nk, ok := r.NameKey(); ok {
		out.NameKey = hex.EncodeToString(nk.Secret())
	}
	return out
}

func describe(k *KeyringV2) *keyringOpened {
	out := &keyringOpened{
		Default: describeRing(k.Default), Tenants: map[string]openedTenant{},
		Unopened: slices.Sorted(maps.Keys(k.Unopened)), Buckets: map[string]bucketOwner{},
	}
	if out.Unopened == nil {
		out.Unopened = []string{}
	}
	for name, r := range k.Tenants {
		out.Tenants[name] = describeRing(r)
	}
	for _, b := range vectorBuckets {
		name, destroyed := k.Directory.Tenant(b)
		out.Buckets[b] = bucketOwner{Tenant: name, Destroyed: destroyed}
	}
	return out
}

func TestKeyringV2Vectors(t *testing.T) {
	if *updateKeyringVectors {
		file := keyringVectorFile{
			Note: "Known-answer vectors for docs/FORMAT.md section 18, version 2 of the keyring file. " +
				"Root keys are given in hex as a key service or a passphrase would yield them; a tenant " +
				"missing from tenant_roots is one whose root key cannot be obtained. A vector with " +
				"`refused` is a file a reader must refuse as a whole. Regenerate with " +
				"`go test ./internal/crypto/keys -run TestKeyringV2Vectors -update`.",
		}
		for _, c := range keyringCases(t) {
			file.Vectors = append(file.Vectors, buildKeyringVector(t, c))
		}
		out, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyringVectorPath, append(out, '\n'), 0o644); err != nil { //nolint:gosec // a committed test fixture.
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(keyringVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var file keyringVectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if want := len(keyringCases(t)); len(file.Vectors) != want {
		t.Fatalf("%d vectors in the file, %d cases: regenerate with -update", len(file.Vectors), want)
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			root, _ := hex.DecodeString(v.DeploymentRoot)
			roots := map[string][]byte{}
			for name, h := range v.TenantRoots {
				roots[name], _ = hex.DecodeString(h)
			}
			opened, err := OpenKeyringV2([]byte(v.File), root, rootsFunc(roots))
			if v.Refused != "" {
				if err == nil {
					t.Fatalf("opened a file that breaks %q", v.Refused)
				}
				if !errors.Is(err, ErrKeyringMalformed) {
					t.Fatalf("refused, but not as malformed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(describe(opened))
			want, _ := json.Marshal(v.Expect)
			if !bytes.Equal(got, want) {
				t.Fatalf("opened to\n%s\nwant\n%s", got, want)
			}
		})
	}
}
