package keys

import (
	"errors"
	"testing"
)

func TestDirectoryTenant(t *testing.T) {
	d := Directory{
		Tenants:    []DirectoryTenant{{Name: "acme", Buckets: []string{"acme-*", "shared-reports"}}},
		Tombstones: []Tombstone{{Name: "globex", Buckets: []string{"globex-*"}}},
	}
	for bucket, want := range map[string]struct {
		tenant    string
		destroyed bool
	}{
		"acme-photos":      {"acme", false},
		"acme-":            {"acme", false},
		"acme":             {DefaultTenant, false}, // the prefix is "acme-", not "acme"
		"shared-reports":   {"acme", false},
		"shared-reports-2": {DefaultTenant, false}, // an exact name matches only itself
		"globex-data":      {"globex", true},
		"other":            {DefaultTenant, false},
	} {
		name, destroyed := d.Tenant(bucket)
		if name != want.tenant || destroyed != want.destroyed {
			t.Errorf("Tenant(%q) = %q, %v; want %q, %v", bucket, name, destroyed, want.tenant, want.destroyed)
		}
	}
}

func TestBucketEntriesOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"acme", "acme", true},
		{"acme", "acmf", false},
		{"acme-*", "acme-photos", true},
		{"acme-photos", "acme-*", true},
		{"acme-*", "acme-p*", true},
		{"acme-*", "acm*", true},
		{"acme-*", "acmf-*", false},
		{"acme-*", "acme", false},
	} {
		if got := overlap(c.a, c.b); got != c.want {
			t.Errorf("overlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestValidBucketEntry(t *testing.T) {
	for e, want := range map[string]bool{
		"abc": true, "ab": false, "a*": true, "*": false, "Acme": false, "acme_x": false,
		"a.b-c": true, "acme-*": true, "acme-*-x": false,
	} {
		if got := validBucketEntry(e); got != want {
			t.Errorf("validBucketEntry(%q) = %v, want %v", e, got, want)
		}
	}
}

// One tenant that cannot be opened must not take another down with it, in
// whatever order they come: each is opened or not on its own.
func TestAnUnopenedTenantLeavesTheOthersOpen(t *testing.T) {
	root := vkey("deployment/root")
	def := vring(t, "default", "d1")
	locked := TenantSeal{Name: "a-locked", Buckets: []string{"a-*"}, Ring: vring(t, "a", "a1"),
		RootKey: vkey("a/root"), RootRef: &RootKeyRef{Source: SourceAWSKMS, Ciphertext: "x", KeyName: "alias/a"}}
	shared := TenantSeal{Name: "b-shared", Buckets: []string{"b-*"}, Ring: vring(t, "b", "b1"), RootKey: root}
	data, err := MarshalV2(def, root, deploymentRef, nil, 1, []TenantSeal{locked, shared}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenKeyringV2(data, root, func(string, Lock) ([]byte, error) {
		return nil, errors.New("the key service is down")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := opened.Unopened["a-locked"]; !ok {
		t.Error("a-locked opened without its root key")
	}
	if _, ok := opened.Tenants["b-shared"]; !ok {
		t.Errorf("b-shared, under the deployment's lock, did not open: %v", opened.Unopened["b-shared"])
	}
}

// LoadKeyring must keep refusing version 2 until the gateway routes buckets to
// their tenants: opening only the default tenant would wrap every tenant's
// buckets under its keys.
func TestLoadKeyringRefusesVersion2(t *testing.T) {
	root := vkey("deployment/root")
	data, err := MarshalV2(vring(t, "default", "d1"), root, deploymentRef, nil, 1,
		[]TenantSeal{{Name: "acme", Buckets: []string{"acme-*"}, Ring: vring(t, "acme", "a1"), RootKey: root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyringWithRootKey(data, root); err == nil {
		t.Fatal("LoadKeyringWithRootKey opened a version 2 keyring")
	}
}

func TestSealKeyRefusesAnOversizedPlaintext(t *testing.T) {
	if _, err := sealKey(vkey("k"), make([]byte, maxSealed+1), nil); err == nil {
		t.Fatal("sealed more than maxSealed")
	}
	if _, err := sealKey(vkey("k"), make([]byte, maxSealed), nil); err != nil {
		t.Fatal(err)
	}
}
