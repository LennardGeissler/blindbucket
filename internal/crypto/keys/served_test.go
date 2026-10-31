package keys

import (
	"bytes"
	"errors"
	"testing"
)

// servedFile is withTenants with acme active, beta inactive, and globex
// destroyed, opened with acme's root key or without it.
func servedFile(t *testing.T, withAcme bool) *Served {
	t.Helper()
	f := openV(t, withTenants(t), fileRoot, acmeRoots)
	if err := f.Activate("acme", ""); err != nil {
		t.Fatal(err)
	}
	f.Tombstones = []Tombstone{{Name: "globex", Buckets: []string{"globex-*"}, KIDs: []string{"globex-1"},
		Locks: []Lock{{Source: LockDeployment}}}}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string][]byte{}
	if withAcme {
		roots = acmeRoots
	}
	return NewServed(openV(t, data, fileRoot, roots))
}

func TestServedFor(t *testing.T) {
	s := servedFile(t, true)
	defName, _ := s.Default().NameKey()
	acmeName, _ := s.tenants["acme"].Ring.NameKey()

	for bucket, want := range map[string]BucketKeys{
		"other":       {Tenant: DefaultTenant, KID: "2026-10", NameTenant: DefaultTenant, Name: defName},
		"acme-photos": {Tenant: "acme", KID: "acme-2026-10", NameTenant: "acme", Name: acmeName},
		// beta is not active: its buckets behave as the default tenant's,
		// names included, until every instance serves it.
		"beta-1": {Tenant: "beta", KID: "2026-10", NameTenant: DefaultTenant, Name: defName},
	} {
		got, err := s.For(bucket)
		if err != nil || got != want {
			t.Errorf("For(%q) = %+v, %v; want %+v", bucket, got, err, want)
		}
	}
	if _, err := s.For("globex-data"); !errors.Is(err, ErrTenantDestroyed) {
		t.Errorf("a destroyed tenant's bucket: %v, want ErrTenantDestroyed", err)
	}
}

// A tenant that did not open refuses its own buckets and nobody else's.
func TestServedUnopenedTenant(t *testing.T) {
	s := servedFile(t, false)
	if _, err := s.For("acme-photos"); !errors.Is(err, ErrTenantUnopened) {
		t.Errorf("acme's bucket without acme: %v, want ErrTenantUnopened", err)
	}
	if _, err := s.For("beta-1"); err != nil {
		t.Errorf("beta's bucket while acme is unopened: %v", err)
	}
	if _, err := s.Unwrap(t.Context(), "acme-2026-10", make([]byte, WrappedDEKSize), nil); !errors.Is(err, ErrUnknownKID) {
		t.Errorf("unwrap under an unopened tenant's key: %v, want ErrUnknownKID", err)
	}
}

// Reads go by the key id, whoever holds it; the associated data is what binds
// a data key to its object.
func TestServedUnwrapsByKeyID(t *testing.T) {
	s := servedFile(t, true)
	dek := bytes.Repeat([]byte{7}, KeySize)
	for _, kid := range []string{"2026-10", "acme-2026-10", "beta-2026-10"} {
		wrapped, err := s.Wrap(t.Context(), kid, dek, []byte("aad"))
		if err != nil {
			t.Fatalf("%s: %v", kid, err)
		}
		got, err := s.Unwrap(t.Context(), kid, wrapped, []byte("aad"))
		if err != nil || !bytes.Equal(got, dek) {
			t.Errorf("%s: %v", kid, err)
		}
		if _, err := s.Unwrap(t.Context(), kid, wrapped, []byte("other")); err == nil {
			t.Errorf("%s: opened under other associated data", kid)
		}
	}
	want, _ := s.tenants["acme"].Ring.TokenKey(t.Context(), "acme-2026-10")
	if got, err := s.TokenKey(t.Context(), "acme-2026-10"); err != nil || !bytes.Equal(got, want) {
		t.Errorf("TokenKey for acme's key is not acme's: %v", err)
	}
	if _, err := s.Unwrap(t.Context(), "globex-1", make([]byte, WrappedDEKSize), nil); !errors.Is(err, ErrUnknownKID) {
		t.Errorf("a destroyed tenant's key: %v, want ErrUnknownKID", err)
	}
}

func TestKeyringForIsTheDefaultTenant(t *testing.T) {
	r := vring(t, "x", "k1")
	nk, _ := r.NameKey()
	got, err := r.For("any-bucket")
	if err != nil || got != (BucketKeys{Tenant: DefaultTenant, KID: "k1", NameTenant: DefaultTenant, Name: nk}) {
		t.Errorf("For = %+v, %v", got, err)
	}
}

// A Served is a snapshot: the file it came from may go on being changed, as
// the keyring commands change theirs, without the running instance noticing.
func TestServedIsASnapshot(t *testing.T) {
	f := openV(t, withTenants(t), fileRoot, nil)
	s := NewServed(f)
	if err := f.Activate("beta", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.Assign("beta", []string{"beta-2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.For("beta-1"); got.KID != "2026-10" {
		t.Errorf("activating beta in the file reached the served keyring: %+v", got)
	}
	if got, _ := s.For("beta-2"); got.Tenant != DefaultTenant {
		t.Errorf("assigning beta-2 in the file reached the served keyring: %+v", got)
	}
}

// An audit entry's names go under the key of the bucket's tenant whenever it
// opened here, active or not, and are not held for one destroyed or unopened.
func TestServedAuditTenant(t *testing.T) {
	type want struct {
		tenant string
		held   bool
	}
	for withAcme, cases := range map[bool]map[string]want{
		true: {
			"other": {"", true}, "acme-photos": {"acme", true},
			"beta-1": {"beta", true}, "globex-data": {"globex", false},
		},
		false: {"acme-photos": {"acme", false}, "beta-1": {"beta", true}},
	} {
		s := servedFile(t, withAcme)
		for bucket, w := range cases {
			if tenant, held := s.AuditTenant(bucket); tenant != w.tenant || held != w.held {
				t.Errorf("acme open %v: AuditTenant(%q) = %q, %v; want %q, %v",
					withAcme, bucket, tenant, held, w.tenant, w.held)
			}
		}
	}

	s := servedFile(t, true)
	nk, _ := s.tenants["acme"].Ring.NameKey()
	acmeKey, err := nk.AuditNameKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.AuditNameKey("acme"); err != nil || !bytes.Equal(got, acmeKey) {
		t.Errorf("AuditNameKey(acme) = %x, %v", got, err)
	}
	for _, tenant := range []string{"zeta", "globex"} {
		if _, err := s.AuditNameKey(tenant); err == nil {
			t.Errorf("AuditNameKey(%s) gave a key", tenant)
		}
	}
	if _, err := servedFile(t, false).AuditNameKey("acme"); err == nil {
		t.Error("AuditNameKey gave an unopened tenant's key")
	}
}
