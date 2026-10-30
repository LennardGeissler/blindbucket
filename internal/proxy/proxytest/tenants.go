package proxytest

import (
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
)

// Key ids of Tenancy's keyrings.
const (
	DefaultKID = "default-key"
	TenantKID  = "acme-key"
)

// Tenancy is a keyring in which Bucket belongs to the tenant "acme", served
// at each point of its life: added and not yet active, active, unopened on
// this instance, and destroyed. Inactive and Active are one keyring at two
// generations, so either reads what the other wrote.
type Tenancy struct {
	Inactive, Active, Unopened, Destroyed *keys.Served
}

// NewTenancy builds the keyrings of Tenancy.
func NewTenancy(t *testing.T) *Tenancy {
	t.Helper()
	root := make([]byte, keys.KeySize)
	ref := keys.RootKeyRef{Source: keys.SourceVaultTransit, Ciphertext: "vault:v1:test", KeyName: "test"}
	ring := func(kid string) *keys.Keyring {
		r := keys.NewKeyring()
		if err := r.Generate(kid); err != nil {
			t.Fatal(err)
		}
		nk, err := keys.NewNameKey()
		if err != nil {
			t.Fatal(err)
		}
		r.SetNameKey(nk)
		return r
	}
	write := func(f *keys.File) []byte {
		data, err := f.MarshalWithRootKey(root, ref)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	open := func(data []byte) *keys.File {
		f, err := keys.OpenFile(data, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	base := write(&keys.File{Default: ring(DefaultKID)})
	f := open(base)
	if err := f.AddTenant("acme", []string{Bucket}, ring(TenantKID), keys.DeploymentLock()); err != nil {
		t.Fatal(err)
	}
	inactive := open(write(f))
	out := &Tenancy{Inactive: keys.NewServed(inactive)}
	if err := inactive.Activate("acme", ""); err != nil {
		t.Fatal(err)
	}
	out.Active = keys.NewServed(open(write(inactive)))

	// acme under a lock this instance has no root key for.
	f = open(base)
	lock, err := keys.ServiceLock(make([]byte, keys.KeySize),
		keys.RootKeyRef{Source: keys.SourceAWSKMS, Ciphertext: "AQICAHtest", KeyName: "alias/acme"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AddTenant("acme", []string{Bucket}, ring(TenantKID), lock); err != nil {
		t.Fatal(err)
	}
	out.Unopened = keys.NewServed(open(write(f)))

	f = open(base)
	f.Tombstones = []keys.Tombstone{{Name: "acme", Buckets: []string{Bucket}, KIDs: []string{TenantKID},
		Locks: []keys.Lock{{Source: keys.LockDeployment}}}}
	out.Destroyed = keys.NewServed(open(write(f)))
	return out
}

// WithKeys serves the gateway with k instead of the harness's keyring.
func WithKeys(k keys.BucketKeyProvider) func(*proxy.Config) {
	return func(c *proxy.Config) { c.Keys = k }
}
