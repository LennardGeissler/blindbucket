package keys

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// ErrTenantDestroyed refuses a bucket whose tenant was destroyed. Its buckets
// do not fall back to the default tenant: the first write after a destruction
// would otherwise store new data in a deleted tenant's bucket under keys
// nobody intends to destroy (ADR-038).
var ErrTenantDestroyed = errors.New("keys: the bucket's tenant was destroyed")

// ErrTenantUnopened refuses a bucket whose tenant did not open at startup. Its
// buckets get no other keys; the other tenants are served (ADR-038).
var ErrTenantUnopened = errors.New("keys: the bucket's tenant is not open on this instance")

// BucketKeys are the keys writes to one bucket use.
type BucketKeys struct {
	// Tenant is the tenant the bucket belongs to.
	Tenant string
	// KID is the KEK new data keys are wrapped under.
	KID string
	// NameTenant is the tenant whose name key maps the bucket's object names:
	// Tenant once it is active, the default tenant before. Name is that key,
	// nil when the tenant has none.
	NameTenant string
	Name       *NameKey
}

// BucketKeyProvider is a KeyProvider that also says which keys writes to a
// bucket use. Reads go by the key id an object names, through Unwrap, whoever
// that key belongs to: the data key's associated data binds bucket and key,
// so an object moved to another bucket does not open (FORMAT.md section 6.1).
type BucketKeyProvider interface {
	KeyProvider
	For(bucket string) (BucketKeys, error)
}

// For implements BucketKeyProvider for a keyring without tenants: every
// bucket is the default tenant's.
func (r *Keyring) For(string) (BucketKeys, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return BucketKeys{Tenant: DefaultTenant, KID: r.active, NameTenant: DefaultTenant, Name: r.name}, nil
}

// Served is an opened keyring as the gateway serves it: one KeyProvider over
// the KEKs of the default tenant and of every tenant that opened, and the
// directory, which says for each bucket whose keys its writes use.
//
// It is built once at startup and not changed: a keyring change reaches an
// instance when it restarts (ADR-002, ADR-038).
type Served struct {
	def        *Keyring
	dir        Directory
	generation uint64
	byKID      map[string]*Keyring
	tenants    map[string]*Tenant
}

// NewServed serves an opened file. It takes a snapshot of the directory:
// changes made to f afterwards do not reach it, as a keyring change does not
// reach a running instance.
func NewServed(f *File) *Served {
	s := &Served{
		def: f.Default, generation: f.Generation,
		byKID: map[string]*Keyring{}, tenants: map[string]*Tenant{},
	}
	for _, kid := range f.Default.KIDs() {
		s.byKID[kid] = f.Default
	}
	snap := &File{Default: f.Default, Generation: f.Generation}
	for _, t := range f.Tombstones {
		t.Buckets, t.KIDs, t.Locks = slices.Clone(t.Buckets), slices.Clone(t.KIDs), slices.Clone(t.Locks)
		snap.Tombstones = append(snap.Tombstones, t)
	}
	for _, t := range f.Tenants {
		c := &Tenant{
			Name: t.Name, Buckets: slices.Clone(t.Buckets), ActiveKID: t.ActiveKID,
			KIDs: slices.Clone(t.KIDs), Locks: slices.Clone(t.Locks), Ring: t.Ring, Err: t.Err,
		}
		snap.Tenants = append(snap.Tenants, c)
		s.tenants[c.Name] = c
		if c.Ring == nil {
			continue
		}
		for _, kid := range c.Ring.KIDs() {
			s.byKID[kid] = c.Ring
		}
	}
	s.dir = snap.Directory()
	return s
}

// Default is the default tenant, with the deployment's audit, name and
// freshness keys.
func (s *Served) Default() *Keyring { return s.def }

// Generation is the generation of the keyring file served.
func (s *Served) Generation() uint64 { return s.generation }

// Tenants returns every live tenant, opened or not, in the directory's order.
func (s *Served) Tenants() []*Tenant {
	out := make([]*Tenant, 0, len(s.dir.Tenants))
	for _, d := range s.dir.Tenants {
		out = append(out, s.tenants[d.Name])
	}
	return out
}

// For implements BucketKeyProvider. A bucket of an inactive tenant is written
// under the default tenant's keys, with its names under the default tenant's
// name key: until every instance serves the tenant, none uses it (ADR-038,
// rule 1).
func (s *Served) For(bucket string) (BucketKeys, error) {
	name, destroyed := s.dir.Tenant(bucket)
	if destroyed {
		return BucketKeys{}, fmt.Errorf("%w: %q", ErrTenantDestroyed, name)
	}
	if name == DefaultTenant {
		return s.def.For(bucket)
	}
	t := s.tenants[name]
	if t.Ring == nil {
		return BucketKeys{}, fmt.Errorf("%w: %q", ErrTenantUnopened, name)
	}
	if t.ActiveKID == "" {
		bk, err := s.def.For(bucket)
		bk.Tenant = name
		return bk, err
	}
	nk, _ := t.Ring.NameKey()
	return BucketKeys{Tenant: name, KID: t.ActiveKID, NameTenant: name, Name: nk}, nil
}

// AuditTenant says whose key encrypts the names of an audit entry about bucket
// (FORMAT.md section 14.5): "" for the deployment's, or the bucket's tenant's
// whenever it opened here, active or not. Unlike a bucket's object names,
// nothing needs every instance to agree on it, since a reader tries every key
// it holds; so a tenant's entries are its own from the start, and shredded with
// it. held is false for a tenant destroyed or not opened here.
func (s *Served) AuditTenant(bucket string) (tenant string, held bool) {
	name, destroyed := s.dir.Tenant(bucket)
	switch {
	case destroyed:
		return name, false
	case name == DefaultTenant:
		return "", true
	}
	return name, s.tenants[name].Ring != nil
}

// AuditNameKey returns the key a tenant's audit entries encrypt names under,
// derived from its name key. The caller owns it and should wipe it.
func (s *Served) AuditNameKey(tenant string) ([]byte, error) {
	t := s.tenants[tenant]
	if t == nil || t.Ring == nil {
		return nil, fmt.Errorf("keys: tenant %q is not open here", tenant)
	}
	nk, ok := t.Ring.NameKey()
	if !ok {
		return nil, fmt.Errorf("keys: tenant %q has no name key", tenant)
	}
	return nk.AuditNameKey()
}

// ActiveKID implements KeyProvider with the default tenant's active key. Writes
// to a bucket use For's.
func (s *Served) ActiveKID() string { return s.def.ActiveKID() }

// Wrap implements KeyProvider, under whichever opened tenant holds kid.
func (s *Served) Wrap(ctx context.Context, kid string, dek, aad []byte) ([]byte, error) {
	r, err := s.ring(kid)
	if err != nil {
		return nil, err
	}
	return r.Wrap(ctx, kid, dek, aad)
}

// Unwrap implements KeyProvider, under whichever opened tenant holds kid.
func (s *Served) Unwrap(ctx context.Context, kid string, wrapped, aad []byte) ([]byte, error) {
	r, err := s.ring(kid)
	if err != nil {
		return nil, err
	}
	return r.Unwrap(ctx, kid, wrapped, aad)
}

// TokenKey implements KeyProvider, under whichever opened tenant holds kid.
func (s *Served) TokenKey(ctx context.Context, kid string) ([]byte, error) {
	r, err := s.ring(kid)
	if err != nil {
		return nil, err
	}
	return r.TokenKey(ctx, kid)
}

func (s *Served) ring(kid string) (*Keyring, error) {
	r, ok := s.byKID[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	return r, nil
}

var (
	_ BucketKeyProvider = (*Keyring)(nil)
	_ BucketKeyProvider = (*Served)(nil)
)
