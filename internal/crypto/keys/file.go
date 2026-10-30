package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// ErrKeyringHasTenants is what LoadKeyring returns for a version 2 file. The
// gateway and the commands that read and write objects open a keyring with
// LoadKeyring, and until they route a bucket to its tenant's keys they must not
// open one with tenants: opening only the default tenant would wrap every
// tenant's buckets under the default tenant's keys (ADR-038).
var ErrKeyringHasTenants = errors.New("keys: this keyring has tenants (version 2), which the gateway " +
	"and the object commands do not serve yet; only tenants, keys, keygen and reseal open it")

// File is a keyring file opened whole, version 1 or 2: the default tenant and,
// with tenants, the directory and every tenant's keys.
//
// It is what a command that rewrites the keyring works on. Each change is
// checked when it is made, and Marshal writes the file again as generation
// Generation+1. A tenant's section is written back as it was read unless the
// change needs it sealed afresh, so a command needs only the deployment's root
// key, and the root keys of the tenants it changes.
type File struct {
	// Default is the default tenant, with the deployment's audit and
	// freshness keys, exactly as a version 1 file opens.
	Default *Keyring
	// Generation is the generation the file was read at; 0 for version 1.
	Generation uint64
	// Tenants are the live tenants, in the directory's order.
	Tenants    []*Tenant
	Tombstones []Tombstone
}

// Tenant is a live tenant of an opened keyring.
type Tenant struct {
	Name    string
	Buckets []string
	// ActiveKID is the key its buckets' writes are wrapped under, "" while it
	// is not active and they still use the default tenant's.
	ActiveKID string
	KIDs      []string
	// Locks is every lock the tenant has been sealed under, oldest first; the
	// last is the current one.
	Locks []Lock
	// Ring holds the tenant's KEKs and name key, or is nil when the tenant did
	// not open, and Err says why.
	Ring *Keyring
	Err  error

	section tenantSection // as read
	seal    *TenantLock   // set when the section is to be sealed under a new lock
}

// Lock returns the tenant's current lock.
func (t *Tenant) Lock() Lock { return t.Locks[len(t.Locks)-1] }

// TenantLock is what a tenant's section is sealed under: a root key of its
// own, from a key service or a passphrase, or the deployment's (the zero
// value).
type TenantLock struct {
	rootKey []byte
	ref     *RootKeyRef
	kdf     *KDFParams
}

// DeploymentLock seals a tenant under the deployment's root key: keys of its
// own, but any copy of the file that the deployment's root key opens opens
// them too.
func DeploymentLock() TenantLock { return TenantLock{} }

// ServiceLock seals a tenant under rootKey, which ref says how to obtain from
// Vault Transit or AWS KMS. It copies rootKey; Wipe clears the copy.
func ServiceLock(rootKey []byte, ref RootKeyRef) (TenantLock, error) {
	if len(rootKey) != KeySize {
		return TenantLock{}, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	if ref.Source == SourcePassphrase || ref.Source == "" {
		return TenantLock{}, fmt.Errorf("keys: ServiceLock needs a service-backed source")
	}
	if err := ref.validate(); err != nil {
		return TenantLock{}, err
	}
	return TenantLock{rootKey: slices.Clone(rootKey), ref: &ref}, nil
}

// PassphraseLock seals a tenant under a root key stretched from passphrase
// with a fresh salt. Wipe clears the root key.
func PassphraseLock(passphrase []byte, params KDFParams) (TenantLock, error) {
	if len(passphrase) == 0 {
		return TenantLock{}, fmt.Errorf("keys: refusing to seal a tenant without a passphrase")
	}
	params.Algorithm = "argon2id"
	salt := make([]byte, kdfSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return TenantLock{}, err
	}
	params.Salt = base64.StdEncoding.EncodeToString(salt)
	root, err := params.deriveRootKey(passphrase)
	if err != nil {
		return TenantLock{}, err
	}
	return TenantLock{rootKey: root, kdf: &params}, nil
}

// Wipe clears the lock's root key.
func (l TenantLock) Wipe() { clear(l.rootKey) }

// record is the lock as the directory records it.
func (l TenantLock) record() Lock {
	switch {
	case l.kdf != nil:
		return Lock{Source: SourcePassphrase, Salt: l.kdf.Salt}
	case l.ref != nil:
		return Lock{Source: l.ref.Source, KeyName: l.ref.KeyName}
	default:
		return Lock{Source: LockDeployment}
	}
}

// TenantRootFunc obtains a tenant's root key from what its section records
// about its lock: the service's reference, or for a passphrase the KDF
// parameters, with ref.Source "passphrase". OpenFile wipes what it returns.
type TenantRootFunc func(tenant string, ref RootKeyRef, kdf *KDFParams) ([]byte, error)

// OpenFile opens a keyring file of either version with the deployment's root
// key, and each tenant with the root key tenantRoot returns for it. A tenant
// under the deployment's lock opens with the deployment's root key. One whose
// root key cannot be obtained, or whose section does not open, has a nil Ring
// and its reason in Err (FORMAT.md section 18.6). The caller owns rootKey.
func OpenFile(data, rootKey []byte, tenantRoot TenantRootFunc) (*File, error) {
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	return openFile(data, file, rootKey, tenantRoot, "the root key does not open this keyring")
}

// OpenFileWithPassphrase is OpenFile for a keyring sealed by a passphrase.
func OpenFileWithPassphrase(data, passphrase []byte, tenantRoot TenantRootFunc) (*File, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	if src := file.RootKey.Source; src != "" && src != SourcePassphrase {
		return nil, fmt.Errorf("keys: this keyring's root key comes from %s, not from a passphrase", src)
	}
	if file.KDF == nil {
		return nil, fmt.Errorf("keys: this keyring records no KDF parameters")
	}
	rootKey, err := file.KDF.deriveRootKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(rootKey)
	return openFile(data, file, rootKey, tenantRoot, "wrong passphrase, or the keyring was modified")
}

func openFile(data []byte, base keyringFile, rootKey []byte, tenantRoot TenantRootFunc, hint string) (*File, error) {
	def, err := openKeyring(base, rootKey, hint)
	if err != nil {
		return nil, err
	}
	if base.Version == keyringVersion {
		return &File{Default: def}, nil
	}

	var file keyringFileV2
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("keys: keyring is not valid JSON: %w", err)
	}
	if file.Directory == "" {
		return nil, fmt.Errorf("%w: no directory", ErrKeyringMalformed)
	}
	wrapped, err := base64.StdEncoding.DecodeString(file.Directory)
	if err != nil {
		return nil, fmt.Errorf("%w: the directory is not valid base64", ErrKeyringMalformed)
	}
	plain, err := openKey(rootKey, wrapped, []byte(aadDirectory))
	if err != nil {
		return nil, fmt.Errorf("%w: the directory does not open: %w", ErrKeyringMalformed, err)
	}
	var dir Directory
	err = json.Unmarshal(plain, &dir)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("%w: the directory is not valid JSON: %w", ErrKeyringMalformed, err)
	}
	if dir.Generation != file.Generation {
		return nil, fmt.Errorf("%w: generation %d in the directory, %d in the file",
			ErrKeyringMalformed, dir.Generation, file.Generation)
	}
	if err := dir.validate(def.KIDs()); err != nil {
		return nil, err
	}

	sections := map[string]tenantSection{}
	for _, s := range file.Tenants {
		if _, dup := sections[s.Name]; dup {
			return nil, fmt.Errorf("%w: two sections for tenant %q", ErrKeyringMalformed, s.Name)
		}
		sections[s.Name] = s
	}
	if len(sections) != len(dir.Tenants) {
		return nil, fmt.Errorf("%w: %d tenants in the directory, %d sections",
			ErrKeyringMalformed, len(dir.Tenants), len(sections))
	}
	for _, t := range dir.Tenants {
		s, ok := sections[t.Name]
		if !ok {
			return nil, fmt.Errorf("%w: no section for tenant %q", ErrKeyringMalformed, t.Name)
		}
		var have []string
		for _, e := range s.Keys {
			have = append(have, e.KID)
		}
		slices.Sort(have)
		want := slices.Sorted(slices.Values(t.KIDs))
		if !slices.Equal(have, want) {
			return nil, fmt.Errorf("%w: tenant %q's section holds keys %v, the directory lists %v",
				ErrKeyringMalformed, t.Name, have, want)
		}
		if s.NameKey == nil {
			return nil, fmt.Errorf("%w: tenant %q's section has no name key", ErrKeyringMalformed, t.Name)
		}
		if !s.matchesLock(t.Locks[len(t.Locks)-1]) {
			return nil, fmt.Errorf("%w: tenant %q's section is not sealed by its recorded lock",
				ErrKeyringMalformed, t.Name)
		}
	}

	out := &File{Default: def, Generation: dir.Generation, Tombstones: dir.Tombstones}
	for _, d := range dir.Tenants {
		t := &Tenant{
			Name: d.Name, Buckets: d.Buckets, ActiveKID: d.ActiveKID, KIDs: d.KIDs, Locks: d.Locks,
			section: sections[d.Name],
		}
		t.Ring, t.Err = openTenant(t, rootKey, tenantRoot)
		out.Tenants = append(out.Tenants, t)
	}
	return out, nil
}

// openTenant opens one tenant's section, with the deployment's root key or the
// one tenantRoot returns.
func openTenant(t *Tenant, rootKey []byte, tenantRoot TenantRootFunc) (*Keyring, error) {
	if t.Lock().Source == LockDeployment {
		return openSection(t.section, t.ActiveKID, rootKey)
	}
	if tenantRoot == nil {
		return nil, fmt.Errorf("keys: tenant %q: no root key for its lock", t.Name)
	}
	ref := RootKeyRef{Source: SourcePassphrase}
	if t.section.RootKey != nil {
		ref = *t.section.RootKey
		if err := ref.validate(); err != nil {
			return nil, fmt.Errorf("keys: tenant %q: %w", t.Name, err)
		}
	}
	root, err := tenantRoot(t.Name, ref, t.section.KDF)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	return openSection(t.section, t.ActiveKID, root)
}

func openSection(s tenantSection, active string, rootKey []byte) (*Keyring, error) {
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: tenant %q: root key is %d bytes, want %d", s.Name, len(rootKey), KeySize)
	}
	ring := NewKeyring()
	for _, e := range s.Keys {
		aad, err := tenantKEKAAD(s.Name, e.KID)
		if err != nil {
			return nil, err
		}
		wrapped, err := base64.StdEncoding.DecodeString(e.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("keys: tenant %q: key %q is not valid base64", s.Name, e.KID)
		}
		kek, err := openKey(rootKey, wrapped, aad)
		if err != nil {
			return nil, fmt.Errorf("keys: tenant %q: %w", s.Name, err)
		}
		err = ring.Add(e.KID, kek)
		clear(kek)
		if err != nil {
			return nil, err
		}
		if e.Created.IsZero() {
			delete(ring.created, e.KID)
		} else {
			ring.created[e.KID] = e.Created
		}
	}
	// Add made the first key active; a tenant is active only as the
	// directory says.
	ring.active = active
	aad, err := tenantNameAAD(s.Name)
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(s.NameKey.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("keys: tenant %q: the name key is not valid base64", s.Name)
	}
	secret, err := openKey(rootKey, wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("keys: tenant %q: the name key: %w", s.Name, err)
	}
	defer clear(secret)
	name, err := NameKeyFromSecret(secret)
	if err != nil {
		return nil, err
	}
	ring.name = name
	return ring, nil
}

// Directory returns the directory as it now stands.
func (f *File) Directory() Directory {
	d := Directory{Generation: f.Generation, Tombstones: f.Tombstones}
	for _, t := range f.Tenants {
		d.Tenants = append(d.Tenants, DirectoryTenant{
			Name: t.Name, Buckets: t.Buckets, KIDs: t.KIDs, ActiveKID: t.ActiveKID, Locks: t.Locks,
		})
	}
	return d
}

// Tenant returns the live tenant called name, or nil.
func (f *File) Tenant(name string) *Tenant {
	for _, t := range f.Tenants {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// KIDOwner reports which tenant, live or destroyed, holds a key id. Key ids
// are unique across the keyring, and a destroyed tenant's are never issued
// again.
func (f *File) KIDOwner(kid string) (string, bool) {
	if _, ok := f.Default.Created(kid); ok {
		return DefaultTenant, true
	}
	for _, t := range f.Tenants {
		if slices.Contains(t.KIDs, kid) {
			return t.Name, true
		}
	}
	for _, t := range f.Tombstones {
		if slices.Contains(t.KIDs, kid) {
			return t.Name, true
		}
	}
	return "", false
}

// checkEntries refuses bucket entries that are malformed, or that overlap
// each other or any tenant's, live or destroyed.
func (f *File) checkEntries(entries []string) error {
	type owned struct{ entry, tenant string }
	var taken []owned
	for _, t := range f.Tenants {
		for _, e := range t.Buckets {
			taken = append(taken, owned{e, t.Name})
		}
	}
	for _, t := range f.Tombstones {
		for _, e := range t.Buckets {
			taken = append(taken, owned{e, t.Name + " (destroyed)"})
		}
	}
	for i, e := range entries {
		if !validBucketEntry(e) {
			return fmt.Errorf("keys: %q is neither a bucket name (3 to 63 of a-z 0-9 . -) "+
				"nor a prefix of one ending in *", e)
		}
		for _, o := range taken {
			if overlap(o.entry, e) {
				return fmt.Errorf("keys: %q overlaps %q, which is tenant %s's; "+
					"a bucket belongs to one tenant and never leaves it", e, o.entry, o.tenant)
			}
		}
		for _, prev := range entries[:i] {
			if overlap(prev, e) {
				return fmt.Errorf("keys: %q and %q overlap", prev, e)
			}
		}
	}
	return nil
}

// AddTenant adds a tenant with the keys and name key in ring, sealed under
// lock, owning buckets. It starts inactive: its buckets' writes keep using the
// default tenant's keys until Activate, after every instance serves it
// (ADR-038, rule 1). AddTenant takes ownership of ring and of lock.
func (f *File) AddTenant(name string, buckets []string, ring *Keyring, lock TenantLock) error {
	if err := ValidateTenantName(name); err != nil {
		return err
	}
	if f.Tenant(name) != nil {
		return fmt.Errorf("keys: tenant %q exists", name)
	}
	for _, t := range f.Tombstones {
		if t.Name == name {
			return fmt.Errorf("keys: %q is the name of a destroyed tenant, and stays its", name)
		}
	}
	if _, ok := ring.NameKey(); !ok {
		return fmt.Errorf("keys: tenant %q has no name key", name)
	}
	kids := ring.KIDs()
	if len(kids) == 0 {
		return fmt.Errorf("keys: tenant %q has no keys", name)
	}
	for _, kid := range kids {
		if owner, used := f.KIDOwner(kid); used {
			return fmt.Errorf("keys: key id %q is %s's; key ids are unique across the keyring", kid, owner)
		}
	}
	if err := f.checkEntries(buckets); err != nil {
		return err
	}
	ring.mu.Lock()
	ring.active = ""
	ring.mu.Unlock()
	t := &Tenant{
		Name: name, Buckets: slices.Clone(buckets), KIDs: kids, Locks: []Lock{lock.record()}, Ring: ring,
	}
	if t.Buckets == nil {
		t.Buckets = []string{}
	}
	if lock.rootKey != nil {
		t.seal = &lock
	}
	f.Tenants = append(f.Tenants, t)
	return nil
}

// Assign adds bucket entries to a live tenant. A bucket joins a tenant from
// the default tenant and never leaves it (ADR-038).
func (f *File) Assign(name string, entries []string) error {
	t, err := f.live(name)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("keys: no buckets to assign")
	}
	if err := f.checkEntries(entries); err != nil {
		return err
	}
	t.Buckets = append(t.Buckets, entries...)
	return nil
}

// Activate makes kid the key a tenant's buckets are written under; "" picks
// the tenant's only key. The tenant has to have opened: activating keys
// nothing has checked would make every write to its buckets depend on them.
func (f *File) Activate(name, kid string) error {
	t, err := f.live(name)
	if err != nil {
		return err
	}
	if t.Ring == nil {
		return fmt.Errorf("keys: tenant %q did not open here (%w), and is activated only where it does", name, t.Err)
	}
	if kid == "" {
		if len(t.KIDs) != 1 {
			return fmt.Errorf("keys: tenant %q has %d keys; say which to activate", name, len(t.KIDs))
		}
		kid = t.KIDs[0]
	}
	if !slices.Contains(t.KIDs, kid) {
		return fmt.Errorf("keys: tenant %q has no key %q", name, kid)
	}
	if t.ActiveKID == kid {
		return fmt.Errorf("keys: tenant %q is already active with %q; nothing would change", name, kid)
	}
	t.ActiveKID = kid
	t.Ring.mu.Lock()
	t.Ring.active = kid
	t.Ring.mu.Unlock()
	return nil
}

// Reseal moves a tenant to another lock, as reseal moves the deployment
// (ADR-023). The keys stay the same, and the old lock stays in the tenant's
// history: every copy of the file from before still opens with it, and a
// destruction has to destroy it too. The tenant has to have opened. Reseal
// takes ownership of lock.
func (f *File) Reseal(name string, lock TenantLock) error {
	t, err := f.live(name)
	if err != nil {
		return err
	}
	if t.Ring == nil {
		return fmt.Errorf("keys: tenant %q did not open (%w); a reseal needs its current lock", name, t.Err)
	}
	rec := lock.record()
	if rec == t.Lock() {
		return fmt.Errorf("keys: tenant %q is already sealed by that lock; nothing would change", name)
	}
	t.Locks = append(slices.Clone(t.Locks), rec)
	t.seal = nil
	if lock.rootKey != nil {
		t.seal = &lock
	}
	return nil
}

func (f *File) live(name string) (*Tenant, error) {
	if name == DefaultTenant {
		return nil, fmt.Errorf("keys: the default tenant holds every bucket no tenant claims; it is not changed this way")
	}
	if t := f.Tenant(name); t != nil {
		return t, nil
	}
	for _, t := range f.Tombstones {
		if t.Name == name {
			return nil, fmt.Errorf("keys: tenant %q was destroyed on %s", name, t.Destroyed.Format("2006-01-02"))
		}
	}
	return nil, fmt.Errorf("keys: no tenant %q", name)
}

// Marshal writes the file again, with every secret of the deployment wrapped
// under a root key derived from passphrase.
func (f *File) Marshal(passphrase []byte, params KDFParams) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("keys: refusing to write a keyring without a passphrase")
	}
	params.Algorithm = "argon2id"
	if params.Salt == "" {
		salt := make([]byte, kdfSaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		params.Salt = base64.StdEncoding.EncodeToString(salt)
	}
	rootKey, err := params.deriveRootKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(rootKey)
	return f.marshal(rootKey, RootKeyRef{Source: SourcePassphrase}, &params)
}

// MarshalWithRootKey writes the file again under a root key held by a key
// service; ref records how to obtain it. The caller owns rootKey.
func (f *File) MarshalWithRootKey(rootKey []byte, ref RootKeyRef) ([]byte, error) {
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	if ref.Source == SourcePassphrase || ref.Source == "" {
		return nil, fmt.Errorf("keys: MarshalWithRootKey needs a service-backed source")
	}
	return f.marshal(rootKey, ref, nil)
}

// marshal writes version 1 while there are no tenants and no tombstones, so a
// deployment that never uses them can still downgrade, and version 2 at
// generation Generation+1 otherwise. A tenant under the deployment's lock is
// sealed again under rootKey, one moved to a new lock under that lock, and
// every other section is written back as it was read.
func (f *File) marshal(rootKey []byte, ref RootKeyRef, params *KDFParams) ([]byte, error) {
	if len(f.Tenants) == 0 && len(f.Tombstones) == 0 {
		return f.Default.marshal(rootKey, ref, params)
	}
	base, err := f.Default.buildFile(rootKey, ref, params)
	if err != nil {
		return nil, err
	}
	dir := f.Directory()
	dir.Generation = f.Generation + 1
	var sections []tenantSection
	for _, t := range f.Tenants {
		var s tenantSection
		switch {
		case t.Lock().Source == LockDeployment:
			if t.Ring == nil {
				return nil, fmt.Errorf("keys: tenant %q is under the deployment's lock and did not open (%w); "+
					"the keyring cannot be written without it", t.Name, t.Err)
			}
			s, err = sealSection(t.Name, t.Ring, rootKey, nil, nil)
		case t.seal != nil:
			s, err = sealSection(t.Name, t.Ring, t.seal.rootKey, t.seal.ref, t.seal.kdf)
		default:
			s = t.section
		}
		if err != nil {
			return nil, err
		}
		if !s.matchesLock(t.Lock()) {
			return nil, fmt.Errorf("keys: tenant %q: its section is not sealed by its current lock", t.Name)
		}
		sections = append(sections, s)
	}
	return writeV2(base, rootKey, sections, dir, f.Default.KIDs())
}

// Equal reports whether two opened files hold the same keyring: the same
// default tenant, the same tenants with the same buckets, keys, active key
// and locks, each opened in both to the same keys or in neither, and the same
// tombstones. The generation is not compared; every write changes it.
//
// It is reseal's check, as Keyring.Equal is for a keyring without tenants.
func (f *File) Equal(g *File) bool {
	if !f.Default.Equal(g.Default) || len(f.Tenants) != len(g.Tenants) {
		return false
	}
	for i, a := range f.Tenants {
		b := g.Tenants[i]
		if a.Name != b.Name || a.ActiveKID != b.ActiveKID || !slices.Equal(a.Buckets, b.Buckets) ||
			!slices.Equal(a.KIDs, b.KIDs) || !slices.Equal(a.Locks, b.Locks) {
			return false
		}
		if (a.Ring == nil) != (b.Ring == nil) || a.Ring != nil && !a.Ring.Equal(b.Ring) {
			return false
		}
	}
	return slices.EqualFunc(f.Tombstones, g.Tombstones, func(a, b Tombstone) bool {
		return a.Name == b.Name && slices.Equal(a.Buckets, b.Buckets) && slices.Equal(a.KIDs, b.KIDs) &&
			slices.Equal(a.Locks, b.Locks) && a.Destroyed.Equal(b.Destroyed)
	})
}
