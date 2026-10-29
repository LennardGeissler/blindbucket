package keys

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Version 2 of the keyring file: tenants (docs/FORMAT.md section 18,
// docs/adr/ADR-038-tenants-and-crypto-shredding.md).
//
// Nothing outside this package uses it yet. LoadKeyring still refuses a version
// 2 file, and has to until the gateway routes a bucket's writes to its tenant: a
// reader that opened the default tenant and ignored the rest would wrap the
// tenants' buckets under the default tenant's keys.

const (
	keyringVersion2 = 2

	// DefaultTenant names the tenant every bucket belongs to that no other
	// tenant claims. It holds what a version 1 keyring holds, and no tenant may
	// take its name.
	DefaultTenant = "default"

	// LockDeployment is the lock of a tenant sealed under the deployment's own
	// root key: keys of its own, but no lock of its own.
	LockDeployment = "deployment"

	aadDirectory        = "blindbucket/v1/directory"
	aadTenantKEKPrefix  = "blindbucket/v1/tenant-kek"
	aadTenantNamePrefix = "blindbucket/v1/tenant-name-key"
)

// ErrKeyringMalformed reports a version 2 file that breaks a rule of FORMAT.md
// section 18.6: a failure of the whole file, visible without any key but the
// deployment's, after which nothing in it says reliably which bucket is whose.
var ErrKeyringMalformed = errors.New("keys: malformed keyring")

// Lock is what seals a tenant's section (FORMAT.md section 18.3).
type Lock struct {
	Source  string `json:"source"`
	KeyName string `json:"key_name,omitempty"`
	Salt    string `json:"salt,omitempty"`
}

// DirectoryTenant is a live tenant as the directory records it.
type DirectoryTenant struct {
	Name      string   `json:"name"`
	Buckets   []string `json:"buckets"`
	KIDs      []string `json:"kids"`
	ActiveKID string   `json:"active_kid"`
	// Locks is every lock the tenant's section has been sealed under, oldest
	// first; the last is the current one.
	Locks []Lock `json:"locks"`
}

// Tombstone is a destroyed tenant. It keeps the tenant's buckets refused and
// its key ids from ever being issued again.
type Tombstone struct {
	Name      string    `json:"name"`
	Buckets   []string  `json:"buckets"`
	KIDs      []string  `json:"kids"`
	Locks     []Lock    `json:"locks"`
	Destroyed time.Time `json:"destroyed"`
}

// Directory is the sealed part of a version 2 keyring: which tenants exist,
// which buckets are theirs, and which locks they ever had.
type Directory struct {
	Generation uint64            `json:"generation"`
	Tenants    []DirectoryTenant `json:"tenants"`
	Tombstones []Tombstone       `json:"tombstones"`
}

// tenantSection is a tenant's own part of the file, sealed under its lock.
type tenantSection struct {
	Name    string      `json:"name"`
	RootKey *RootKeyRef `json:"root_key,omitempty"`
	KDF     *KDFParams  `json:"kdf,omitempty"`
	Keys    []keyEntry  `json:"keys"`
	NameKey *nameEntry  `json:"name_key,omitempty"`
}

// keyringFileV2 is a version 1 file with the directory and the sections added.
type keyringFileV2 struct {
	keyringFile
	Generation uint64          `json:"generation"`
	Directory  string          `json:"directory"`
	Tenants    []tenantSection `json:"tenants"`
}

// Tenant resolves a bucket to its tenant (FORMAT.md section 18.5): the live
// tenant whose bucket entry matches, DefaultTenant if none does, and destroyed
// set when the matching entry is a tombstone's.
func (d Directory) Tenant(bucket string) (name string, destroyed bool) {
	for _, t := range d.Tenants {
		if matchesAny(t.Buckets, bucket) {
			return t.Name, false
		}
	}
	for _, t := range d.Tombstones {
		if matchesAny(t.Buckets, bucket) {
			return t.Name, true
		}
	}
	return DefaultTenant, false
}

func matchesAny(entries []string, bucket string) bool {
	for _, e := range entries {
		if prefix, ok := strings.CutSuffix(e, "*"); ok {
			if strings.HasPrefix(bucket, prefix) {
				return true
			}
		} else if e == bucket {
			return true
		}
	}
	return false
}

// validBucketEntry reports whether e is a bucket name, 3 to 63 bytes of
// a-z 0-9 . -, or a prefix of 1 to 62 such bytes followed by '*'.
func validBucketEntry(e string) bool {
	body, prefix := strings.CutSuffix(e, "*")
	lo, hi := 3, 63
	if prefix {
		lo, hi = 1, 62
	}
	if len(body) < lo || len(body) > hi {
		return false
	}
	for i := range len(body) {
		c := body[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// overlap reports whether two bucket entries can match the same bucket.
func overlap(a, b string) bool {
	pa, aPrefix := strings.CutSuffix(a, "*")
	pb, bPrefix := strings.CutSuffix(b, "*")
	switch {
	case aPrefix && bPrefix:
		return strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
	case aPrefix:
		return strings.HasPrefix(b, pa)
	case bPrefix:
		return strings.HasPrefix(a, pb)
	default:
		return a == b
	}
}

// validTenantName applies the key id's shape (FORMAT.md section 3.1), and
// keeps the default tenant's name for the default tenant.
func validTenantName(name string) error {
	if name == DefaultTenant {
		return fmt.Errorf("%w: %q names the default tenant", ErrKeyringMalformed, name)
	}
	if err := ValidateKID(name); err != nil {
		return fmt.Errorf("%w: tenant name %q: %w", ErrKeyringMalformed, name, err)
	}
	return nil
}

// validate checks the directory against FORMAT.md section 18.6, given the
// default tenant's key ids. It needs no key.
func (d Directory) validate(defaultKIDs []string) error {
	names := map[string]bool{}
	kids := map[string]string{}
	for _, kid := range defaultKIDs {
		kids[kid] = DefaultTenant
	}
	var entries []string
	claim := func(tenant string, tkids, buckets []string) error {
		if err := validTenantName(tenant); err != nil {
			return err
		}
		if names[tenant] {
			return fmt.Errorf("%w: tenant %q is listed twice", ErrKeyringMalformed, tenant)
		}
		names[tenant] = true
		if len(tkids) == 0 {
			return fmt.Errorf("%w: tenant %q has no keys", ErrKeyringMalformed, tenant)
		}
		for _, kid := range tkids {
			if err := ValidateKID(kid); err != nil {
				return fmt.Errorf("%w: %w", ErrKeyringMalformed, err)
			}
			if owner, dup := kids[kid]; dup {
				return fmt.Errorf("%w: key id %q is used by %q and %q", ErrKeyringMalformed, kid, owner, tenant)
			}
			kids[kid] = tenant
		}
		for _, e := range buckets {
			if !validBucketEntry(e) {
				return fmt.Errorf("%w: tenant %q: %q is not a bucket name or prefix", ErrKeyringMalformed, tenant, e)
			}
			for _, prev := range entries {
				if overlap(prev, e) {
					return fmt.Errorf("%w: bucket entries %q and %q overlap", ErrKeyringMalformed, prev, e)
				}
			}
			entries = append(entries, e)
		}
		return nil
	}
	for _, t := range d.Tenants {
		if err := claim(t.Name, t.KIDs, t.Buckets); err != nil {
			return err
		}
		if t.ActiveKID != "" && !slices.Contains(t.KIDs, t.ActiveKID) {
			return fmt.Errorf("%w: tenant %q: active key %q is not one of its keys", ErrKeyringMalformed, t.Name, t.ActiveKID)
		}
		if len(t.Locks) == 0 {
			return fmt.Errorf("%w: tenant %q has no lock", ErrKeyringMalformed, t.Name)
		}
	}
	for _, t := range d.Tombstones {
		if err := claim(t.Name, t.KIDs, t.Buckets); err != nil {
			return err
		}
	}
	return nil
}

// matchesLock reports whether a section is sealed the way its tenant's current
// lock says.
func (s tenantSection) matchesLock(l Lock) bool {
	source := ""
	switch {
	case s.KDF != nil && (s.RootKey == nil || s.RootKey.Source == SourcePassphrase):
		source = SourcePassphrase
	case s.KDF == nil && s.RootKey == nil:
		source = LockDeployment
	case s.KDF == nil && s.RootKey != nil && s.RootKey.Source != SourcePassphrase:
		source = s.RootKey.Source
	}
	if source == "" || source != l.Source {
		return false
	}
	switch source {
	case SourcePassphrase:
		return s.KDF.Salt == l.Salt
	case LockDeployment:
		return true
	default:
		return s.RootKey.KeyName == l.KeyName
	}
}

// lock reports how a tenant's section is sealed, as its directory entry has
// to record it.
func (s tenantSection) lock() Lock {
	switch {
	case s.KDF != nil:
		return Lock{Source: SourcePassphrase, Salt: s.KDF.Salt}
	case s.RootKey != nil:
		return Lock{Source: s.RootKey.Source, KeyName: s.RootKey.KeyName}
	default:
		return Lock{Source: LockDeployment}
	}
}

func tenantKEKAAD(tenant, kid string) ([]byte, error) {
	aad, err := appendLP([]byte(aadTenantKEKPrefix), tenant)
	if err != nil {
		return nil, err
	}
	return appendLP(aad, kid)
}

func tenantNameAAD(tenant string) ([]byte, error) {
	return appendLP([]byte(aadTenantNamePrefix), tenant)
}

// TenantSeal is what writing one tenant's section takes: its keys, and the
// lock to seal them under.
type TenantSeal struct {
	Name    string
	Buckets []string
	Ring    *Keyring // the tenant's KEKs, its active key and its name key
	// Inactive writes the tenant with no active key: it owns its buckets, but
	// writes to them still use the default tenant's (ADR-038, rule 1).
	Inactive bool
	// RootKey is the tenant's own root key, or the deployment's for a tenant
	// without a lock of its own (RootRef and KDF both nil).
	RootKey []byte
	RootRef *RootKeyRef
	KDF     *KDFParams
	// Previous locks, oldest first, before the current one.
	Previous []Lock
}

// MarshalV2 writes a version 2 keyring: the default tenant under the
// deployment's root key as in version 1, the directory sealed under it, and
// one section per tenant under that tenant's root key.
func MarshalV2(def *Keyring, rootKey []byte, ref RootKeyRef, params *KDFParams,
	generation uint64, tenants []TenantSeal, tombstones []Tombstone,
) ([]byte, error) {
	base, err := def.buildFile(rootKey, ref, params)
	if err != nil {
		return nil, err
	}
	base.Version = keyringVersion2
	file := keyringFileV2{keyringFile: base, Generation: generation}
	dir := Directory{Generation: generation, Tenants: []DirectoryTenant{}, Tombstones: tombstones}
	if dir.Tombstones == nil {
		dir.Tombstones = []Tombstone{}
	}
	for _, t := range tenants {
		section, err := sealSection(t)
		if err != nil {
			return nil, err
		}
		file.Tenants = append(file.Tenants, section)
		active := t.Ring.ActiveKID()
		if t.Inactive {
			active = ""
		}
		dir.Tenants = append(dir.Tenants, DirectoryTenant{
			Name: t.Name, Buckets: t.Buckets, KIDs: t.Ring.KIDs(), ActiveKID: active,
			Locks: append(slices.Clone(t.Previous), section.lock()),
		})
	}
	if file.Tenants == nil {
		file.Tenants = []tenantSection{}
	}
	if len(dir.Tenants) == 0 && len(dir.Tombstones) == 0 {
		return nil, fmt.Errorf("keys: a keyring without tenants or tombstones is written as version 1")
	}
	if err := dir.validate(def.KIDs()); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(dir)
	if err != nil {
		return nil, err
	}
	wrapped, err := sealKey(rootKey, plain, []byte(aadDirectory))
	if err != nil {
		return nil, err
	}
	file.Directory = base64.StdEncoding.EncodeToString(wrapped)
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func sealSection(t TenantSeal) (tenantSection, error) {
	t.Ring.mu.RLock()
	defer t.Ring.mu.RUnlock()
	if t.Ring.name == nil {
		return tenantSection{}, fmt.Errorf("keys: tenant %q has no name key", t.Name)
	}
	section := tenantSection{Name: t.Name, RootKey: t.RootRef, KDF: t.KDF}
	for _, kid := range sortedKeys(t.Ring.keks) {
		aad, err := tenantKEKAAD(t.Name, kid)
		if err != nil {
			return tenantSection{}, err
		}
		kek := t.Ring.keks[kid]
		wrapped, err := sealKey(t.RootKey, kek[:], aad)
		if err != nil {
			return tenantSection{}, err
		}
		section.Keys = append(section.Keys, keyEntry{
			KID: kid, Created: t.Ring.created[kid], Wrapped: base64.StdEncoding.EncodeToString(wrapped),
		})
	}
	secret := t.Ring.name.Secret()
	defer clear(secret)
	aad, err := tenantNameAAD(t.Name)
	if err != nil {
		return tenantSection{}, err
	}
	wrapped, err := sealKey(t.RootKey, secret, aad)
	if err != nil {
		return tenantSection{}, err
	}
	section.NameKey = &nameEntry{Wrapped: base64.StdEncoding.EncodeToString(wrapped)}
	return section, nil
}

// KeyringV2 is an opened version 2 keyring.
type KeyringV2 struct {
	// Default is the default tenant, with the deployment's audit and
	// freshness keys, exactly as a version 1 file would open.
	Default   *Keyring
	Directory Directory
	// Tenants holds each opened tenant's KEKs, active key and name key.
	Tenants map[string]*Keyring
	// Unopened holds, for each tenant that did not open, why. Its keys are
	// never used and its buckets are refused.
	Unopened map[string]error
}

// OpenKeyringV2 opens a version 2 file with the deployment's root key, and
// each tenant with the root key tenantRoot returns for it. A tenant under the
// deployment's lock uses the deployment's root key; one for which tenantRoot
// returns an error, or whose section does not open, is unopened rather than
// fatal (FORMAT.md section 18.6).
func OpenKeyringV2(data, rootKey []byte, tenantRoot func(name string, l Lock) ([]byte, error)) (*KeyringV2, error) {
	var file keyringFileV2
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("keys: keyring is not valid JSON: %w", err)
	}
	if file.Version != keyringVersion2 {
		return nil, fmt.Errorf("keys: keyring version %d, want %d", file.Version, keyringVersion2)
	}
	if len(file.Keys) == 0 {
		return nil, fmt.Errorf("keys: keyring contains no keys")
	}
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	def, err := openKeyring(file.keyringFile, rootKey, "the root key does not open this keyring")
	if err != nil {
		return nil, err
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
	if err := json.Unmarshal(plain, &dir); err != nil {
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

	out := &KeyringV2{Default: def, Directory: dir, Tenants: map[string]*Keyring{}, Unopened: map[string]error{}}
	for _, t := range dir.Tenants {
		lock := t.Locks[len(t.Locks)-1]
		var (
			troot []byte
			err   error
		)
		switch {
		case lock.Source == LockDeployment:
			troot = rootKey
		case tenantRoot == nil:
			out.Unopened[t.Name] = fmt.Errorf("keys: tenant %q: no root key for its lock", t.Name)
			continue
		default:
			troot, err = tenantRoot(t.Name, lock)
		}
		if err != nil {
			out.Unopened[t.Name] = err
			continue
		}
		ring, err := openSection(sections[t.Name], t.ActiveKID, troot)
		if err != nil {
			out.Unopened[t.Name] = err
			continue
		}
		out.Tenants[t.Name] = ring
	}
	return out, nil
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
