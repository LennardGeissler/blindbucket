package keys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// keyringVersion is the on-disk format version of a keyring file.
const keyringVersion = 1

// Keyring holds the key-encryption keys of a deployment in memory and wraps data
// keys under them locally.
//
// Holding the KEKs in memory is the point of the three-level hierarchy: the
// keyring is decrypted once at startup, and wrapping a data key afterwards costs
// no network round trip and no per-object key service call. See
// docs/adr/ADR-002-key-hierarchy.md.
//
// A Keyring is safe for concurrent use.
type Keyring struct {
	mu      sync.RWMutex
	active  string
	keks    map[string][KeySize]byte
	created map[string]time.Time
	// audit is the optional audit-log key. A keyring written before audit
	// logging existed has none, which is why it is a pointer and why every
	// reader has to handle its absence rather than assume a zero key.
	audit *AuditKey
	// name is the optional object-name key, for the same reason: a keyring
	// written before name encryption existed has none. It is absent rather than
	// zero so that a gateway configured to encrypt names against such a keyring
	// fails at startup instead of encrypting everything under a key of zeroes.
	name *NameKey
	// freshness is the optional rollback-index key, absent for the same reason
	// and handled the same way (ADR-018).
	freshness *FreshnessKey
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{
		keks:    make(map[string][KeySize]byte),
		created: make(map[string]time.Time),
	}
}

// Generate adds a fresh random KEK under kid. The first key added becomes
// active.
func (r *Keyring) Generate(kid string) error {
	var kek [KeySize]byte
	if _, err := rand.Read(kek[:]); err != nil {
		return err
	}
	return r.Add(kid, kek[:])
}

// Add inserts an existing KEK. The first key added becomes active.
func (r *Keyring) Add(kid string, kek []byte) error {
	if err := ValidateKID(kid); err != nil {
		return err
	}
	if len(kek) != KeySize {
		return fmt.Errorf("keys: KEK %q is %d bytes, want %d", kid, len(kek), KeySize)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keks[kid]; exists {
		return fmt.Errorf("keys: key id %q already exists", kid)
	}
	var stored [KeySize]byte
	copy(stored[:], kek)
	r.keks[kid] = stored
	r.created[kid] = time.Now().UTC()
	if r.active == "" {
		r.active = kid
	}
	return nil
}

// Remove deletes a KEK from the keyring.
//
// This is the second half of rotation, and the half that actually retires a
// key: `rotate` moves objects onto a new KEK but leaves the old one in the
// keyring, where it keeps opening everything it ever wrapped. Until it is gone,
// a compromised KEK is still a working KEK.
//
// It is refused for the active key -- removing what new objects are being
// wrapped under would break the next write -- and for the last key, which would
// leave a keyring that cannot be loaded at all. What it cannot check is whether
// objects still reference kid: that lives in the bucket, not here, and it is
// why the caller is expected to have run a rotation first.
func (r *Keyring) Remove(kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.keks[kid]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	switch {
	case kid == r.active:
		return fmt.Errorf("keys: %q is the active key; make another key active before removing it", kid)
	case len(r.keks) == 1:
		return fmt.Errorf("keys: %q is the only key in the keyring", kid)
	}
	// Zero the map slot before deleting it. The value is an array, so it is
	// stored in the map's own memory and this overwrites the key material
	// itself; as everywhere else, the garbage collector may still hold a copy
	// made earlier (ADR-002).
	r.keks[kid] = [KeySize]byte{}
	delete(r.keks, kid)
	delete(r.created, kid)
	return nil
}

// SetActive selects the KEK new data keys are wrapped under.
func (r *Keyring) SetActive(kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.keks[kid]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	r.active = kid
	return nil
}

// SetAuditKey installs the audit-log key, replacing any existing one.
func (r *Keyring) SetAuditKey(k *AuditKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit = k
}

// SetNameKey installs the object-name key, replacing any existing one.
func (r *Keyring) SetNameKey(k *NameKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.name = k
}

// SetFreshnessKey installs the rollback-index key, replacing any existing one.
func (r *Keyring) SetFreshnessKey(k *FreshnessKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.freshness = k
}

// FreshnessKey returns the rollback-index key, and whether the keyring has one.
func (r *Keyring) FreshnessKey() (*FreshnessKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.freshness, r.freshness != nil
}

// NameKey returns the object-name key, and whether the keyring has one.
func (r *Keyring) NameKey() (*NameKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.name, r.name != nil
}

// AuditKey returns the audit-log key, and whether the keyring has one.
func (r *Keyring) AuditKey() (*AuditKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.audit, r.audit != nil
}

// ActiveKID implements KeyProvider.
func (r *Keyring) ActiveKID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// KIDs returns every key id in the keyring, sorted.
func (r *Keyring) KIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.keks))
	for kid := range r.keks {
		out = append(out, kid)
	}
	sort.Strings(out)
	return out
}

// Created reports when a key was added.
func (r *Keyring) Created(kid string) (time.Time, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.created[kid]
	return t, ok
}

// Wrap implements KeyProvider.
func (r *Keyring) Wrap(_ context.Context, kid string, dek, aad []byte) ([]byte, error) {
	kek, err := r.lookup(kid)
	if err != nil {
		return nil, err
	}
	return sealKey(kek[:], dek, aad)
}

// Unwrap implements KeyProvider.
func (r *Keyring) Unwrap(_ context.Context, kid string, wrapped, aad []byte) ([]byte, error) {
	kek, err := r.lookup(kid)
	if err != nil {
		return nil, err
	}
	return openKey(kek[:], wrapped, aad)
}

func (r *Keyring) lookup(kid string) ([KeySize]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	kek, ok := r.keks[kid]
	if !ok {
		return [KeySize]byte{}, fmt.Errorf("%w: %q", ErrUnknownKID, kid)
	}
	return kek, nil
}

// A compile-time assertion that the keyring is a usable KeyProvider.
var _ KeyProvider = (*Keyring)(nil)

// KDFParams describes how a passphrase is stretched into the root key that
// protects a keyring file.
type KDFParams struct {
	Algorithm   string `json:"algorithm"`
	Salt        string `json:"salt"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}

// DefaultKDFParams follows the second recommended option of RFC 9106: 64 MiB of
// memory, three passes, four lanes. The memory cost is what makes a stolen
// keyring file expensive to attack offline.
var DefaultKDFParams = KDFParams{
	Algorithm:   "argon2id",
	Time:        3,
	MemoryKiB:   64 * 1024,
	Parallelism: 4,
}

// Bounds on KDF parameters read from a file.
//
// A keyring file is untrusted input: it may have been written by someone else,
// or tampered with. Without these bounds a file could ask for 100 GiB of memory
// and turn opening it into a denial of service against the reader.
const (
	maxKDFMemoryKiB   = 1 << 20 // 1 GiB
	maxKDFTime        = 16
	maxKDFParallelism = 16
	kdfSaltSize       = 16
)

func (p KDFParams) validate() error {
	switch {
	case p.Algorithm != "argon2id":
		return fmt.Errorf("keys: unsupported KDF %q", p.Algorithm)
	case p.Time == 0 || p.Time > maxKDFTime:
		return fmt.Errorf("keys: KDF time %d outside 1..%d", p.Time, maxKDFTime)
	case p.MemoryKiB == 0 || p.MemoryKiB > maxKDFMemoryKiB:
		return fmt.Errorf("keys: KDF memory %d KiB outside 1..%d", p.MemoryKiB, maxKDFMemoryKiB)
	case p.Parallelism == 0 || p.Parallelism > maxKDFParallelism:
		return fmt.Errorf("keys: KDF parallelism %d outside 1..%d", p.Parallelism, maxKDFParallelism)
	}
	return nil
}

// deriveRootKey stretches a passphrase into the key that wraps the KEKs.
func (p KDFParams) deriveRootKey(passphrase []byte) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil {
		return nil, fmt.Errorf("keys: KDF salt is not valid base64: %w", err)
	}
	if len(salt) < kdfSaltSize {
		return nil, fmt.Errorf("keys: KDF salt is %d bytes, want at least %d", len(salt), kdfSaltSize)
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Parallelism, KeySize), nil
}

// keyringFile is the on-disk representation. Only wrapped key material appears
// in it; the root key exists solely in memory, derived from the passphrase.
type keyringFile struct {
	Version   int    `json:"version"`
	ActiveKID string `json:"active_kid"`
	// RootKey says where the root key comes from. Absent in files written
	// before service-backed sources existed, which are passphrase keyrings --
	// that is what KDF below is for, and it is written only for those.
	RootKey RootKeyRef `json:"root_key,omitempty"`
	// A pointer, so a service-sealed keyring omits it entirely rather than
	// carrying a zeroed Argon2id block it can never use: encoding/json's
	// omitempty does nothing for a struct value.
	KDF  *KDFParams `json:"kdf,omitempty"`
	Keys []keyEntry `json:"keys"`
	// Audit is the audit-log key, absent in a keyring that has none. It is
	// optional rather than a format version bump so that a keyring written
	// before audit logging existed keeps loading unchanged.
	Audit *auditEntry `json:"audit_key,omitempty"`

	// Name is the wrapped object-name key, absent in a keyring written before
	// name encryption existed.
	Name *nameEntry `json:"name_key,omitempty"`

	// Freshness is the optional rollback-index key, absent from every keyring
	// written before ADR-018.
	Freshness *freshnessEntry `json:"freshness_key,omitempty"`
}

// auditEntry is the audit key as it is stored: the secret wrapped under the root
// key, and the Ed25519 public key in clear.
//
// The public half is unprotected on purpose -- it is what lets someone verify a
// log without being handed anything that can write one. It is not therefore
// unchecked: openKeyring re-derives it from the unwrapped secret and refuses a
// file where the two disagree, so an attacker who swaps in a public key they
// hold cannot make a forged log verify against this keyring.
// nameEntry is the wrapped object-name key. Unlike auditEntry it records
// nothing in clear: a name key has no public half, so there is nothing about it
// an unwrapping could be checked against, and nothing worth an attacker's edit
// that the AEAD does not already catch.
type freshnessEntry struct {
	Wrapped string `json:"wrapped"`
}

type nameEntry struct {
	Wrapped string `json:"wrapped"`
}

type auditEntry struct {
	Wrapped   string `json:"wrapped"`
	PublicKey string `json:"public_key"`
}

type keyEntry struct {
	KID     string    `json:"kid"`
	Created time.Time `json:"created"`
	Wrapped string    `json:"wrapped"`
}

// Marshal renders the keyring as a file, with every KEK wrapped under a root key
// derived from passphrase.
func (r *Keyring) Marshal(passphrase []byte, params KDFParams) ([]byte, error) {
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

	return r.marshal(rootKey, RootKeyRef{Source: SourcePassphrase}, &params)
}

// MarshalWithRootKey renders the keyring under a root key held elsewhere.
//
// ref records what has to be asked to get that key back, and is written into
// the file. The caller owns rootKey and should wipe it.
func (r *Keyring) MarshalWithRootKey(rootKey []byte, ref RootKeyRef) ([]byte, error) {
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	if err := ref.validate(); err != nil {
		return nil, err
	}
	if ref.Source == SourcePassphrase || ref.Source == "" {
		return nil, fmt.Errorf("keys: MarshalWithRootKey needs a service-backed source")
	}
	return r.marshal(rootKey, ref, nil)
}

func (r *Keyring) marshal(rootKey []byte, ref RootKeyRef, params *KDFParams) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == "" {
		return nil, fmt.Errorf("keys: refusing to write an empty keyring")
	}

	file := keyringFile{
		Version: keyringVersion, ActiveKID: r.active, RootKey: ref, KDF: params,
	}
	for _, kid := range sortedKeys(r.keks) {
		aad, err := kekAAD(kid)
		if err != nil {
			return nil, err
		}
		kek := r.keks[kid]
		wrapped, err := sealKey(rootKey, kek[:], aad)
		if err != nil {
			return nil, err
		}
		file.Keys = append(file.Keys, keyEntry{
			KID:     kid,
			Created: r.created[kid],
			Wrapped: base64.StdEncoding.EncodeToString(wrapped),
		})
	}

	if r.audit != nil {
		entry, err := sealAudit(rootKey, r.audit)
		if err != nil {
			return nil, err
		}
		file.Audit = entry
	}

	if r.name != nil {
		entry, err := sealName(rootKey, r.name)
		if err != nil {
			return nil, err
		}
		file.Name = entry
	}

	if r.freshness != nil {
		entry, err := sealFreshness(rootKey, r.freshness)
		if err != nil {
			return nil, err
		}
		file.Freshness = entry
	}

	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// sealFreshness wraps the rollback-index key.
func sealFreshness(rootKey []byte, key *FreshnessKey) (*freshnessEntry, error) {
	secret := key.Secret()
	defer clear(secret)
	wrapped, err := sealKey(rootKey, secret, freshnessAAD())
	if err != nil {
		return nil, err
	}
	return &freshnessEntry{Wrapped: base64.StdEncoding.EncodeToString(wrapped)}, nil
}

// openFreshness unwraps the rollback-index key.
func openFreshness(entry *freshnessEntry, rootKey []byte, wrongKeyHint string) (*FreshnessKey, error) {
	wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("keys: the freshness key is not valid base64: %w", err)
	}
	secret, err := openKey(rootKey, wrapped, freshnessAAD())
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, wrongKeyHint)
	}
	defer clear(secret)
	return FreshnessKeyFromSecret(secret)
}

// sealName wraps the object-name key.
func sealName(rootKey []byte, key *NameKey) (*nameEntry, error) {
	secret := key.Secret()
	defer clear(secret)
	wrapped, err := sealKey(rootKey, secret, nameAAD())
	if err != nil {
		return nil, err
	}
	return &nameEntry{Wrapped: base64.StdEncoding.EncodeToString(wrapped)}, nil
}

// openName unwraps the object-name key.
func openName(entry *nameEntry, rootKey []byte, wrongKeyHint string) (*NameKey, error) {
	wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("keys: the name key is not valid base64: %w", err)
	}
	secret, err := openKey(rootKey, wrapped, nameAAD())
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, wrongKeyHint)
	}
	defer clear(secret)
	return NameKeyFromSecret(secret)
}

// sealAudit wraps the audit secret and records its public key.
func sealAudit(rootKey []byte, key *AuditKey) (*auditEntry, error) {
	secret := key.Secret()
	defer clear(secret)
	wrapped, err := sealKey(rootKey, secret, auditAAD())
	if err != nil {
		return nil, err
	}
	pub, err := key.Public()
	if err != nil {
		return nil, err
	}
	return &auditEntry{
		Wrapped:   base64.StdEncoding.EncodeToString(wrapped),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// parseKeyringFile decodes and version-checks a keyring file.
func parseKeyringFile(data []byte) (keyringFile, error) {
	var file keyringFile
	if err := json.Unmarshal(data, &file); err != nil {
		return keyringFile{}, fmt.Errorf("keys: keyring is not valid JSON: %w", err)
	}
	if file.Version != keyringVersion {
		return keyringFile{}, fmt.Errorf("keys: keyring version %d, this build supports %d",
			file.Version, keyringVersion)
	}
	if len(file.Keys) == 0 {
		return keyringFile{}, fmt.Errorf("keys: keyring contains no keys")
	}
	return file, nil
}

// LoadKeyring parses a keyring file and unwraps its KEKs with passphrase.
//
// The key id is authenticated as associated data, so an attacker who reorders or
// relabels entries in the file cannot make a KEK load under a different id.
func LoadKeyring(data, passphrase []byte) (*Keyring, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	if src := file.RootKey.Source; src != "" && src != SourcePassphrase {
		return nil, fmt.Errorf(
			"keys: this keyring's root key comes from %s, not from a passphrase", src)
	}

	if file.KDF == nil {
		return nil, fmt.Errorf("keys: this keyring records no KDF parameters")
	}
	rootKey, err := file.KDF.deriveRootKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(rootKey)
	return openKeyring(file, rootKey, "wrong passphrase, or the keyring was modified")
}

// LoadKeyringWithRootKey unwraps a keyring whose root key came from elsewhere.
//
// It is the same operation as LoadKeyring past the KDF: Vault and KMS replace
// how the root key is obtained, not what it protects or how. The caller owns
// rootKey and should wipe it.
func LoadKeyringWithRootKey(data, rootKey []byte) (*Keyring, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	if len(rootKey) != KeySize {
		return nil, fmt.Errorf("keys: root key is %d bytes, want %d", len(rootKey), KeySize)
	}
	return openKeyring(file, rootKey, "the root key does not open this keyring")
}

// openKeyring unwraps every KEK in a parsed file under rootKey.
func openKeyring(file keyringFile, rootKey []byte, wrongKeyHint string) (*Keyring, error) {
	ring := NewKeyring()
	for _, entry := range file.Keys {
		aad, err := kekAAD(entry.KID)
		if err != nil {
			return nil, err
		}
		wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("keys: key %q is not valid base64: %w", entry.KID, err)
		}
		kek, err := openKey(rootKey, wrapped, aad)
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", err, wrongKeyHint)
		}
		if err := ring.Add(entry.KID, kek); err != nil {
			clear(kek)
			return nil, err
		}
		clear(kek)
		// Add stamped the key with the current time, which is right for a key
		// being created and wrong for one being read back. A file that records
		// no date -- every keyring written before the field existed -- leaves
		// the key's age unknown, and saying so beats reporting today.
		if entry.Created.IsZero() {
			delete(ring.created, entry.KID)
		} else {
			ring.created[entry.KID] = entry.Created
		}
	}

	if err := ring.SetActive(file.ActiveKID); err != nil {
		return nil, fmt.Errorf("keys: active key id %q is not in the keyring", file.ActiveKID)
	}
	if file.Audit != nil {
		audit, err := openAudit(file.Audit, rootKey, wrongKeyHint)
		if err != nil {
			return nil, err
		}
		ring.audit = audit
	}
	if file.Name != nil {
		name, err := openName(file.Name, rootKey, wrongKeyHint)
		if err != nil {
			return nil, err
		}
		ring.name = name
	}
	if file.Freshness != nil {
		freshness, err := openFreshness(file.Freshness, rootKey, wrongKeyHint)
		if err != nil {
			return nil, err
		}
		ring.freshness = freshness
	}
	return ring, nil
}

// openAudit unwraps the audit secret and checks the recorded public key against
// it.
//
// The check is the reason the public key can be stored in clear: without it, an
// attacker who can edit the keyring file could replace the public key with one
// whose private half they hold, and a log they signed would then verify against
// this keyring. The secret itself is authenticated by its AEAD, so they cannot
// change that instead.
func openAudit(entry *auditEntry, rootKey []byte, wrongKeyHint string) (*AuditKey, error) {
	wrapped, err := base64.StdEncoding.DecodeString(entry.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("keys: the audit key is not valid base64: %w", err)
	}
	secret, err := openKey(rootKey, wrapped, auditAAD())
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, wrongKeyHint)
	}
	defer clear(secret)

	audit, err := AuditKeyFromSecret(secret)
	if err != nil {
		return nil, err
	}
	pub, err := audit.Public()
	if err != nil {
		return nil, err
	}
	recorded, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keys: the audit public key is not valid base64: %w", err)
	}
	if !bytes.Equal(pub, recorded) {
		return nil, fmt.Errorf(
			"keys: the audit public key in this keyring does not belong to its audit secret; " +
				"the file has been modified")
	}
	return audit, nil
}

// PublicAuditKey reads the audit public key out of a keyring file without
// opening it.
//
// It needs no root key, which is what makes it useful: an operator can publish
// the key an auditor will verify against without the auditor ever holding
// anything that opens the keyring. What it cannot do is authenticate the value
// it read -- the file is untrusted until a root key opens it. Whoever verifies a
// log against a key obtained this way is trusting the same file an attacker
// would have edited; the key belongs in the operator's own records, and that is
// what `blindbucket audit pubkey` prints it for.
func PublicAuditKey(data []byte) (ed25519.PublicKey, error) {
	file, err := parseKeyringFile(data)
	if err != nil {
		return nil, err
	}
	if file.Audit == nil {
		return nil, ErrNoAuditKey
	}
	pub, err := base64.StdEncoding.DecodeString(file.Audit.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keys: the audit public key is not valid base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keys: the audit public key is %d bytes, want %d",
			len(pub), ed25519.PublicKeySize)
	}
	return pub, nil
}

func sortedKeys(m map[string][KeySize]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
