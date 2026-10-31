package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/rootkey"
)

// newRootKeySource builds the source a configuration names.
//
// Returns nil for provider "file", which needs no service: the root key is
// derived from a passphrase inside the process.
func newRootKeySource(cfg config.Keys) (rootkey.Source, error) {
	switch cfg.Provider {
	case "", "file":
		return nil, nil
	case "vault":
		return rootkey.NewVault(rootkey.VaultConfig{
			Address:   cfg.Vault.Address,
			Token:     cfg.Vault.Token,
			Mount:     cfg.Vault.Mount,
			KeyName:   cfg.Vault.KeyName,
			Namespace: cfg.Vault.Namespace,
		})
	case "awskms":
		kcfg := rootkey.KMSConfig{
			Region:   cfg.AWSKMS.Region,
			KeyID:    cfg.AWSKMS.KeyID,
			Endpoint: cfg.AWSKMS.Endpoint,
			Context:  cfg.AWSKMS.EncryptionContext,
		}
		creds, err := awsCredentials(cfg.AWSKMS.CredentialSource, cfg.AWSKMS.Region)
		if err != nil {
			return nil, fmt.Errorf("keys.awskms.credential_source %q: %w", cfg.AWSKMS.CredentialSource, err)
		}
		if creds != nil {
			kcfg.Credentials = creds
		} else {
			kcfg.AccessKeyID, kcfg.SecretAccessKey, kcfg.SessionToken =
				cfg.AWSKMS.AccessKeyID, cfg.AWSKMS.SecretAccessKey, cfg.AWSKMS.SessionToken
		}
		return rootkey.NewKMS(kcfg)
	default:
		return nil, fmt.Errorf("unknown keys.provider %q", cfg.Provider)
	}
}

// openKeyring reads a keyring file and unlocks it by whatever sealed it.
//
// The file says which source that was, and the configuration says how to reach
// it. Disagreement between the two is an error: falling back to a passphrase
// prompt for a Vault-sealed keyring would ask the operator for something that
// cannot work, and silently using a configured service on a passphrase keyring
// would fail with no explanation. This is the single place all three commands
// open a keyring, so the rule is stated once.
func openKeyring(ctx context.Context, path string, cfg config.Keys, pass *passphraseFlags) (*keys.Keyring, error) {
	ring, _, err := openKeyringFile(ctx, path, cfg, pass)
	return ring, err
}

// openKeyringFile is openKeyring for a command that will write the keyring
// back: it also returns the bytes it opened, which replaceKeyring compares the
// file against before replacing it.
func openKeyringFile(
	ctx context.Context, path string, cfg config.Keys, pass *passphraseFlags,
) (*keys.Keyring, []byte, error) {
	warnIfExposed("keyring", path)
	//nolint:gosec // the path comes from the operator's own configuration.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, keyringReadError(path, err)
	}
	ring, err := unlockKeyring(ctx, path, data, cfg, pass)
	if err != nil {
		return nil, nil, err
	}
	return ring, data, nil
}

// unlockKeyring opens keyring bytes by whatever sealed them.
//
// It opens the default tenant only, and refuses a keyring with tenants
// (keys.ErrKeyringHasTenants). Only encrypt and decrypt still open the
// keyring this way; the gateway and every other command open it whole, with
// openFile or openServedKeyring.
func unlockKeyring(
	ctx context.Context, path string, data []byte, cfg config.Keys, pass *passphraseFlags,
) (*keys.Keyring, error) {
	return unlock(ctx, path, data, cfg, pass, keys.LoadKeyring, keys.LoadKeyringWithRootKey)
}

// unlock opens keyring bytes with the deployment's root key, from a passphrase
// or from the service the file names, by withPassphrase or withRootKey.
func unlock[T any](
	ctx context.Context, path string, data []byte, cfg config.Keys, pass *passphraseFlags,
	withPassphrase func(data, passphrase []byte) (T, error), withRootKey func(data, rootKey []byte) (T, error),
) (T, error) {
	var none T
	ref, err := keys.ReadRootKeyRef(data)
	if err != nil {
		return none, fmt.Errorf("%s is not a keyring this build can read (keys.keyring): %w", path, err)
	}

	if ref.Source == keys.SourcePassphrase {
		if cfg.Provider != "" && cfg.Provider != "file" {
			return none, fmt.Errorf(
				"%s is sealed with a passphrase, but keys.provider is %q", path, cfg.Provider)
		}
		phrase, err := pass.resolve("Passphrase for "+path+": ", false)
		if err != nil {
			return none, err
		}
		defer clear(phrase)
		opened, err := withPassphrase(data, phrase)
		if errors.Is(err, keys.ErrUnwrap) {
			return none, fmt.Errorf("%s: %w; check the passphrase -- $%s, keys.passphrase_file "+
				"or --passphrase-file", path, err, passphraseEnv)
		}
		return opened, err
	}

	source, err := newRootKeySource(cfg)
	if err != nil {
		return none, err
	}
	if source == nil {
		return none, fmt.Errorf(
			"%s is sealed by %s, but keys.provider is %q; configure that provider to open it",
			path, ref.Source, cfg.Provider)
	}

	root, err := source.RootKey(ctx, ref)
	if err != nil {
		return none, fmt.Errorf("%s could not be unsealed: %w; %s", path, err, unsealFix(cfg))
	}
	defer clear(root)
	return withRootKey(data, root)
}

// openFile reads a keyring file, of either version, for a command that may
// write it back: it returns the bytes it opened as well, which replaceKeyring
// compares the file against. Tenants open as roots allows.
func openFile(
	ctx context.Context, path string, cfg config.Keys, pass *passphraseFlags, roots *tenantRoots,
) (*keys.File, []byte, error) {
	warnIfExposed("keyring", path)
	//nolint:gosec // the path comes from the operator's own configuration.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, keyringReadError(path, err)
	}
	f, err := unlockFile(ctx, path, data, cfg, pass, roots)
	if err != nil {
		return nil, nil, err
	}
	return f, data, nil
}

// unlockFile opens keyring bytes of either version whole.
func unlockFile(
	ctx context.Context, path string, data []byte, cfg config.Keys, pass *passphraseFlags, roots *tenantRoots,
) (*keys.File, error) {
	return unlock(ctx, path, data, cfg, pass,
		func(data, phrase []byte) (*keys.File, error) {
			return keys.OpenFileWithPassphrase(data, phrase, roots.root)
		},
		func(data, root []byte) (*keys.File, error) { return keys.OpenFile(data, root, roots.root) })
}

// errNotNeeded is why a tenant a command did not ask for stays unopened.
var errNotNeeded = errors.New("not opened: this command does not need it")

// tenantRoots obtains tenants' root keys from the keys.tenants section of a
// configuration.
//
// A command that changes one tenant opens only that one, so it asks no other
// tenant's key service and prompts for no other passphrase; the others are
// written back as they were read. A passphrase is asked for once per command
// and remembered until wipe, the way passphraseFlags does it for the
// deployment.
type tenantRoots struct {
	ctx context.Context
	cfg map[string]config.Keys
	// only, when not nil, names the tenants to open; the rest stay unopened.
	only map[string]bool
	// prompt allows asking the terminal for a tenant's passphrase when its
	// passphrase_file is not set.
	prompt  bool
	phrases map[string]*passphraseFlags
}

// openTenants opens every tenant the configuration can, prompting for none.
func openTenants(ctx context.Context, cfg config.Keys) *tenantRoots {
	return &tenantRoots{ctx: ctx, cfg: cfg.Tenants}
}

// openTenant opens only the named tenants, prompting for a passphrase if one
// is needed; with no names, it opens none but those under the deployment's
// lock, which open with the deployment.
func openTenant(ctx context.Context, cfg config.Keys, names ...string) *tenantRoots {
	r := &tenantRoots{ctx: ctx, cfg: cfg.Tenants, only: map[string]bool{}, prompt: true}
	for _, n := range names {
		r.only[n] = true
	}
	return r
}

// root implements keys.TenantRootFunc.
func (r *tenantRoots) root(name string, ref keys.RootKeyRef, kdf *keys.KDFParams) ([]byte, error) {
	if r.only != nil && !r.only[name] {
		return nil, errNotNeeded
	}
	tc, ok := r.cfg[name]
	if !ok {
		return nil, fmt.Errorf("keys.tenants.%s is not configured, so the lock of tenant %q (%s) "+
			"cannot be opened here", name, name, describeRootKey(ref))
	}
	if want := providerFor(ref.Source); tc.Provider != want {
		return nil, fmt.Errorf("tenant %q is sealed by %s, but keys.tenants.%s.provider is %q",
			name, describeRootKey(ref), name, tc.Provider)
	}
	if ref.Source == keys.SourcePassphrase {
		if kdf == nil {
			return nil, fmt.Errorf("tenant %q records no KDF parameters", name)
		}
		phrase, err := r.passphrase(name, tc, false)
		if err != nil {
			return nil, err
		}
		defer clear(phrase)
		return kdf.DeriveRootKey(phrase)
	}
	source, err := newRootKeySource(tc)
	if err != nil {
		return nil, fmt.Errorf("keys.tenants.%s: %w", name, err)
	}
	root, err := source.RootKey(r.ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("tenant %q could not be unsealed: %w; %s", name, err,
			strings.ReplaceAll(unsealFix(tc), "keys.", "keys.tenants."+name+"."))
	}
	return root, nil
}

// newLock seals a new root key for a tenant under the source its entry in
// keys.tenants names. The caller wipes the lock.
func (r *tenantRoots) newLock(name string) (keys.TenantLock, error) {
	tc, ok := r.cfg[name]
	if !ok {
		return keys.TenantLock{}, fmt.Errorf("keys.tenants.%s is not configured: it names the lock "+
			"tenant %q is sealed under", name, name)
	}
	if tc.Provider == "file" {
		phrase, err := r.passphrase(name, tc, true)
		if err != nil {
			return keys.TenantLock{}, err
		}
		defer clear(phrase)
		return keys.PassphraseLock(phrase, keys.DefaultKDFParams)
	}
	source, err := newRootKeySource(tc)
	if err != nil {
		return keys.TenantLock{}, fmt.Errorf("keys.tenants.%s: %w", name, err)
	}
	root, err := keys.NewRootKey()
	if err != nil {
		return keys.TenantLock{}, err
	}
	defer clear(root)
	ref, err := source.Encrypt(r.ctx, root)
	if err != nil {
		return keys.TenantLock{}, fmt.Errorf("sealing tenant %q's root key: %w", name, err)
	}
	return keys.ServiceLock(root, ref)
}

// passphrase returns a tenant's passphrase, from its passphrase_file or, where
// allowed, the terminal; never from $BLINDBUCKET_PASSPHRASE, which is the
// deployment's.
func (r *tenantRoots) passphrase(name string, tc config.Keys, confirm bool) ([]byte, error) {
	if r.phrases == nil {
		r.phrases = map[string]*passphraseFlags{}
	}
	p, ok := r.phrases[name]
	if !ok {
		if tc.PassphraseFile == "" && !r.prompt {
			return nil, fmt.Errorf("keys.tenants.%s.passphrase_file is not set", name)
		}
		p = &passphraseFlags{file: tc.PassphraseFile, noEnv: true}
		r.phrases[name] = p
	}
	return p.resolve("Passphrase for tenant "+name+": ", confirm)
}

// wipe forgets every passphrase asked for.
func (r *tenantRoots) wipe() {
	for _, p := range r.phrases {
		p.wipe()
	}
}

// providerFor names the keys.provider that opens a root-key source.
func providerFor(source string) string {
	switch source {
	case keys.SourceVaultTransit:
		return "vault"
	case keys.SourceAWSKMS:
		return "awskms"
	default:
		return "file"
	}
}

// keyringReadError says what to do about a keyring file that cannot be read.
func keyringReadError(path string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the keyring (keys.keyring): %w; `blindbucket init` "+
			"or `blindbucket keygen --out %s` creates one", err, path)
	}
	return fmt.Errorf("the keyring %s (keys.keyring): %w; the user this runs as must be able "+
		"to read it", path, err)
}

// unsealFix names what to check when a root-key service would not unseal a
// keyring: the service's own error says what it refused, not where that is
// configured.
func unsealFix(cfg config.Keys) string {
	switch cfg.Provider {
	case "vault":
		return fmt.Sprintf("check keys.vault.address and keys.vault.token, and that the token "+
			"may decrypt with the Transit key %q under keys.vault.mount", cfg.Vault.KeyName)
	case "awskms":
		return fmt.Sprintf("check keys.awskms.region and its credentials, and that they may "+
			"kms:Decrypt with %s", cfg.AWSKMS.KeyID)
	}
	return "check the keys section"
}

// warnIfExposed reports a key file that more than its owner can read.
//
// A warning rather than a refusal: the file may be deliberately group-readable
// for a service account, and refusing to start over it would be the gateway
// deciding an operator's deployment for them. But a keyring whose permissions
// were never narrowed is the ordinary way a passphrase stops being worth
// anything, and nothing here used to say so -- THREAT_MODEL section 5.5 asks
// for exactly this and left it to the reader.
//
// Written to stderr rather than the log, because every command that opens a
// keyring should say it, and only one of them has a logger.
func warnIfExposed(kind, path string) {
	info, err := os.Stat(path) //nolint:gosec // the operator's own key file; only its mode is read.
	if err != nil || !info.Mode().IsRegular() {
		// Not readable, or not a file. Whatever the caller does next will
		// report that properly.
		return
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		fmt.Fprintf(os.Stderr,
			"warning: %s %s is mode %04o -- readable beyond its owner. `chmod 600 %s`\n",
			kind, path, mode, path)
	}
}
