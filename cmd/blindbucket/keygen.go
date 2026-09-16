package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

func runKeygen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket keygen --out <file> [flags]

Creates a keyring holding one key-encryption key. By default the root key that
protects it is an Argon2id stretch of a passphrase. With --config naming a
configuration whose keys.provider is "vault" or "awskms", the root key is
random and sealed by that service instead, and the keyring records which one --
so opening it later needs the service, not a passphrase.

Without --add, an existing file is never overwritten: losing a keyring means
losing every object encrypted under it.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		out      = fs.String("out", "", "keyring file to write (required)")
		kid      = fs.String("kid", defaultKID(), "id of the key to create")
		add      = fs.Bool("add", false, "add a key to an existing keyring instead of creating one")
		addAudit = fs.Bool("add-audit-key", false,
			"add an audit-log signing key to an existing keyring; new keyrings get one anyway")
		addName = fs.Bool("add-name-key", false,
			"add an object-name key to an existing keyring; new keyrings get one anyway")
		act  = fs.Bool("activate", true, "with --add, make the new key the active one")
		conf = fs.String("config", "",
			"configuration file naming the root-key provider (default: a passphrase)")
		pass passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	if *out == "" {
		fs.Usage()
		return errors.New("--out is required")
	}
	if err := keys.ValidateKID(*kid); err != nil {
		return err
	}

	keysCfg, err := keysConfig(*conf, &pass)
	if err != nil {
		return err
	}

	switch {
	case (*addAudit || *addName) && !*add:
		return addStandaloneKeys(ctx, *out, *addAudit, *addName, keysCfg, &pass)
	case *add:
		return addKey(ctx, *out, *kid, *act, *addAudit, *addName, keysCfg, &pass)
	}
	return createKeyring(ctx, *out, *kid, keysCfg, &pass)
}

// sealKeyring writes a keyring under whichever root key the configuration names.
//
// The passphrase path and the service path differ only in where the root key
// comes from: Argon2id over something the operator knows, or 32 random bytes
// the service will hand back. What they protect, and how, is identical.
func sealKeyring(
	ctx context.Context, ring *keys.Keyring, cfg config.Keys, pass *passphraseFlags, confirm bool,
) ([]byte, error) {
	source, err := newRootKeySource(cfg)
	if err != nil {
		return nil, err
	}
	if source == nil {
		phrase, err := pass.resolve("Passphrase for the keyring: ", confirm)
		if err != nil {
			return nil, err
		}
		defer clear(phrase)
		return ring.Marshal(phrase, keys.DefaultKDFParams)
	}

	root, err := keys.NewRootKey()
	if err != nil {
		return nil, err
	}
	defer clear(root)

	// The reference comes back from the source rather than being assembled
	// here: what has to be recorded is the service's business, and for KMS it
	// includes the encryption context the ciphertext is bound to.
	ref, err := source.Encrypt(ctx, root)
	if err != nil {
		return nil, err
	}
	return ring.MarshalWithRootKey(root, ref)
}

func createKeyring(
	ctx context.Context, path, kid string, cfg config.Keys, pass *passphraseFlags,
) error {
	// Refuse to clobber. A keyring is the only copy of the keys protecting every
	// object written under it; overwriting one is not recoverable.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists (use --add to add a key to it)", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	ring := keys.NewKeyring()
	if err := ring.Generate(kid); err != nil {
		return err
	}
	// Every new keyring gets an audit key, whether or not audit logging is
	// configured. It is 32 wrapped bytes and inert until something uses it,
	// against the alternative of having to reseal the keyring of a running
	// deployment on the day an audit log is first wanted.
	audit, err := keys.NewAuditKey()
	if err != nil {
		return err
	}
	ring.SetAuditKey(audit)
	// And a name key, on the same reasoning: 32 more wrapped bytes, inert until
	// names are encrypted, against having to reseal a running deployment's
	// keyring on the day they are. Unlike the audit key it has no public half to
	// record, so there is nothing to print.
	name, err := keys.NewNameKey()
	if err != nil {
		return err
	}
	ring.SetNameKey(name)

	data, err := sealKeyring(ctx, ring, cfg, pass, true)
	if err != nil {
		return err
	}
	if err := writeKeyring(path, data); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %s with key %q (active), sealed by %s\n",
		path, kid, sealedBy(cfg))
	return printAuditPublicKey(ring)
}

// printAuditPublicKey tells the operator the value a verifier will need.
//
// Printed at creation because that is the moment it can still be recorded
// somewhere else. A public key retrieved later from the same host as the log is
// worth much less: see ADR-016 and `blindbucket audit pubkey`.
func printAuditPublicKey(ring *keys.Keyring) error {
	key, ok := ring.AuditKey()
	if !ok {
		return nil
	}
	pub, err := key.Public()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr,
		"audit log public key: %s\n"+
			"  Record this somewhere the gateway host does not control. It is what\n"+
			"  verifies an audit log, and it is all that is needed to.\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

// addStandaloneKeys gives an existing keyring an audit key, a name key, or both,
// without adding a KEK.
func addStandaloneKeys(
	ctx context.Context, path string, withAudit, withName bool,
	cfg config.Keys, pass *passphraseFlags,
) error {
	ring, err := openKeyring(ctx, path, cfg, pass)
	if err != nil {
		return err
	}
	if withAudit {
		if err := attachAuditKey(ring, path); err != nil {
			return err
		}
	}
	if withName {
		if err := attachNameKey(ring, path); err != nil {
			return err
		}
	}

	updated, err := sealKeyring(ctx, ring, cfg, pass, false)
	if err != nil {
		return err
	}
	if err := writeKeyring(path, updated); err != nil {
		return err
	}
	if withAudit {
		fmt.Fprintf(os.Stderr, "added an audit key to %s\n", path)
	}
	if withName {
		fmt.Fprintf(os.Stderr, "added an object-name key to %s\n", path)
	}
	if withAudit {
		return printAuditPublicKey(ring)
	}
	return nil
}

// attachAuditKey generates an audit key and installs it, refusing to replace one.
//
// Refused rather than replaced. A new audit key is a new public key, and every
// log written under the old one stops verifying against the keyring -- which is
// indistinguishable, to whoever checks it later, from the logs having been
// forged.
func attachAuditKey(ring *keys.Keyring, path string) error {
	if _, exists := ring.AuditKey(); exists {
		return fmt.Errorf("%s already has an audit key; replacing it would leave every "+
			"log written under the old one unverifiable against this keyring", path)
	}
	audit, err := keys.NewAuditKey()
	if err != nil {
		return err
	}
	ring.SetAuditKey(audit)
	return nil
}

// attachNameKey generates an object-name key and installs it, refusing to
// replace one.
//
// Refused for a harder reason than the audit key's. Every object written while
// names were encrypted is stored under a name derived from this key, and no
// record of the old key remains anywhere: replacing it does not rename those
// objects, it makes them unfindable. Moving to a new name key is a rewrite of
// every object's key, which ADR-015 describes as a migration.
func attachNameKey(ring *keys.Keyring, path string) error {
	if _, exists := ring.NameKey(); exists {
		return fmt.Errorf("%s already has a name key; replacing it would leave every "+
			"object stored under an encrypted name unfindable, because nothing "+
			"records the old key", path)
	}
	name, err := keys.NewNameKey()
	if err != nil {
		return err
	}
	ring.SetNameKey(name)
	return nil
}

// sealedBy names the root-key source for the operator's confirmation line.
func sealedBy(cfg config.Keys) string {
	switch cfg.Provider {
	case "vault":
		return "Vault Transit key " + cfg.Vault.KeyName
	case "awskms":
		return "AWS KMS key " + cfg.AWSKMS.KeyID
	default:
		return "a passphrase"
	}
}

func addKey(
	ctx context.Context, path, kid string, activate, withAudit, withName bool,
	cfg config.Keys, pass *passphraseFlags,
) error {
	ring, err := openKeyring(ctx, path, cfg, pass)
	if err != nil {
		return err
	}
	if err := ring.Generate(kid); err != nil {
		return err
	}
	if activate {
		if err := ring.SetActive(kid); err != nil {
			return err
		}
	}
	if withAudit {
		if err := attachAuditKey(ring, path); err != nil {
			return err
		}
	}
	if withName {
		if err := attachNameKey(ring, path); err != nil {
			return err
		}
	}

	// Re-sealed rather than patched: a new root key on every write means a
	// keyring that is added to does not accumulate ciphertext under one key
	// forever, and for the passphrase case it re-runs the KDF with a new salt.
	updated, err := sealKeyring(ctx, ring, cfg, pass, false)
	if err != nil {
		return err
	}
	if err := writeKeyring(path, updated); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "added key %q to %s (active key: %q)\n", kid, path, ring.ActiveKID())
	if withName {
		fmt.Fprintf(os.Stderr, "added an object-name key to %s\n", path)
	}
	if withAudit {
		return printAuditPublicKey(ring)
	}
	return nil
}

// writeKeyring writes atomically and restrictively: a half-written keyring would
// be unreadable, and a world-readable one defeats the passphrase.
func writeKeyring(path string, data []byte) error {
	tmp := path + ".tmp"
	//nolint:gosec // the path is a command-line argument.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// defaultKID names a key after the month it was created, which is the shape the
// rotation workflow of ADR-009 assumes.
func defaultKID() string { return time.Now().UTC().Format("2006-01") }
