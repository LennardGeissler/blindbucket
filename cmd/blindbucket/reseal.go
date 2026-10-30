package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// errSamePassphrase refuses a passphrase change to the passphrase the keyring
// already has. It would be harmless -- a fresh salt, nothing else -- and it is
// still refused, because the operator who ran it believes the passphrase
// changed.
var errSamePassphrase = errors.New("the new passphrase is the one the keyring already has; " +
	"nothing would change")

func runReseal(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reseal", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket reseal --keyring <file> [--config <file>] [--to-config <file>] [flags]

Seals a keyring under a different root-key source: a passphrase, Vault Transit
or AWS KMS, in any direction, or a new passphrase. --config names the source
the keyring is sealed with now and --to-config the one to seal it with; either
left out means a passphrase. The keys inside do not change, and no object is
touched.

Before the file is replaced, what was written is opened again with the new
source and compared key by key with what was read. A source that can seal but
not unseal -- a KMS key policy or Vault policy allowing encrypt and not decrypt
-- is caught there, and nothing is written. --dry-run stops after that check:
it asks the new source to seal and to unseal, and writes nothing.

The file is replaced in place and no backup is kept, because a backup would
be a second way into the same keys (ADR-013, ADR-023). For the same reason:
any copy of the old file that exists elsewhere still opens with the old source.
Reseal changes the lock and not the keys, so against a root key or passphrase
that may already be out, the remedy is a new KEK, rotate and keys remove.

Afterwards, every instance's configuration has to name the new source before
it restarts; one that does not refuses to start and says which source the
keyring needs.

With --tenant, the tenant's own lock is moved instead: --config names how it is
sealed now, under keys.tenants, and --to-config's keys.tenants entry for it the
lock to seal it with. The deployment and every other tenant stay as they are.
The old lock stays in the tenant's lock history (ADR-038): every copy of the
file from before still opens the tenant with it, so destroying the tenant means
destroying that lock too.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		keyring = fs.String("keyring", "", "keyring file to reseal (required)")
		tenant  = fs.String("tenant", "",
			"reseal this tenant instead of the deployment, under the lock --to-config's keys.tenants names for it")
		conf = fs.String("config", "",
			"configuration naming the source the keyring is sealed with now (default: a passphrase)")
		toConf = fs.String("to-config", "",
			"configuration naming the source to seal it with (default: a passphrase)")
		dryRun  = fs.Bool("dry-run", false, "seal and unseal with the new source, write nothing")
		pass    passphraseFlags
		newPass passphraseFlags
	)
	pass.register(fs)
	newPass.registerNew(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	defer newPass.wipe()
	if *keyring == "" {
		fs.Usage()
		return errors.New("--keyring is required")
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}

	from, err := keysConfig(*conf, &pass)
	if err != nil {
		return err
	}
	if *tenant != "" {
		if *toConf == "" {
			fs.Usage()
			return fmt.Errorf("--tenant needs --to-config, whose keys.tenants.%s names the new lock", *tenant)
		}
		if newPass.file != "" {
			return fmt.Errorf("--new-passphrase-file is the deployment's new passphrase; with --tenant, "+
				"the tenant's comes from --to-config's keys.tenants.%s.passphrase_file", *tenant)
		}
		to, err := keysConfig(*toConf, &passphraseFlags{})
		if err != nil {
			return err
		}
		return resealTenant(ctx, *keyring, *tenant, from, to, &pass, *dryRun)
	}
	to, err := keysConfig(*toConf, &newPass)
	if err != nil {
		return err
	}

	// Only the deployment's lock changes. Tenants under it are sealed again
	// with it; tenants with locks of their own are written back as they are,
	// so none of their locks is asked for.
	f, opened, err := openFile(ctx, *keyring, from, &pass, openTenant(ctx, from))
	if err != nil {
		return err
	}
	ring := f.Default
	before, err := keys.ReadRootKeyRef(opened)
	if err != nil {
		return err
	}

	sealed, err := sealKeyring(ctx, f, to, &newPass, true)
	if err != nil {
		return fmt.Errorf("sealing under %s: %w", sealedBy(to), err)
	}
	if before.Source == keys.SourcePassphrase && isPassphrase(to) &&
		subtle.ConstantTimeCompare(pass.resolved, newPass.resolved) == 1 {
		return errSamePassphrase
	}

	// The check the command rests on. A keyring that has been sealed is not yet
	// a keyring that can be opened: a service may encrypt for a principal it
	// will not decrypt for, and finding that out after the file was replaced
	// is finding it out with every object locked away.
	reopened, err := unlockFile(ctx, *keyring, sealed, to, &newPass, openTenant(ctx, to))
	if err != nil {
		return fmt.Errorf("%s sealed the keyring but cannot open it again (%w); "+
			"nothing was written -- check that the configured credentials may decrypt "+
			"as well as encrypt", sealedBy(to), err)
	}
	if !f.Equal(reopened) {
		return fmt.Errorf("the keyring sealed under %s opened with different keys; "+
			"nothing was written", sealedBy(to))
	}

	after, err := keys.ReadRootKeyRef(sealed)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(os.Stderr, "would reseal %s from %s to %s: sealed and opened again, "+
			"%s unchanged; nothing written\n",
			*keyring, describeRootKey(before), describeRootKey(after), countKeys(ring))
		return nil
	}

	if err := replaceKeyring(*keyring, opened, sealed); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "resealed %s from %s to %s: %s unchanged, active %q\n"+
		"  Every instance's keys section must name the new source before it restarts.\n"+
		"  Any other copy of the previous file still opens with %s.\n",
		*keyring, describeRootKey(before), describeRootKey(after),
		countKeys(ring), ring.ActiveKID(), describeRootKey(before))
	return nil
}

// resealTenant moves one tenant to the lock to's keys.tenants entry names, as
// the deployment's reseal does for the deployment (ADR-038). The deployment
// stays sealed as it is, and so does every other tenant.
func resealTenant(
	ctx context.Context, path, name string, from, to config.Keys, pass *passphraseFlags, dryRun bool,
) error {
	fromRoots := openTenant(ctx, from, name)
	defer fromRoots.wipe()
	toRoots := openTenant(ctx, to, name)
	defer toRoots.wipe()

	f, opened, err := openFile(ctx, path, from, pass, fromRoots)
	if err != nil {
		return err
	}
	t := f.Tenant(name)
	if t == nil {
		return fmt.Errorf("%s has no tenant %q (see `blindbucket tenants list`)", path, name)
	}
	if t.Ring == nil {
		return fmt.Errorf("tenant %q did not open with its current lock (%w); a reseal needs it", name, t.Err)
	}
	before := t.Lock()

	lock, err := toRoots.newLock(name)
	if err != nil {
		return err
	}
	defer lock.Wipe()
	if before.Source == keys.SourcePassphrase && to.Tenants[name].Provider == "file" &&
		subtle.ConstantTimeCompare(fromRoots.phrases[name].resolved, toRoots.phrases[name].resolved) == 1 {
		return errSamePassphrase
	}
	if err := f.Reseal(name, lock); err != nil {
		return err
	}
	after := f.Tenant(name).Lock()

	sealed, err := sealKeyring(ctx, f, from, pass, false)
	if err != nil {
		return err
	}
	// Opened again with the new lock before anything is replaced, for the
	// reason the deployment's reseal does it: a key service that encrypts for
	// these credentials may not decrypt for them.
	reopened, err := unlockFile(ctx, path, sealed, from, pass, toRoots)
	if err != nil {
		return err
	}
	if r := reopened.Tenant(name); r == nil || r.Ring == nil {
		var why error
		if r != nil {
			why = r.Err
		}
		return fmt.Errorf("tenant %q was sealed under %s but does not open with it (%w); "+
			"nothing was written -- check that the credentials in keys.tenants.%s may decrypt "+
			"as well as encrypt", name, describeLock(after), why, name)
	}
	if !f.Equal(reopened) {
		return fmt.Errorf("tenant %q sealed under %s opened with different keys; nothing was written",
			name, describeLock(after))
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "would reseal tenant %s from %s to %s: sealed and opened again, "+
			"%s unchanged; nothing written\n", name, describeLock(before), describeLock(after), countKeys(t.Ring))
		return nil
	}
	if err := replaceKeyring(path, opened, sealed); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "resealed tenant %s in %s from %s to %s: %s unchanged, generation %d\n"+
		"  Every instance's keys.tenants.%s must name the new lock before it restarts.\n"+
		"  Any other copy of the previous file still opens %s with %s. It stays in %s's\n"+
		"  lock history, and destroying %s means destroying it as well.\n",
		name, path, describeLock(before), describeLock(after), countKeys(t.Ring), f.Generation+1,
		name, name, describeLock(before), name, name)
	return nil
}

// countKeys says how many KEKs a keyring holds, for the summary.
func countKeys(ring *keys.Keyring) string {
	if n := len(ring.KIDs()); n != 1 {
		return fmt.Sprintf("%d keys", n)
	}
	return "1 key"
}

func isPassphrase(cfg config.Keys) bool {
	return cfg.Provider == "" || cfg.Provider == "file"
}

// describeLock names a tenant's lock, from the directory's record of it.
func describeLock(l keys.Lock) string {
	switch l.Source {
	case keys.LockDeployment:
		return "the deployment's lock"
	case keys.SourcePassphrase:
		return "a passphrase"
	}
	return describeRootKey(keys.RootKeyRef{Source: l.Source, KeyName: l.KeyName})
}

// describeRootKey names what seals a keyring, from the file's own record of it.
func describeRootKey(ref keys.RootKeyRef) string {
	switch ref.Source {
	case keys.SourceVaultTransit:
		return "Vault Transit key " + ref.KeyName
	case keys.SourceAWSKMS:
		return "AWS KMS key " + ref.KeyName
	default:
		return "a passphrase"
	}
}
