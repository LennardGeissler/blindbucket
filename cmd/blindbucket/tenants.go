package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

func runTenants(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return tenantsUsage()
	}
	switch args[0] {
	case "create":
		return runTenantsCreate(ctx, args[1:])
	case "assign":
		return runTenantsAssign(ctx, args[1:])
	case "activate":
		return runTenantsActivate(ctx, args[1:])
	case "list":
		return runTenantsList(ctx, args[1:])
	case "-h", "--help", "help":
		return tenantsUsage()
	}
	return fmt.Errorf("unknown tenants subcommand %q (try `blindbucket tenants help`)", args[0])
}

func tenantsUsage() error {
	_, _ = fmt.Fprint(os.Stderr, `Usage: blindbucket tenants <subcommand> [flags]

A tenant is a set of buckets with keys of its own, sealed under a lock of its
own, so that it can be deleted by destroying that lock (ADR-038). A bucket no
tenant claims belongs to the default tenant, which holds the keyring's other
keys.

Subcommands:
  create    add a tenant, inactive, with its keys, its lock and its buckets
  assign    give a tenant more buckets, for good
  activate  write a tenant's buckets under its own keys from now on
  list      show the tenants, their buckets, keys and locks

Every change writes the keyring as its next generation. It reaches an instance
when the instance restarts, so roll each change out before the next one:
blindbucket_keyring_generation says which generation each instance serves.

Run "blindbucket tenants <subcommand> -h" for a subcommand's flags.
`)
	return errUsage
}

// tenantsFlags are the flags every tenants subcommand shares.
type tenantsFlags struct {
	fs      *flag.FlagSet
	keyring *string
	conf    *string
	pass    passphraseFlags
}

func newTenantsFlags(name, usage string) *tenantsFlags {
	t := &tenantsFlags{fs: flag.NewFlagSet("tenants "+name, flag.ContinueOnError)}
	t.fs.Usage = func() {
		_, _ = fmt.Fprint(t.fs.Output(), usage+"\nFlags:\n")
		t.fs.PrintDefaults()
	}
	t.keyring = t.fs.String("keyring", "", "keyring file (required)")
	t.conf = t.fs.String("config", "",
		"configuration naming the root-key provider, and under keys.tenants each tenant's lock")
	t.pass.register(t.fs)
	return t
}

// parse parses args and loads the configuration, wanting at least minArgs
// arguments after the flags.
func (t *tenantsFlags) parse(args []string, minArgs int) (config.Keys, error) {
	if err := t.fs.Parse(args); err != nil {
		return config.Keys{}, err
	}
	if *t.keyring == "" {
		t.fs.Usage()
		return config.Keys{}, errors.New("--keyring is required")
	}
	if t.fs.NArg() < minArgs {
		t.fs.Usage()
		return config.Keys{}, errUsage
	}
	return keysConfig(*t.conf, &t.pass)
}

func runTenantsCreate(ctx context.Context, args []string) error {
	t := newTenantsFlags("create", `Usage: blindbucket tenants create --keyring <file> [flags] <name> [<bucket>...]

Adds a tenant with a key-encryption key and a name key of its own, and gives it
the buckets listed: names, or prefixes ending in * (quote them: 'acme-*').
Buckets join a tenant and never leave it.

The tenant is sealed under the lock --config's keys.tenants.<name> names: a KMS
key, a Vault Transit key, or a passphrase. Destroying that lock is what will
delete the tenant, wherever copies of the keyring are. --deployment-lock seals
it under the deployment's lock instead: keys of its own, but every copy of the
keyring opens them with the deployment's root key, so a destruction cannot
reach those copies.

The tenant starts inactive: its buckets are still written under the default
tenant's keys. Roll the keyring out to every instance and every running
command, then run "blindbucket tenants activate".
`)
	kid := t.fs.String("kid", "", "id of the tenant's first key (default: <name>-<year>-<month>)")
	deployment := t.fs.Bool("deployment-lock", false,
		"seal the tenant under the deployment's lock rather than one of its own")
	defer t.pass.wipe()
	cfg, err := t.parse(args, 1)
	if err != nil {
		return err
	}
	name, buckets := t.fs.Arg(0), t.fs.Args()[1:]
	if err := keys.ValidateTenantName(name); err != nil {
		return err
	}
	if *kid == "" {
		*kid = name + "-" + defaultKID()
	}
	if err := keys.ValidateKID(*kid); err != nil {
		return fmt.Errorf("%w; choose one with --kid", err)
	}
	_, configured := cfg.Tenants[name]
	switch {
	case configured && *deployment:
		return fmt.Errorf("keys.tenants.%s names a lock and --deployment-lock asks for none; choose one", name)
	case !configured && !*deployment:
		return fmt.Errorf("keys.tenants.%s is not in the configuration: it names the lock the tenant "+
			"is sealed under. Pass --deployment-lock to seal it under the deployment's, knowing that "+
			"destroying it then rests on every copy of the keyring being gone", name)
	}

	roots := openTenant(ctx, cfg, name)
	defer roots.wipe()
	f, opened, err := openFile(ctx, *t.keyring, cfg, &t.pass, roots)
	if err != nil {
		return err
	}

	ring := keys.NewKeyring()
	if err := ring.Generate(*kid); err != nil {
		return err
	}
	nameKey, err := keys.NewNameKey()
	if err != nil {
		return err
	}
	ring.SetNameKey(nameKey)
	lock := keys.DeploymentLock()
	if configured {
		if lock, err = roots.newLock(name); err != nil {
			return err
		}
		defer lock.Wipe()
	}
	if err := f.AddTenant(name, buckets, ring, lock); err != nil {
		return err
	}

	sealed, err := sealKeyring(ctx, f, cfg, &t.pass, false)
	if err != nil {
		return err
	}
	// Opened again before the file is replaced, as reseal does: a key service
	// may seal for these credentials and refuse to unseal for them.
	reopened, err := unlockFile(ctx, *t.keyring, sealed, cfg, &t.pass, roots)
	if err != nil {
		return err
	}
	if r := reopened.Tenant(name); r == nil || r.Ring == nil || !f.Equal(reopened) {
		var why error
		if r != nil {
			why = r.Err
		}
		return fmt.Errorf("tenant %q was sealed but does not open again (%v); nothing was written -- "+
			"check that the credentials in keys.tenants.%s may decrypt as well as encrypt", name, why, name)
	}
	if err := replaceKeyring(*t.keyring, opened, sealed); err != nil {
		return err
	}

	tn := f.Tenant(name)
	fmt.Fprintf(os.Stderr, "created tenant %s in %s with key %q, sealed by %s; generation %d\n",
		name, *t.keyring, *kid, describeLock(tn.Lock()), f.Generation+1)
	if len(buckets) == 0 {
		fmt.Fprintf(os.Stderr, "  It has no buckets yet: `blindbucket tenants assign %s <bucket>...`.\n", name)
	} else {
		fmt.Fprintf(os.Stderr, "  Its buckets: %s\n", strings.Join(buckets, ", "))
	}
	fmt.Fprintf(os.Stderr, "  It is not active: its buckets are still written under the default tenant's keys.\n"+
		"  Roll this keyring out to every instance and every running command. Once\n"+
		"  blindbucket_keyring_generation is %d on every instance, run\n"+
		"  `blindbucket tenants activate %s` and roll that out too.\n", f.Generation+1, name)
	if *deployment {
		fmt.Fprintf(os.Stderr, "warning: %s has keys of its own but no lock of its own. Any copy of this\n"+
			"  keyring opens them with the deployment's root key, so destroying %s will not\n"+
			"  reach a copy that is kept. `blindbucket reseal --tenant %s` gives it a lock later.\n",
			name, name, name)
	}
	return nil
}

func runTenantsAssign(ctx context.Context, args []string) error {
	t := newTenantsFlags("assign", `Usage: blindbucket tenants assign --keyring <file> [flags] <name> <bucket>...

Gives a tenant more buckets: names, or prefixes ending in * (quote them:
'acme-*'). A bucket joins a tenant from the default tenant, with or without
objects in it, and never leaves it; moving data between tenants is a copy.

Objects already in the buckets stay on the keys they were written under until
they are rotated onto the tenant's. Writes use the tenant's keys once the
tenant is active and every instance serves this keyring.
`)
	defer t.pass.wipe()
	cfg, err := t.parse(args, 2)
	if err != nil {
		return err
	}
	name, buckets := t.fs.Arg(0), t.fs.Args()[1:]

	roots := openTenant(ctx, cfg)
	defer roots.wipe()
	f, opened, err := openFile(ctx, *t.keyring, cfg, &t.pass, roots)
	if err != nil {
		return err
	}
	if err := f.Assign(name, buckets); err != nil {
		return err
	}
	sealed, err := sealKeyring(ctx, f, cfg, &t.pass, false)
	if err != nil {
		return err
	}
	if err := replaceKeyring(*t.keyring, opened, sealed); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "assigned %s to tenant %s in %s; generation %d\n"+
		"  They stay %s's for good. Objects already in them stay on the keys they were\n"+
		"  written under until they are rotated onto %s's. Roll this keyring out until\n"+
		"  blindbucket_keyring_generation is %d on every instance.\n",
		strings.Join(buckets, ", "), name, *t.keyring, f.Generation+1, name, name, f.Generation+1)
	return nil
}

func runTenantsActivate(ctx context.Context, args []string) error {
	t := newTenantsFlags("activate", `Usage: blindbucket tenants activate --keyring <file> [flags] <name>

Makes a tenant's key the one its buckets are written under, once every instance
serves the new keyring. Activate a tenant only after every instance and every
running command serves the keyring that added it: one that does not yet know
the tenant cannot read what the others write under its keys.

The tenant has to open with the lock --config's keys.tenants names for it, so
that writes are never pointed at keys nothing has checked.
`)
	kid := t.fs.String("kid", "", "the key to activate (default: the tenant's only key)")
	defer t.pass.wipe()
	cfg, err := t.parse(args, 1)
	if err != nil {
		return err
	}
	if t.fs.NArg() != 1 {
		t.fs.Usage()
		return errUsage
	}
	name := t.fs.Arg(0)

	roots := openTenant(ctx, cfg, name)
	defer roots.wipe()
	f, opened, err := openFile(ctx, *t.keyring, cfg, &t.pass, roots)
	if err != nil {
		return err
	}
	if err := f.Activate(name, *kid); err != nil {
		return err
	}
	sealed, err := sealKeyring(ctx, f, cfg, &t.pass, false)
	if err != nil {
		return err
	}
	if err := replaceKeyring(*t.keyring, opened, sealed); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "activated tenant %s in %s with key %q; generation %d\n"+
		"  Instances write %s's buckets under it once they serve this keyring: roll it out\n"+
		"  until blindbucket_keyring_generation is %d on every instance. Objects written\n"+
		"  before stay on the keys they were written under until rotated.\n",
		name, *t.keyring, f.Tenant(name).ActiveKID, f.Generation+1, name, f.Generation+1)
	return nil
}

func runTenantsList(ctx context.Context, args []string) error {
	t := newTenantsFlags("list", `Usage: blindbucket tenants list --keyring <file> [flags]

Lists the keyring's tenants: their buckets, active key, lock and how many locks
they had before, whether they opened here, and the tenants destroyed. The
keyring's generation goes to stderr.

Tenants open with the locks --config's keys.tenants names; one that does not
is listed from the keyring's directory, which the deployment's root key opens.
`)
	jsonOut := jsonFlag(t.fs, "the tenant list")
	defer t.pass.wipe()
	cfg, err := t.parse(args, 0)
	if err != nil {
		return err
	}
	roots := openTenants(ctx, cfg)
	defer roots.wipe()
	f, _, err := openFile(ctx, *t.keyring, cfg, &t.pass, roots)
	if err != nil {
		return err
	}

	if *jsonOut {
		data, err := marshalTenantsJSON(f)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}

	if len(f.Tenants) == 0 && len(f.Tombstones) == 0 {
		fmt.Fprintln(os.Stderr, "no tenants: every bucket is the default tenant's")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TENANT\tBUCKETS\tACTIVE KEY\tLOCK\tSTATE")
	for _, tn := range f.Tenants {
		active := tn.ActiveKID
		if active == "" {
			active = "(inactive)"
		}
		lock := describeLock(tn.Lock())
		if n := len(tn.Locks) - 1; n > 0 {
			lock += fmt.Sprintf(" (+%d earlier)", n)
		}
		state := "open"
		if tn.Ring == nil {
			state = "not opened"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", tn.Name, bucketList(tn.Buckets), active, lock, state)
	}
	for _, tb := range f.Tombstones {
		_, _ = fmt.Fprintf(w, "%s\t%s\t\t%s\tdestroyed %s\n", tb.Name, bucketList(tb.Buckets),
			describeLock(tb.Locks[len(tb.Locks)-1]), tb.Destroyed.Format("2006-01-02"))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\ngeneration %d\n", f.Generation)
	for _, tn := range f.Tenants {
		if tn.Ring == nil {
			fmt.Fprintf(os.Stderr, "tenant %s did not open: %v\n", tn.Name, tn.Err)
		}
	}
	return nil
}

func bucketList(b []string) string {
	if len(b) == 0 {
		return "(none)"
	}
	return strings.Join(b, ",")
}

type tenantsJSON struct {
	Generation uint64              `json:"generation"`
	Tenants    []tenantJSON        `json:"tenants"`
	Tombstones []tenantTombstoneJS `json:"tombstones"`
}

type tenantJSON struct {
	Name      string      `json:"name"`
	Buckets   []string    `json:"buckets"`
	KIDs      []string    `json:"kids"`
	ActiveKID string      `json:"active_kid"`
	Locks     []keys.Lock `json:"locks"`
	Opened    bool        `json:"opened"`
	Error     string      `json:"error,omitempty"`
}

type tenantTombstoneJS struct {
	Name      string      `json:"name"`
	Buckets   []string    `json:"buckets"`
	KIDs      []string    `json:"kids"`
	Locks     []keys.Lock `json:"locks"`
	Destroyed string      `json:"destroyed"`
}

// marshalTenantsJSON renders the tenant list as newline-terminated JSON. A
// lock's salt is the passphrase KDF's, in the keyring in clear; it is listed
// as the directory records it.
func marshalTenantsJSON(f *keys.File) ([]byte, error) {
	out := tenantsJSON{Generation: f.Generation, Tenants: []tenantJSON{}, Tombstones: []tenantTombstoneJS{}}
	for _, t := range f.Tenants {
		e := tenantJSON{Name: t.Name, Buckets: t.Buckets, KIDs: t.KIDs, ActiveKID: t.ActiveKID,
			Locks: t.Locks, Opened: t.Ring != nil}
		if t.Err != nil {
			e.Error = t.Err.Error()
		}
		out.Tenants = append(out.Tenants, e)
	}
	for _, t := range f.Tombstones {
		out.Tombstones = append(out.Tombstones, tenantTombstoneJS{Name: t.Name, Buckets: t.Buckets,
			KIDs: t.KIDs, Locks: t.Locks, Destroyed: t.Destroyed.UTC().Format(time.RFC3339)})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
