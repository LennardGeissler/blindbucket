package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/census"
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
	case "census":
		return runTenantsCensus(ctx, args[1:])
	case "destroy":
		return runTenantsDestroy(ctx, args[1:])
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
  census    count what in a tenant's buckets is not under its keys
  destroy   take a census, then tombstone a tenant for good

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

func runTenantsCensus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tenants census", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), `Usage: blindbucket tenants census --config <file> [flags] <name>

Counts, in every bucket of a tenant, the objects that are not wrapped under the
tenant's keys: those a destruction of the tenant would leave readable. It reads
each object's metadata at the provider and decrypts nothing, so the tenant's
lock is not needed. Exits 1 when any such object is found, or any object could
not be read.

A census holds only once every instance serves the tenant active, and no rotate
or encrypt-existing started on an earlier keyring is still running: until then,
something can still write the tenant's buckets under the default tenant's keys
(ADR-038, rule 2). blindbucket_keyring_generation says what each instance serves.
The objects found are moved by "blindbucket rotate" on their bucket.

In a versioned bucket it counts every version the provider keeps. An earlier
version written under another tenant's keys survives its object being replaced,
and rotate cannot move it: it goes by deleting it, or by a lifecycle rule that
expires noncurrent versions. A provider that does not list versions keeps none,
and its buckets are counted by their current objects.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		workers = fs.Int("concurrency", 8, "objects to read at once")
		jsonOut = jsonFlag(fs, "the census")
		verbose = fs.Bool("v", false, "log at debug level")
		pass    passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	if fs.NArg() != 1 {
		fs.Usage()
		return errUsage
	}
	name := fs.Arg(0)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	f, _, err := openFile(ctx, cfg.Keys.Keyring, cfg.Keys, &pass, openTenant(ctx, cfg.Keys))
	if err != nil {
		return err
	}
	tn, err := liveTenant(f, cfg.Keys.Keyring, name)
	if err != nil {
		return err
	}
	if tn.ActiveKID == "" {
		return fmt.Errorf("tenant %s is not active: its buckets are still written under the default "+
			"tenant's keys, so a census cannot come out clean. Activate it and roll that out first", name)
	}

	result, err := takeCensus(ctx, cfg, tn, *workers, *verbose)
	if err != nil {
		return err
	}

	if *jsonOut {
		data, err := marshalCensusJSON(name, f.Generation, result)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
		return censusErrors(name, result)
	}

	if err := printCensus(f, *cfgPath, result); err != nil {
		return err
	}
	return censusErrors(name, result)
}

// liveTenant returns the live tenant called name, or says why there is none.
func liveTenant(f *keys.File, keyring, name string) (*keys.Tenant, error) {
	if tn := f.Tenant(name); tn != nil {
		return tn, nil
	}
	for _, tb := range f.Tombstones {
		if tb.Name == name {
			return nil, fmt.Errorf("tenant %s was destroyed on %s", name, tb.Destroyed.Format("2006-01-02"))
		}
	}
	return nil, fmt.Errorf("%s has no tenant %q (see `blindbucket tenants list`)", keyring, name)
}

// takeCensus counts, in every bucket of tn, the objects not under its keys.
func takeCensus(ctx context.Context, cfg *config.Config, tn *keys.Tenant, workers int, verbose bool) (*census.Result, error) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	client, _, err := upstreamClient(cfg, nil)
	if err != nil {
		return nil, err
	}
	return census.Run(ctx, census.Config{
		Upstream: client, Entries: tn.Buckets, KIDs: tn.KIDs, Log2ChunkSize: cfg.Crypto.Log2ChunkSize,
		Concurrency: workers,
		Log:         slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})),
	})
}

// printCensus writes a census as a table, says what moves the objects off the
// tenant, and which keyring generation the count holds for.
func printCensus(f *keys.File, cfgPath string, result *census.Result) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "BUCKET\tSCANNED\tON TENANT\tOFF TENANT\tEARLIER VERSIONS OFF\tNOT OURS\tFAILED\t")
	for _, b := range result.Buckets {
		if b.Missing {
			_, _ = fmt.Fprintf(w, "%s\t(does not exist)\t\t\t\t\t\t\n", b.Name)
			continue
		}
		_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t\n",
			b.Name, b.Scanned, b.OnTenant, b.OffTenant, b.NoncurrentOff, b.Foreign, b.Failed)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, b := range result.Buckets {
		for _, kid := range slices.Sorted(maps.Keys(b.OffKIDs)) {
			fmt.Fprintf(os.Stderr, "%s: %d under %q (%s); `blindbucket rotate --config %s s3://%s` "+
				"moves them\n", b.Name, b.OffKIDs[kid], kid, keyOwner(f, kid), cfgPath, b.Name)
		}
		for _, kid := range slices.Sorted(maps.Keys(b.NoncurrentKIDs)) {
			fmt.Fprintf(os.Stderr, "%s: %d earlier versions under %q (%s); rotate cannot move a "+
				"version that is not current, so delete them, or expire noncurrent versions by a "+
				"lifecycle rule\n", b.Name, b.NoncurrentKIDs[kid], kid, keyOwner(f, kid))
		}
		if !b.Missing && !b.Versioned {
			fmt.Fprintf(os.Stderr, "%s: the provider does not list versions, so current objects were "+
				"counted; a provider without versions keeps no earlier ones\n", b.Name)
		}
	}
	fmt.Fprintf(os.Stderr, "\nCounted against keyring generation %d. The count holds only if every instance\n"+
		"served it, or a later one, throughout (blindbucket_keyring_generation), and no rotate\n"+
		"or encrypt-existing started on an earlier keyring was still running.\n", f.Generation)
	return nil
}

// keyOwner says who holds kid in an opened file.
func keyOwner(f *keys.File, kid string) string {
	if owner, ok := f.KIDOwner(kid); ok {
		return "tenant " + owner + "'s"
	}
	return "a key this keyring does not hold"
}

// censusErrors is the census's exit status: clean only when every object in
// the tenant's buckets was read and is under its keys.
func censusErrors(name string, result *census.Result) error {
	var errs []error
	if n := result.OffTenant(); n > 0 {
		errs = append(errs, fmt.Errorf("%d objects in tenant %s's buckets are not under its keys", n, name))
	}
	if n := result.NoncurrentOff(); n > 0 {
		errs = append(errs, fmt.Errorf("%d earlier versions in tenant %s's buckets are not under its keys", n, name))
	}
	if n := result.Failed(); n > 0 {
		errs = append(errs, fmt.Errorf("%d objects could not be read; see the log", n))
	}
	return errors.Join(errs...)
}

type censusJSON struct {
	Tenant     string `json:"tenant"`
	Generation uint64 `json:"generation"`
	OffTenant  int64  `json:"off_tenant"`
	// NoncurrentOffTenant counts earlier versions off the tenant's keys,
	// which rotate cannot move (#218).
	NoncurrentOffTenant int64              `json:"noncurrent_off_tenant"`
	Failed              int64              `json:"failed"`
	Buckets             []censusBucketJSON `json:"buckets"`
}

type censusBucketJSON struct {
	Bucket    string `json:"bucket"`
	Missing   bool   `json:"missing"`
	Versioned bool   `json:"versioned"`
	Scanned   int64  `json:"scanned"`
	// Noncurrent counts the versions among Scanned that are not current.
	Noncurrent          int64            `json:"noncurrent"`
	OnTenant            int64            `json:"on_tenant"`
	OffTenant           int64            `json:"off_tenant"`
	NoncurrentOffTenant int64            `json:"noncurrent_off_tenant"`
	Foreign             int64            `json:"foreign"`
	Failed              int64            `json:"failed"`
	OffKIDs             map[string]int64 `json:"off_kids"`
	NoncurrentOffKIDs   map[string]int64 `json:"noncurrent_off_kids"`
}

// marshalCensusJSON renders a census as newline-terminated JSON.
func marshalCensusJSON(name string, generation uint64, result *census.Result) ([]byte, error) {
	out := censusJSON{Tenant: name, Generation: generation, OffTenant: result.OffTenant(),
		NoncurrentOffTenant: result.NoncurrentOff(), Failed: result.Failed(), Buckets: []censusBucketJSON{}}
	for _, b := range result.Buckets {
		noncurrentKIDs := b.NoncurrentKIDs
		if noncurrentKIDs == nil {
			noncurrentKIDs = map[string]int64{}
		}
		out.Buckets = append(out.Buckets, censusBucketJSON{
			Bucket: b.Name, Missing: b.Missing, Versioned: b.Versioned, Scanned: b.Scanned,
			Noncurrent: b.Noncurrent, OnTenant: b.OnTenant, OffTenant: b.OffTenant,
			NoncurrentOffTenant: b.NoncurrentOff, Foreign: b.Foreign, Failed: b.Failed,
			OffKIDs: b.OffKIDs, NoncurrentOffKIDs: noncurrentKIDs,
		})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func runTenantsDestroy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tenants destroy", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), `Usage: blindbucket tenants destroy --config <file> [flags] <name>

Destroys a tenant (ADR-038). This cannot be undone.

First it takes the tenant's census, as "blindbucket tenants census" does: an
object in its buckets that is not under its keys would stay readable after the
destruction, so any such object, earlier versions in a versioned bucket
included, or any object it could not read, stops it. --force destroys the
tenant all the same.

Then it writes the keyring as its next generation with the tenant's keys left
out and a tombstone in their place: the tenant's buckets stay its own and are
refused, its name and key ids are never issued again. The tenant's lock is not
needed for this.

That alone deletes nothing. Every earlier copy of the keyring still holds the
tenant's keys, sealed under its locks. Roll the new keyring out to every
instance, let every command started on an earlier one end, and then destroy
each lock the tenant was ever sealed under, at its key service. The command
names them; it does not destroy them itself, so that the gateway's credentials
need no right to delete keys.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		workers = fs.Int("concurrency", 8, "objects to read at once")
		force   = fs.Bool("force", false, "destroy even if the census finds objects not under the tenant's keys")
		dryRun  = fs.Bool("dry-run", false, "take the census and say what would happen, write nothing")
		verbose = fs.Bool("v", false, "log at debug level")
		pass    passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	if fs.NArg() != 1 {
		fs.Usage()
		return errUsage
	}
	name := fs.Arg(0)
	if name == keys.DefaultTenant {
		return errors.New("the default tenant holds every bucket no tenant claims; it cannot be destroyed")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	path := cfg.Keys.Keyring
	// No tenant's lock is opened: a tenant whose key service is already gone
	// can still be destroyed.
	f, opened, err := openFile(ctx, path, cfg.Keys, &pass, openTenant(ctx, cfg.Keys))
	if err != nil {
		return err
	}
	tn, err := liveTenant(f, path, name)
	if err != nil {
		return err
	}

	result, err := takeCensus(ctx, cfg, tn, *workers, *verbose)
	if err != nil {
		return err
	}
	if err := printCensus(f, *cfgPath, result); err != nil {
		return err
	}
	if tn.ActiveKID == "" {
		fmt.Fprintf(os.Stderr, "\nwarning: %s was never active, so its buckets are written under the default\n"+
			"  tenant's keys until every instance serves the tombstone. What is written to\n"+
			"  them until then stays readable with those keys.\n", name)
	}
	if err := destroyVerdict(name, result, *force); err != nil {
		return err
	}

	if *dryRun {
		fmt.Fprintf(os.Stderr, "\nwould destroy tenant %s in %s as generation %d; nothing was written\n",
			name, path, f.Generation+1)
		return nil
	}
	tomb, err := f.Destroy(name, time.Now())
	if err != nil {
		return err
	}
	sealed, err := sealKeyring(ctx, f, cfg.Keys, &pass, false)
	if err != nil {
		return err
	}
	if err := replaceKeyring(path, opened, sealed); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\ndestroyed tenant %s in %s; generation %d\n"+
		"  Its buckets stay its own and are refused on every instance that serves this\n"+
		"  keyring: %s.\n"+
		"  Its keys are gone from this file, and from no earlier copy yet.\n"+
		"  1. Roll this keyring out until blindbucket_keyring_generation is %d on every\n"+
		"     instance, and let every command started on an earlier keyring end.\n"+
		"  2. Then destroy each lock %s was ever sealed under. Until the last is gone,\n"+
		"     a copy of the keyring from before opens its keys.\n",
		name, path, f.Generation+1, strings.Join(tomb.Buckets, ", "), f.Generation+1, name)
	deployment, err := keys.ReadRootKeyRef(sealed)
	if err != nil {
		return err
	}
	for _, line := range lockInstructions(f, deployment, cfg.Keys.Tenants[name], tomb) {
		fmt.Fprintln(os.Stderr, "     "+line)
	}
	if _, ok := cfg.Keys.Tenants[name]; ok {
		fmt.Fprintf(os.Stderr, "  3. Remove keys.tenants.%s from the configuration of every instance.\n", name)
	}
	return nil
}

// lockInstructions says, for each lock a destroyed tenant was ever sealed
// under, what destroys it and where: the command does not, so that the
// gateway's credentials need no right to delete keys. A key that also seals
// the deployment or a live tenant is called out instead, since destroying it
// would destroy them too. tc is the tenant's entry under keys.tenants, if the
// configuration still has one.
func lockInstructions(f *keys.File, deployment keys.RootKeyRef, tc config.Keys, tomb keys.Tombstone) []string {
	var out []string
	for _, l := range tomb.Locks {
		if l.Source == keys.LockDeployment {
			out = append(out,
				"- the deployment's lock: every copy of the keyring from while "+tomb.Name+" was under it",
				"  opens its keys with the deployment's root key, which cannot be destroyed without",
				"  the deployment. Destroying them means deleting those copies: backups, Secrets,",
				"  and old releases of the file.")
			continue
		}
		if l.Source == keys.SourcePassphrase {
			out = append(out,
				"- a passphrase (salt "+l.Salt+"): forget it, every copy of it, in passphrase files,",
				"  password managers and scripts. Nothing can check that it is gone.")
			continue
		}
		if users := lockUsers(f, deployment, l); len(users) > 0 {
			out = append(out,
				"- "+describeLock(l)+": DO NOT DESTROY. It also seals "+strings.Join(users, " and ")+",",
				"  which destroying it would destroy too. "+tomb.Name+"'s keys stay in every copy of",
				"  the keyring from while it was under this key, until those copies are deleted.")
			continue
		}
		switch l.Source {
		case keys.SourceAWSKMS:
			out = append(out,
				"- "+describeLock(l)+": schedule its deletion. That takes a key id, not an",
				"  alias, so look the key up; if an alias was moved since "+tomb.Name+" was sealed",
				"  under it, the key is the one it pointed to then:",
				"    aws kms describe-key --key-id "+l.KeyName+" --query KeyMetadata.KeyId",
				"    aws kms schedule-key-deletion --key-id <that key id> --pending-window-in-days 7",
				"  Until the waiting period of 7 to 30 days ends, the deletion can be cancelled and",
				"  "+tomb.Name+" brought back with the key.")
		case keys.SourceVaultTransit:
			mount := "transit"
			if tc.Provider == "vault" && tc.Vault.KeyName == l.KeyName && tc.Vault.Mount != "" {
				mount = tc.Vault.Mount
			}
			out = append(out,
				"- "+describeLock(l)+": delete it, where its Transit engine is mounted:",
				"    vault write "+mount+"/keys/"+l.KeyName+"/config deletion_allowed=true",
				"    vault delete "+mount+"/keys/"+l.KeyName,
				"  Vault's snapshots, and any backup or export of the key, hold it until they are",
				"  deleted too.")
		default:
			out = append(out, "- "+describeLock(l)+": destroy it at its key service.")
		}
	}
	return out
}

// lockUsers names who else a service key seals: the deployment, or a live
// tenant now or at any time before. Only the recorded names are compared, so
// an alias and the key id it stands for are not seen to be the same key.
func lockUsers(f *keys.File, deployment keys.RootKeyRef, l keys.Lock) []string {
	var users []string
	if deployment.Source == l.Source && deployment.KeyName == l.KeyName {
		users = append(users, "the deployment")
	}
	for _, t := range f.Tenants {
		if slices.Contains(t.Locks, l) {
			users = append(users, "tenant "+t.Name)
		}
	}
	return users
}

// destroyVerdict decides whether a census lets a tenant be destroyed: only a
// clean one does, unless force says otherwise, and then it says what is left
// readable.
func destroyVerdict(name string, result *census.Result, force bool) error {
	off, noncurrent, failed := result.OffTenant(), result.NoncurrentOff(), result.Failed()
	if off == 0 && noncurrent == 0 && failed == 0 {
		return nil
	}
	if !force {
		return fmt.Errorf("not destroying tenant %s: %w\n"+
			"Rotate current objects onto its keys or delete them, delete earlier versions or expire "+
			"them by a lifecycle rule, and run this again; --force destroys it with them left as "+
			"they are", name, censusErrors(name, result))
	}
	fmt.Fprintf(os.Stderr, "\nwarning: --force: destroying tenant %s with %d objects and %d earlier versions in its\n"+
		"  buckets not under its keys, which stay readable with the keys they are under, and %d\n"+
		"  whose keys are not known.\n", name, off, noncurrent, failed)
	return nil
}
