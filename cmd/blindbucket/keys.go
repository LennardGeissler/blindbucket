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
	"github.com/LennardGeissler/blindbucket/internal/obs"
)

func runKeys(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return keysUsage()
	}
	switch args[0] {
	case "list":
		return runKeysList(ctx, args[1:])
	case "remove":
		return runKeysRemove(ctx, args[1:])
	case "-h", "--help", "help":
		return keysUsage()
	}
	return fmt.Errorf("unknown keys subcommand %q (try `blindbucket keys help`)", args[0])
}

func keysUsage() error {
	_, _ = fmt.Fprint(os.Stderr, `Usage: blindbucket keys <subcommand> [flags]

Subcommands:
  list      show the key-encryption keys in a keyring, and how old they are
  remove    retire a key that nothing references any more

Keys are created by "blindbucket keygen" and moved onto by "blindbucket rotate".

Run "blindbucket keys <subcommand> -h" for a subcommand's flags.
`)
	return errUsage
}

func runKeysList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keys list", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket keys list --keyring <file> [flags]

Lists the key-encryption keys in a keyring, by tenant: which one new objects are
wrapped under, and how long each has been in use. A tenant whose lock this
configuration cannot open (keys.tenants) is listed from the keyring's directory,
with what only its keys would say left unknown.

Age is what decides whether a rotation is due, so it is what this prints. The
keyring is opened rather than read, so what it shows is authenticated: a key id
or a date edited in the file would fail to unwrap before it could be listed.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		keyring = fs.String("keyring", "", "keyring file (required)")
		conf    = fs.String("config", "", "configuration file naming the root-key provider")
		jsonOut = jsonFlag(fs, "the key list")
		pass    passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	if *keyring == "" {
		fs.Usage()
		return errors.New("--keyring is required")
	}

	keysCfg, err := keysConfig(*conf, &pass)
	if err != nil {
		return err
	}
	roots := openTenants(ctx, keysCfg)
	defer roots.wipe()
	f, _, err := openFile(ctx, *keyring, keysCfg, &pass, roots)
	if err != nil {
		return err
	}
	ring := f.Default
	rows := keyRows(f)

	now := time.Now().UTC()
	var jsonData []byte
	if *jsonOut {
		jsonData, err = marshalKeysJSON(now, rows)
		if err != nil {
			return err
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "TENANT\tKEY ID\tCREATED\tAGE\t")
		for _, r := range rows {
			created, age := "unknown", ""
			if r.created != nil {
				created = r.created.Format(time.RFC3339)
				age = humanAge(now.Sub(*r.created))
			}
			var marker []string
			if r.active {
				marker = append(marker, "active")
			}
			if !r.opened {
				marker = append(marker, "not opened")
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.tenant, r.kid, created, age, strings.Join(marker, ", "))
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	for _, t := range f.Tenants {
		if t.Ring == nil {
			fmt.Fprintf(os.Stderr, "\ntenant %s did not open: %v\n", t.Name, t.Err)
		}
	}

	if _, ok := ring.AuditKey(); !ok {
		fmt.Fprintf(os.Stderr,
			"\nthis keyring has no audit key; `keygen --add-audit-key` adds one\n")
	}
	if _, ok := ring.FreshnessKey(); !ok {
		fmt.Fprintf(os.Stderr,
			"\nthis keyring has no rollback-index key; `keygen --add-freshness-key` adds one\n")
	}
	if _, ok := ring.NameKey(); !ok {
		fmt.Fprintf(os.Stderr,
			"\nthis keyring has no object-name key; `keygen --add-name-key` adds one.\n"+
				"  Add it before encrypting names, not after: the key decides where every\n"+
				"  object is stored, so it cannot be changed once objects exist under it.\n")
	}
	if *jsonOut {
		_, _ = os.Stdout.Write(jsonData)
	}
	return nil
}

// keyRow is one key in the list.
type keyRow struct {
	tenant  string
	kid     string
	created *time.Time
	active  bool
	// opened is false for a tenant that did not open: its key ids are the
	// directory's, and what is unknown about them stays unknown.
	opened bool
}

// keyRows lists the default tenant's keys and then each tenant's.
func keyRows(f *keys.File) []keyRow {
	rows := ringRows(keys.DefaultTenant, f.Default)
	for _, t := range f.Tenants {
		if t.Ring != nil {
			rows = append(rows, ringRows(t.Name, t.Ring)...)
			continue
		}
		for _, kid := range t.KIDs {
			rows = append(rows, keyRow{tenant: t.Name, kid: kid, active: kid == t.ActiveKID})
		}
	}
	return rows
}

func ringRows(tenant string, ring obs.KeyringInfo) []keyRow {
	var rows []keyRow
	for _, kid := range ring.KIDs() {
		r := keyRow{tenant: tenant, kid: kid, active: kid == ring.ActiveKID(), opened: true}
		if t, ok := ring.Created(kid); ok && !t.IsZero() {
			r.created = &t
		}
		rows = append(rows, r)
	}
	return rows
}

type keyListJSON struct {
	Keys []keyListEntryJSON `json:"keys"`
}

type keyListEntryJSON struct {
	Tenant     string  `json:"tenant"`
	KID        string  `json:"kid"`
	Created    *string `json:"created"`
	AgeSeconds *int64  `json:"age_seconds"`
	Active     bool    `json:"active"`
	Opened     bool    `json:"opened"`
}

// marshalKeysJSON renders the key list as newline-terminated JSON with UTC timestamps.
func marshalKeysJSON(now time.Time, rows []keyRow) ([]byte, error) {
	out := keyListJSON{Keys: make([]keyListEntryJSON, 0, len(rows))}
	for _, r := range rows {
		entry := keyListEntryJSON{Tenant: r.tenant, KID: r.kid, Active: r.active, Opened: r.opened}
		if r.created != nil {
			created := r.created.UTC().Format(time.RFC3339)
			age := int64(now.Sub(*r.created).Seconds())
			entry.Created = &created
			entry.AgeSeconds = &age
		}
		out.Keys = append(out.Keys, entry)
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}

// humanAge renders a key's age at the resolution a rotation decision needs.
func humanAge(d time.Duration) string {
	if days := int(d.Hours() / 24); days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

func runKeysRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keys remove", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket keys remove --keyring <file> [flags] <kid>

Removes a key-encryption key from a keyring.

This is the half of rotation that actually retires a key. "blindbucket rotate"
moves objects onto a new KEK but leaves the old one in the keyring, where it
goes on opening everything it ever wrapped; until it is removed, a compromised
key is still a working key.

It is also the one irreversible operation on a keyring. Every object still
wrapped under the key becomes unreadable, and this command cannot see the
bucket to check -- which is why it needs --force. Run

    blindbucket rotate --config <file> --to-kid <active> --dry-run s3://<bucket>

first and confirm it reports nothing left to rotate.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		keyring = fs.String("keyring", "", "keyring file (required)")
		conf    = fs.String("config", "", "configuration file naming the root-key provider")
		force   = fs.Bool("force", false, "confirm that no object is wrapped under the key any more")
		pass    passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()
	if *keyring == "" {
		fs.Usage()
		return errors.New("--keyring is required")
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one key id is required")
	}
	kid := fs.Arg(0)

	keysCfg, err := keysConfig(*conf, &pass)
	if err != nil {
		return err
	}
	roots := openTenant(ctx, keysCfg)
	defer roots.wipe()
	f, opened, err := openFile(ctx, *keyring, keysCfg, &pass, roots)
	if err != nil {
		return err
	}
	ring := f.Default
	// Checked before --force, so that a typo in the key id is reported as a
	// typo rather than answered with a warning about data loss.
	if owner, used := f.KIDOwner(kid); used && owner != keys.DefaultTenant {
		return fmt.Errorf("%q is tenant %s's key; keys remove retires the default tenant's", kid, owner)
	}
	if _, ok := ring.Created(kid); !ok {
		return fmt.Errorf("%s holds no key %q (see `blindbucket keys list`)", *keyring, kid)
	}
	if !*force {
		return fmt.Errorf(
			"refusing to remove %q without --force: every object still wrapped under it "+
				"becomes unreadable, and this command cannot see the bucket to tell whether "+
				"any is. Rotate onto %q first and check that a --dry-run run reports nothing "+
				"left to rotate", kid, ring.ActiveKID())
	}
	if err := ring.Remove(kid); err != nil {
		return err
	}

	updated, err := sealKeyring(ctx, f, keysCfg, &pass, false)
	if err != nil {
		return err
	}
	if err := replaceKeyring(*keyring, opened, updated); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "removed key %q from %s (active key: %q)\n", kid, *keyring, ring.ActiveKID())
	return nil
}

// keysConfig resolves the key configuration a command was pointed at.
//
// Without --config the keyring is a passphrase keyring, which is the case that
// needs no configuration file at all; with one, the file also supplies the
// passphrase location unless a flag already did.
func keysConfig(conf string, pass *passphraseFlags) (config.Keys, error) {
	if conf == "" {
		return config.Keys{Provider: "file"}, nil
	}
	cfg, err := config.Load(conf)
	if err != nil {
		return config.Keys{}, err
	}
	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	return cfg.Keys, nil
}
