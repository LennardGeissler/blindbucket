package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
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

Lists the key-encryption keys in a keyring: which one new objects are wrapped
under, and how long each has been in use.

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
		jsonOut = fs.Bool("json", false, "emit the key list as JSON")
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
	ring, err := openKeyring(ctx, *keyring, keysCfg, &pass)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if *jsonOut {
		data, err := marshalKeysJSON(now, ring)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "KEY ID\tCREATED\tAGE\t")
	for _, kid := range ring.KIDs() {
		created, age := "unknown", ""
		if t, ok := ring.Created(kid); ok && !t.IsZero() {
			created = t.Format(time.RFC3339)
			age = humanAge(now.Sub(t))
		}
		marker := ""
		if kid == ring.ActiveKID() {
			marker = "active"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", kid, created, age, marker)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if _, ok := ring.AuditKey(); !ok {
		fmt.Fprintf(os.Stderr,
			"\nthis keyring has no audit key; `keygen --add-audit-key` adds one\n")
	}
	return nil
}

type keyListJSON struct {
	Keys []keyListEntryJSON `json:"keys"`
}

type keyListEntryJSON struct {
	KID       string  `json:"kid"`
	Created   *string `json:"created"`
	AgeSeconds *int64 `json:"age_seconds"`
	Active    bool    `json:"active"`
}

func marshalKeysJSON(now time.Time, ring interface {
	KIDs() []string
	Created(string) (time.Time, bool)
	ActiveKID() string
}) ([]byte, error) {
	out := keyListJSON{Keys: make([]keyListEntryJSON, 0, len(ring.KIDs()))}
	for _, kid := range ring.KIDs() {
		entry := keyListEntryJSON{KID: kid, Active: kid == ring.ActiveKID()}
		if t, ok := ring.Created(kid); ok && !t.IsZero() {
			created := t.UTC().Format(time.RFC3339)
			age := int64(now.Sub(t).Seconds())
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
	ring, err := openKeyring(ctx, *keyring, keysCfg, &pass)
	if err != nil {
		return err
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

	updated, err := sealKeyring(ctx, ring, keysCfg, &pass, false)
	if err != nil {
		return err
	}
	if err := writeKeyring(*keyring, updated); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "removed key %q from %s (active key: %q)\n", kid, *keyring, ring.ActiveKID())
	return nil
}

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
