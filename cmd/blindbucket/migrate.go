package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/migrate"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// errNamesInClear refuses a real migration under a configuration that does not
// encrypt names: the gateway it describes would not see a single migrated
// object, and the one thing ADR-022 asks before a run is that every instance
// already does.
var errNamesInClear = errors.New("names.encrypt is off in this configuration, so a gateway " +
	"serving it would see none of the objects a migration moves. Switch every instance to " +
	"names.encrypt: true first, then migrate (ADR-022); a --dry-run works either way")

func runMigrateNames(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate-names", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket migrate-names --config <file> s3://<bucket>[/<prefix>]

Moves objects stored under their keys in clear to the keys they have with
object-name encryption on, so that a bucket written before names.encrypt was
switched on can be read after.

It is a rename at the provider, not a re-encryption: each object keeps its data
key, its KEK and its ciphertext, and no object data moves through this process.

Switch every gateway instance to names.encrypt: true first, then run this.
While it runs, an object it has not reached yet is invisible to clients, and a
delete of such an object does not reach it -- the migration brings it back. A
write to an object's encrypted key is safe: the copy is published with
If-None-Match, so a client that got there first keeps its write. An instance
still serving names in clear loses what is written through it. ADR-022 has the
reasoning, and spec/tla/Migrate.tla the counterexamples.

A run is idempotent, and finishes what an interrupted one left: an object
already copied to its encrypted key is deleted in clear and counted as resumed.

Before touching anything, a run measures whether the provider enforces
If-None-Match, with a probe object under .blindbucket/probe/, and refuses to
start if not -- in a dry run too. --allow-unconditional skips the measurement
along with the condition.

Exits 1 when anything the gateway wrote under the prefix is still in clear
afterwards -- a conflict, a key too long to encrypt, or a failure -- and 0 when
it all moved. Run a --dry-run before the switch: it lists the keys too long to
encrypt, which are out of reach once names are encrypted.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		workers = fs.Int("concurrency", 8, "objects to migrate at once")
		dryRun  = fs.Bool("dry-run", false, "report what would be migrated, change nothing")
		jsonOut = jsonFlag(fs, "the summary")
		uncond  = fs.Bool("allow-unconditional", false,
			"publish without If-None-Match; gives up the one guard, see the warning it prints")
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
	bucket, prefix, err := parseS3Target(fs.Arg(0))
	if err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if !*dryRun && !cfg.Names.Encrypt {
		return fmt.Errorf("%s: %w", *cfgPath, errNamesInClear)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	ring, err := loadServerKeyring(ctx, cfg, &pass)
	if err != nil {
		return err
	}
	nameEnc, err := nameEncrypterFrom(cfg, ring, "migrating names needs the name key")
	if err != nil {
		return err
	}

	client, err := upstream.New(upstream.Config{
		Endpoint:        cfg.Upstream.Endpoint,
		Region:          cfg.Upstream.Region,
		PathStyle:       cfg.Upstream.PathStyle,
		AccessKeyID:     cfg.Upstream.AccessKeyID,
		SecretAccessKey: cfg.Upstream.SecretAccessKey,
		SessionToken:    cfg.Upstream.SessionToken,
	})
	if err != nil {
		return err
	}

	if *uncond {
		_, _ = fmt.Fprintln(os.Stderr,
			"warning: --allow-unconditional publishes without If-None-Match. A client write\n"+
				"         that reaches an object's encrypted key during the migration will be\n"+
				"         replaced by the older object. Nothing may write to this prefix meanwhile.")
	}

	started := time.Now().UTC()
	result, err := migrate.Run(ctx, migrate.Config{
		Upstream: client, Keys: ring, Names: nameEnc, Bucket: bucket, Prefix: prefix,
		Log2ChunkSize: cfg.Crypto.Log2ChunkSize, Concurrency: *workers, DryRun: *dryRun,
		AllowUnconditional: *uncond, Log: log,
	})
	if err != nil {
		return err
	}

	run := migrateRun{
		Bucket: bucket, Prefix: prefix, DryRun: *dryRun, Unconditional: *uncond,
		Started: started, Elapsed: time.Since(started),
	}
	if *jsonOut {
		data, err := marshalMigrateJSON(run, result)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
	} else {
		printMigrate(os.Stdout, run, result)
	}
	return migrateErrors(result, *dryRun)
}

// migrateErrors is the run's exit status. Like gc's and rotate's, the summary
// is printed first in either format; unlike theirs, a run that left anything in
// clear is a failure even when nothing went wrong, because exit 0 is the answer
// to "is this bucket migrated?".
func migrateErrors(r *migrate.Result, dryRun bool) error {
	if !r.Incomplete() {
		return nil
	}
	verb := "are"
	if dryRun {
		verb = "would be"
	}
	return fmt.Errorf("%d objects %s left in clear (conflicted %d, too long %d, failed %d); see the log",
		r.Conflicted+r.TooLong+r.Failed, verb, r.Conflicted, r.TooLong, r.Failed)
}

func printMigrate(w io.Writer, run migrateRun, r *migrate.Result) {
	verb := "migrated"
	if run.DryRun {
		verb = "would migrate"
	}
	_, _ = fmt.Fprintf(w, "%d keys in clear scanned in %s\n",
		r.Scanned, run.Elapsed.Round(time.Millisecond))
	_, _ = fmt.Fprintf(w, "  %-14s %d\n", verb+":", r.Migrated)
	for _, line := range []struct {
		label string
		n     int64
		why   string
	}{
		{"resumed:", r.Resumed, "an earlier run had copied them and stopped"},
		{"superseded:", r.Superseded, "a client wrote them since the switch"},
		{"conflicted:", r.Conflicted, "left in clear; see the log"},
		{"not ours:", r.Foreign, "no gateway metadata; left in clear"},
		{"too long:", r.TooLong, "encrypted, the key would pass 1024 bytes; see the log"},
		{"failed:", r.Failed, "see the log"},
	} {
		if line.n > 0 {
			_, _ = fmt.Fprintf(w, "  %-14s %d  (%s)\n", line.label, line.n, line.why)
		}
	}
}

// migrateRun is what the command knows about a run beyond the package's counts.
type migrateRun struct {
	Bucket, Prefix        string
	DryRun, Unconditional bool
	Started               time.Time
	Elapsed               time.Duration
}

// migrateJSON is the `migrate-names --json` document, shaped as rotate's and
// gc's are: every count always present, and no field name that moves with
// --dry-run.
type migrateJSON struct {
	Bucket          string  `json:"bucket"`
	Prefix          string  `json:"prefix"`
	DryRun          bool    `json:"dry_run"`
	Unconditional   bool    `json:"unconditional"`
	Started         string  `json:"started"`
	DurationSeconds float64 `json:"duration_seconds"`
	Scanned         int64   `json:"scanned"`
	Migrated        int64   `json:"migrated"`
	Resumed         int64   `json:"resumed"`
	Superseded      int64   `json:"superseded"`
	Conflicted      int64   `json:"conflicted"`
	Foreign         int64   `json:"foreign"`
	TooLong         int64   `json:"too_long"`
	Failed          int64   `json:"failed"`
}

// marshalMigrateJSON renders a run's summary as newline-terminated JSON, with
// the start in RFC 3339 UTC and the duration in seconds to the millisecond.
func marshalMigrateJSON(run migrateRun, r *migrate.Result) ([]byte, error) {
	data, err := json.Marshal(migrateJSON{
		Bucket: run.Bucket, Prefix: run.Prefix,
		DryRun: run.DryRun, Unconditional: run.Unconditional,
		Started:         run.Started.UTC().Format(time.RFC3339),
		DurationSeconds: run.Elapsed.Round(time.Millisecond).Seconds(),
		Scanned:         r.Scanned,
		Migrated:        r.Migrated,
		Resumed:         r.Resumed,
		Superseded:      r.Superseded,
		Conflicted:      r.Conflicted,
		Foreign:         r.Foreign,
		TooLong:         r.TooLong,
		Failed:          r.Failed,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
