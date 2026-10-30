package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/encrypt"
)

func runEncryptExisting(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("encrypt-existing", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket encrypt-existing --config <file> s3://<bucket>[/<prefix>]

Encrypts the objects a bucket held before the gateway, in place, so that the
gateway can read them. A gateway refuses such an object with
ObjectNotEncrypted; after a run it serves it as if it had written it.

Each object is read, encrypted under a new data key and the active KEK, and
written back: to its own key with names in clear, to its encrypted key with
names.encrypt -- after which the plaintext is deleted. Headers and metadata are
carried across. Every byte passes through this process, so a run reads and
writes the whole prefix.

Stop the application, or put it in maintenance, for the run: until the run
reaches an object, the gateway refuses it. A client writing through the gateway
meanwhile is safe and wins -- the write is published with If-Match, or
If-None-Match under names.encrypt. With names.encrypt, switch every gateway
instance to it first. ADR-034 has the reasoning.

Left alone, and reported: objects the gateway wrote, objects with tags, under a
legal hold or retention, encrypted with SSE-C, with metadata under the gateway's
bb- prefix, and keys too long to encrypt.

Before touching anything, a run checks that the bucket has no versioning --
overwrites would keep every plaintext as an old version -- and measures whether
the provider enforces the condition the run needs, with a probe object under
.blindbucket/probe/. It refuses to start if either fails, in a dry run too.
--keep-versions and --allow-unconditional are the ways past them.

A run is idempotent. Exits 1 when a plaintext object is left under the prefix
afterwards, and 0 when none is.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		workers = fs.Int("concurrency", 8, "objects to encrypt at once")
		dryRun  = fs.Bool("dry-run", false, "report what would be encrypted, change nothing")
		jsonOut = jsonFlag(fs, "the summary")
		uncond  = fs.Bool("allow-unconditional", false,
			"write without the condition that keeps a client's write; see the warning it prints")
		keepVersions = fs.Bool("keep-versions", false,
			"run on a versioned bucket, whose old plaintext versions you remove yourself")
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

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	served, bucketKeys, err := loadBucketKeyring(ctx, cfg, &pass, bucket)
	if err != nil {
		return err
	}
	if err := defaultTenantOnly("encrypt-existing", bucket, bucketKeys); err != nil {
		return err
	}
	ring := served.Default()
	var nameEnc *names.Encrypter
	if cfg.Names.Encrypt {
		nameEnc, err = nameEncrypterFrom(cfg, ring, "encrypting objects under encrypted names needs the name key")
		if err != nil {
			return err
		}
	}

	client, _, err := upstreamClient(cfg, nil)
	if err != nil {
		return err
	}

	if *uncond {
		_, _ = fmt.Fprintln(os.Stderr,
			"warning: --allow-unconditional writes without the condition that keeps a client's\n"+
				"         write. A client writing an object during the run can lose its write to\n"+
				"         the encrypted older one. Nothing may write to this prefix meanwhile.")
	}
	if *keepVersions {
		_, _ = fmt.Fprintln(os.Stderr,
			"warning: --keep-versions: every object this run encrypts keeps its plaintext at the\n"+
				"         provider as a noncurrent version until you remove it.")
	}
	if cfg.Freshness.Index != "" {
		_, _ = fmt.Fprintln(os.Stderr,
			"note: rollback detection is on. An object this run encrypts is recorded when the\n"+
				"      gateway first reads it. One the gateway wrote once and someone then replaced\n"+
				"      with plaintext past the gateway will be refused as a rollback (ADR-034).")
	}

	started := time.Now().UTC()
	result, err := encrypt.Run(ctx, encrypt.Config{
		Upstream: client, Keys: ring, Names: nameEnc, Bucket: bucket, Prefix: prefix,
		Log2ChunkSize: cfg.Crypto.Log2ChunkSize, Concurrency: *workers, DryRun: *dryRun,
		AllowUnconditional: *uncond, KeepVersions: *keepVersions, Log: log,
	})
	if err != nil {
		return err
	}

	run := encryptRun{
		Bucket: bucket, Prefix: prefix, DryRun: *dryRun, Unconditional: *uncond,
		NamesEncrypted: nameEnc != nil, Started: started, Elapsed: time.Since(started),
	}
	if *jsonOut {
		data, err := marshalEncryptJSON(run, result)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
	} else {
		printEncrypt(os.Stdout, run, result)
	}
	return encryptErrors(result, *dryRun)
}

// encryptErrors is the run's exit status: exit 0 is the answer to "is any
// plaintext left under this prefix?", so a run that left some fails even when
// nothing went wrong.
func encryptErrors(r *encrypt.Result, dryRun bool) error {
	if !r.Incomplete() {
		return nil
	}
	left := r.Conflicted + r.NeedsNameMigration + r.TooLong + r.Tagged + r.Locked + r.Unreadable + r.Failed
	verb := "are"
	if dryRun {
		verb = "would be"
	}
	return fmt.Errorf("%d objects %s left unencrypted (conflicted %d, needs migrate-names %d, "+
		"too long %d, tagged %d, locked %d, unreadable %d, failed %d); see the log",
		left, verb, r.Conflicted, r.NeedsNameMigration, r.TooLong, r.Tagged, r.Locked, r.Unreadable, r.Failed)
}

func printEncrypt(w io.Writer, run encryptRun, r *encrypt.Result) {
	verb := "encrypted"
	if run.DryRun {
		verb = "would encrypt"
	}
	_, _ = fmt.Fprintf(w, "%d keys scanned in %s\n", r.Scanned, run.Elapsed.Round(time.Millisecond))
	_, _ = fmt.Fprintf(w, "  %-22s %d  (%d bytes)\n", verb+":", r.Encrypted, r.BytesEncrypted)
	for _, line := range []struct {
		label string
		n     int64
		why   string
	}{
		{"obsolete:", r.Obsolete, "already at their encrypted key; the plaintext deleted"},
		{"written by the gateway:", r.Skipped, "nothing to do"},
		{"conflicted:", r.Conflicted, "a client wrote them during the run, or see the log"},
		{"needs migrate-names:", r.NeedsNameMigration, "the gateway wrote them with names in clear"},
		{"too long:", r.TooLong, "encrypted, the key would pass 1024 bytes"},
		{"tagged:", r.Tagged, "an overwrite would drop their tags; left"},
		{"locked:", r.Locked, "under a legal hold or retention; left"},
		{"unreadable:", r.Unreadable, "SSE-C, or otherwise not readable; left"},
		{"failed:", r.Failed, "see the log"},
	} {
		if line.n > 0 {
			_, _ = fmt.Fprintf(w, "  %-22s %d  (%s)\n", line.label, line.n, line.why)
		}
	}
}

// encryptRun is what the command knows about a run beyond the package's counts.
type encryptRun struct {
	Bucket, Prefix                        string
	DryRun, Unconditional, NamesEncrypted bool
	Started                               time.Time
	Elapsed                               time.Duration
}

// encryptJSON is the `encrypt-existing --json` document (ADR-034), shaped as
// rotate's, gc's and migrate-names' are: every count always present, and no
// field name that moves with --dry-run.
type encryptJSON struct {
	Bucket             string  `json:"bucket"`
	Prefix             string  `json:"prefix"`
	DryRun             bool    `json:"dry_run"`
	Unconditional      bool    `json:"unconditional"`
	NamesEncrypted     bool    `json:"names_encrypted"`
	Started            string  `json:"started"`
	DurationSeconds    float64 `json:"duration_seconds"`
	Scanned            int64   `json:"scanned"`
	Encrypted          int64   `json:"encrypted"`
	Obsolete           int64   `json:"obsolete"`
	Skipped            int64   `json:"skipped"`
	Conflicted         int64   `json:"conflicted"`
	NeedsNameMigration int64   `json:"needs_name_migration"`
	TooLong            int64   `json:"too_long"`
	Tagged             int64   `json:"tagged"`
	Locked             int64   `json:"locked"`
	Unreadable         int64   `json:"unreadable"`
	Failed             int64   `json:"failed"`
	BytesEncrypted     int64   `json:"bytes_encrypted"`
}

// marshalEncryptJSON renders a run's summary as newline-terminated JSON, with
// the start in RFC 3339 UTC and the duration in seconds to the millisecond.
func marshalEncryptJSON(run encryptRun, r *encrypt.Result) ([]byte, error) {
	data, err := json.Marshal(encryptJSON{
		Bucket: run.Bucket, Prefix: run.Prefix,
		DryRun: run.DryRun, Unconditional: run.Unconditional, NamesEncrypted: run.NamesEncrypted,
		Started:            run.Started.UTC().Format(time.RFC3339),
		DurationSeconds:    run.Elapsed.Round(time.Millisecond).Seconds(),
		Scanned:            r.Scanned,
		Encrypted:          r.Encrypted,
		Obsolete:           r.Obsolete,
		Skipped:            r.Skipped,
		Conflicted:         r.Conflicted,
		NeedsNameMigration: r.NeedsNameMigration,
		TooLong:            r.TooLong,
		Tagged:             r.Tagged,
		Locked:             r.Locked,
		Unreadable:         r.Unreadable,
		Failed:             r.Failed,
		BytesEncrypted:     r.BytesEncrypted,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
