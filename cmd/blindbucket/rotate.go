package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

func runRotate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket rotate --config <file> --to-kid <kid> s3://<bucket>[/<prefix>]

Re-wraps the data keys of stored objects under a different KEK.

Only metadata moves. Each object keeps its data key; what changes is the key that
wraps it, so the ciphertext never leaves the provider and a terabyte costs the
same as a megabyte. The honest limit: this protects against a compromised or
expiring KEK, not against a compromised data key.

Objects already wrapped under --to-kid are skipped, so a run is idempotent and an
interrupted one can simply be started again.

Rotation reads an object and writes it back a moment later. If a client replaces
it in between, the client wins: the final write carries If-Match with the ETag
read at the start, and a 412 makes the object a skip rather than a silent
overwrite. That is invariant I2 in spec/tla/, which has a six-state counterexample
for the version without it.

Not every provider enforces that condition, and one that ignores it looks exactly
like one that allowed the write. So before touching anything, a run measures both
conditions with a probe object under .blindbucket/probe/, and refuses to start if
either is not enforced -- in a dry run too. --allow-unconditional skips the
measurement along with the condition (ADR-020).

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		toKID   = fs.String("to-kid", "", "key id to wrap under; defaults to the active key")
		workers = fs.Int("concurrency", 8, "objects to rotate at once")
		dryRun  = fs.Bool("dry-run", false, "report what would be rotated, change nothing")
		jsonOut = fs.Bool("json", false, "emit the summary as JSON")
		uncond  = fs.Bool("allow-unconditional", false,
			"write without If-Match; gives up I2, see the warning it prints")
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
	ring, err := loadServerKeyring(ctx, cfg, &pass)
	if err != nil {
		return err
	}
	target := *toKID
	if target == "" {
		target = ring.ActiveKID()
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
		// Loud, and on the way out rather than in the log, because the operator
		// running this has to have decided it.
		_, _ = fmt.Fprintln(os.Stderr,
			"warning: --allow-unconditional writes without If-Match. A client write that\n"+
				"         lands during the rotation will be silently replaced by the\n"+
				"         pre-rotation version. Nothing may write to this prefix meanwhile.")
	}

	started := time.Now().UTC()
	// The same encrypter the gateway serves with. A rotation that did not have
	// it would see only stored keys and bind every data key to the wrong name.
	nameEnc, err := openNameEncrypter(cfg, ring, log)
	if err != nil {
		return err
	}

	result, err := rotate.Run(ctx, rotate.Config{
		Upstream: client, Keys: ring, Bucket: bucket, Prefix: prefix, Names: nameEnc,
		TargetKID: target, Log2ChunkSize: cfg.Crypto.Log2ChunkSize,
		Concurrency: *workers, DryRun: *dryRun, AllowUnconditional: *uncond, Log: log,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		data, err := marshalRotateJSON(rotateRun{
			Bucket: bucket, Prefix: prefix, TargetKID: target, DryRun: *dryRun,
			Unconditional: *uncond, Started: started, Elapsed: time.Since(started),
		}, result)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
		return rotateErrors(result)
	}

	verb := "rotated"
	if *dryRun {
		verb = "would rotate"
	}
	fmt.Printf("%d objects scanned in %s\n", result.Scanned, result.Duration(started))
	fmt.Printf("  %s:          %d  (to %q)\n", verb, result.Rotated, target)
	fmt.Printf("  already current: %d\n", result.AlreadyCurrent)
	if result.Conflicted > 0 {
		fmt.Printf("  skipped:         %d  (written by a client during the rotation; run again)\n",
			result.Conflicted)
	}
	if result.Foreign > 0 {
		fmt.Printf("  not ours:        %d  (no gateway metadata)\n", result.Foreign)
	}
	return rotateErrors(result)
}

// rotateErrors is the run's exit status, decided as gc decides it: a partially
// failed rotation still prints its summary in either format, and the failure is
// carried by the exit code and by a failed field that is always present.
func rotateErrors(result *rotate.Result) error {
	if result.Failed > 0 {
		return fmt.Errorf("%d objects could not be rotated; see the log", result.Failed)
	}
	return nil
}

// rotateRun is what the command knows about a run beyond rotate's own counts.
type rotateRun struct {
	Bucket, Prefix, TargetKID string
	DryRun, Unconditional     bool
	Started                   time.Time
	Elapsed                   time.Duration
}

// rotateJSON is the `rotate --json` document, shaped as `gc --json` is: every
// count always present, and no field name that moves with --dry-run.
//
// target_kid is the field the text output only interpolates into its verb line,
// and the one an automated caller most needs: it is what the run was for.
// conflicted is the other: above zero, the rotation needs running again.
type rotateJSON struct {
	Bucket          string  `json:"bucket"`
	Prefix          string  `json:"prefix"`
	TargetKID       string  `json:"target_kid"`
	DryRun          bool    `json:"dry_run"`
	Unconditional   bool    `json:"unconditional"`
	Started         string  `json:"started"`
	DurationSeconds float64 `json:"duration_seconds"`
	Scanned         int64   `json:"scanned"`
	Rotated         int64   `json:"rotated"`
	AlreadyCurrent  int64   `json:"already_current"`
	Conflicted      int64   `json:"conflicted"`
	Foreign         int64   `json:"foreign"`
	Failed          int64   `json:"failed"`
}

// marshalRotateJSON renders a run's summary as newline-terminated JSON, with the
// start in RFC 3339 UTC and the duration in seconds to the millisecond.
func marshalRotateJSON(run rotateRun, result *rotate.Result) ([]byte, error) {
	data, err := json.Marshal(rotateJSON{
		Bucket: run.Bucket, Prefix: run.Prefix, TargetKID: run.TargetKID,
		DryRun: run.DryRun, Unconditional: run.Unconditional,
		Started:         run.Started.UTC().Format(time.RFC3339),
		DurationSeconds: run.Elapsed.Round(time.Millisecond).Seconds(),
		Scanned:         result.Scanned,
		Rotated:         result.Rotated,
		AlreadyCurrent:  result.AlreadyCurrent,
		Conflicted:      result.Conflicted,
		Foreign:         result.Foreign,
		Failed:          result.Failed,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
