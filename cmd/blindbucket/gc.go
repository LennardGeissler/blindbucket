package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/gc"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

func runGC(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket gc --config <file> s3://<bucket>[/<prefix>]

Removes orphaned multipart manifests.

A manifest is orphaned when the object version it describes is no longer the
visible one: a single-part upload replaced a multipart object, an upload crashed
before completing, or the object was deleted in a batch. Orphans hold no
plaintext; they only cost storage.

The pass follows a fixed order (ADR-010, rule R4): list the manifests,
then ask for open uploads and skip any key that has one, then read the manifest
id the visible object uses, and only then delete the rest. That order is
model-checked in spec/tla/, and swapping the first two steps -- both of which
only read -- is enough to make an object unreadable.

Manifests younger than --min-age are left alone whatever the other steps say.
This is a second line of defence for providers whose read-after-write
consistency does not hold as assumed; the default suits the seven-day lifecycle
rule for incomplete uploads that the README recommends.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		minAge  = fs.Duration("min-age", gc.DefaultMinAge,
			"leave manifests younger than this alone; 0 disables the guard")
		dryRun  = fs.Bool("dry-run", false, "report what would be deleted, delete nothing")
		jsonOut = fs.Bool("json", false, "emit the summary as JSON")
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

	started := time.Now().UTC()
	result, err := gc.Run(ctx, gc.Config{
		Upstream:      client,
		Bucket:        bucket,
		Prefix:        prefix,
		MinAge:        *minAge,
		DisableMinAge: *minAge == 0,
		DryRun:        *dryRun,
		Log:           log,
	})
	if err != nil {
		return err
	}

	elapsed := time.Since(started)

	if *jsonOut {
		data, err := marshalGCJSON(gcRun{
			Bucket: bucket, Prefix: prefix, DryRun: *dryRun,
			Started: started, Elapsed: elapsed,
		}, result)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
		return gcErrors(result)
	}

	verb := "deleted"
	if *dryRun {
		verb = "would delete"
	}
	fmt.Printf("%d manifests seen across %d keys in %s\n",
		result.ManifestsSeen, result.KeysScanned, elapsed.Round(time.Millisecond))
	fmt.Printf("  %s:        %d\n", verb, result.Deleted)
	fmt.Printf("  kept, current:  %d\n", result.KeptCurrent)
	fmt.Printf("  kept, too new:  %d\n", result.KeptTooYoung)
	if result.KeysSkipped > 0 {
		fmt.Printf("  keys skipped:   %d (an upload was in flight)\n", result.KeysSkipped)
	}
	if result.KeptUnreadable > 0 {
		fmt.Printf("  kept, unreadable: %d (not written by this gateway)\n", result.KeptUnreadable)
	}
	return gcErrors(result)
}

// gcErrors is the run's exit status. A partially failed run still prints its
// summary, in either format: the counts are what a monitoring system most needs
// when something went wrong, and the failure is carried by the exit code and,
// in the JSON, by an errors field that is always present.
func gcErrors(result *gc.Result) error {
	if result.Errors > 0 {
		return fmt.Errorf("%d manifests or keys could not be processed; see the log", result.Errors)
	}
	return nil
}

// gcRun is what the command knows about a run beyond gc's own counts.
type gcRun struct {
	Bucket, Prefix string
	DryRun         bool
	Started        time.Time
	Elapsed        time.Duration
}

// gcJSON is the `gc --json` document. Every count is always present, zero
// included, and no field name depends on --dry-run: the text output's
// "would delete" becomes dry_run next to a deleted count that means "would
// have deleted" when it is set.
type gcJSON struct {
	Bucket          string  `json:"bucket"`
	Prefix          string  `json:"prefix"`
	DryRun          bool    `json:"dry_run"`
	Started         string  `json:"started"`
	DurationSeconds float64 `json:"duration_seconds"`
	ManifestsSeen   int     `json:"manifests_seen"`
	KeysScanned     int     `json:"keys_scanned"`
	Deleted         int     `json:"deleted"`
	KeptCurrent     int     `json:"kept_current"`
	KeptTooNew      int     `json:"kept_too_new"`
	KeysSkipped     int     `json:"keys_skipped"`
	KeptUnreadable  int     `json:"kept_unreadable"`
	Errors          int     `json:"errors"`
}

// marshalGCJSON renders a run's summary as newline-terminated JSON, with the
// start in RFC 3339 UTC and the duration in seconds to the millisecond.
func marshalGCJSON(run gcRun, result *gc.Result) ([]byte, error) {
	data, err := json.Marshal(gcJSON{
		Bucket: run.Bucket, Prefix: run.Prefix, DryRun: run.DryRun,
		Started:         run.Started.UTC().Format(time.RFC3339),
		DurationSeconds: run.Elapsed.Round(time.Millisecond).Seconds(),
		ManifestsSeen:   result.ManifestsSeen,
		KeysScanned:     result.KeysScanned,
		Deleted:         result.Deleted,
		KeptCurrent:     result.KeptCurrent,
		KeptTooNew:      result.KeptTooYoung,
		KeysSkipped:     result.KeysSkipped,
		KeptUnreadable:  result.KeptUnreadable,
		Errors:          result.Errors,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// parseS3Target splits an s3://bucket/prefix argument.
func parseS3Target(target string) (bucket, prefix string, err error) {
	rest, ok := strings.CutPrefix(target, "s3://")
	if !ok {
		return "", "", fmt.Errorf("target %q must look like s3://bucket or s3://bucket/prefix", target)
	}
	bucket, prefix, _ = strings.Cut(rest, "/")
	if bucket == "" {
		return "", "", fmt.Errorf("target %q names no bucket", target)
	}
	return bucket, prefix, nil
}
