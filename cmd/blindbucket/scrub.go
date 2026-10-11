package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/scrub"
)

func runScrub(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scrub", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket scrub --config <file> s3://<bucket>[/<prefix>]

Reads every object under the prefix from the provider and verifies it exactly as
a GET through the gateway would -- the data key bound to its bucket and key, the
segment header, every chunk, the size, and for a multipart object the manifest
and each part -- then discards the plaintext. Objects that fail are listed with
what failed. Nothing is written, repaired or deleted (ADR-028).

A failure is rechecked before it is reported: an object replaced while it was
being read is verified again in its new version, and one deleted meanwhile is
counted as vanished, so writes during a scrub do not produce findings.

What a scrub cannot say. It sees the version the provider serves now, so an
older genuine version served in place of the latest one passes; rollback is
detected by a gateway with freshness.index, not here. It sees what the listing
shows, so an object the provider deleted is not a finding. And it reads every
byte: on a provider that charges for egress, scrubbing a bucket costs what
downloading it costs.

Objects the gateway did not write are counted, not failed. The exit code is 1 if
any object failed or could not be read.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		workers = fs.Int("concurrency", 4, "objects to verify at once")
		jsonOut = jsonFlag(fs, "the summary and every finding")
		verbose = fs.Bool("v", false, "log at debug level, one line per object")
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
	client, _, err := upstreamClient(cfg, nil)
	if err != nil {
		return err
	}
	// The same encrypter the gateway serves with: without it every data key
	// would be checked against the stored name instead of the one it is bound
	// to, and every object would fail.
	nameEnc, err := openNameEncrypter(cfg, ring, log)
	if err != nil {
		return err
	}

	started := time.Now().UTC()
	result, runErr := scrub.Run(ctx, scrub.Config{
		Upstream: client, Keys: ring, Bucket: bucket, Prefix: prefix, Names: nameEnc,
		Log2ChunkSize: cfg.Crypto.Log2ChunkSize, Concurrency: *workers, Log: log,
	})
	if result == nil {
		return runErr
	}
	elapsed := time.Since(started)

	if *jsonOut {
		// Only a run that finished has a summary to stand behind. One stopped by
		// a failed listing or an interrupt would print counts that read as the
		// state of the prefix when they are the state of part of it.
		if runErr != nil {
			return runErr
		}
		data, err := marshalScrubJSON(scrubRun{
			Bucket: bucket, Prefix: prefix, Started: started, Elapsed: elapsed,
		}, result)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
		return scrubErrors(result)
	}

	for _, f := range result.Findings {
		fmt.Printf("FAILED  %s  (%s) %s\n", f.Key, f.Kind, f.Detail)
	}
	if len(result.Findings) > 0 {
		fmt.Println()
	}
	fmt.Printf("%d objects scanned in %s\n", result.Scanned, elapsed.Round(time.Millisecond))
	fmt.Printf("  verified:   %d  (%d bytes of ciphertext)\n", result.Verified, result.CipherBytes)
	fmt.Printf("  failed:     %d\n", result.Failed)
	if result.Errors > 0 {
		fmt.Printf("  unreadable: %d  (could not be read; see the log)\n", result.Errors)
	}
	if result.Foreign > 0 {
		fmt.Printf("  not ours:   %d  (not written by this gateway)\n", result.Foreign)
	}
	if result.Vanished > 0 {
		fmt.Printf("  vanished:   %d  (deleted during the scrub)\n", result.Vanished)
	}
	if runErr != nil {
		return fmt.Errorf("the scrub did not finish, so the counts above cover part of the prefix: %w", runErr)
	}
	return scrubErrors(result)
}

// scrubErrors is the run's exit status: the summary is printed either way, and
// the exit code says whether every object the gateway wrote verified.
func scrubErrors(result *scrub.Result) error {
	var errs []error
	if result.Failed > 0 {
		errs = append(errs, fmt.Errorf("%d objects failed verification", result.Failed))
	}
	if result.Errors > 0 {
		errs = append(errs, fmt.Errorf("%d objects could not be read; see the log", result.Errors))
	}
	return errors.Join(errs...)
}

// scrubRun is what the command knows about a run beyond scrub's own counts.
type scrubRun struct {
	Bucket, Prefix string
	Started        time.Time
	Elapsed        time.Duration
}

// scrubJSON is the `scrub --json` document, shaped as the other commands' are:
// every count always present, the start in RFC 3339 UTC, the duration in
// seconds. findings is always an array, empty when nothing failed, so that a
// consumer can iterate it without asking first.
type scrubJSON struct {
	Bucket          string             `json:"bucket"`
	Prefix          string             `json:"prefix"`
	Started         string             `json:"started"`
	DurationSeconds float64            `json:"duration_seconds"`
	Scanned         int64              `json:"scanned"`
	Verified        int64              `json:"verified"`
	Failed          int64              `json:"failed"`
	Unreadable      int64              `json:"unreadable"`
	Foreign         int64              `json:"foreign"`
	Vanished        int64              `json:"vanished"`
	CiphertextBytes int64              `json:"ciphertext_bytes"`
	Findings        []scrubFindingJSON `json:"findings"`
}

// scrubFindingJSON is one object that failed. kind is one of a fixed set
// (metadata, unknown_kid, dek_unwrap, header, chunk, size, manifest) and is the
// field to act on; detail is for a person and may change between releases.
type scrubFindingJSON struct {
	Key    string `json:"key"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// marshalScrubJSON renders a run as newline-terminated JSON.
func marshalScrubJSON(run scrubRun, result *scrub.Result) ([]byte, error) {
	findings := make([]scrubFindingJSON, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, scrubFindingJSON{Key: f.Key, Kind: string(f.Kind), Detail: f.Detail})
	}
	data, err := json.Marshal(scrubJSON{
		Bucket: run.Bucket, Prefix: run.Prefix,
		Started:         run.Started.UTC().Format(time.RFC3339),
		DurationSeconds: run.Elapsed.Round(time.Millisecond).Seconds(),
		Scanned:         result.Scanned,
		Verified:        result.Verified,
		Failed:          result.Failed,
		Unreadable:      result.Errors,
		Foreign:         result.Foreign,
		Vanished:        result.Vanished,
		CiphertextBytes: result.CipherBytes,
		Findings:        findings,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
