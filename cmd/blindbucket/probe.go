package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/probe"
)

// errUnguarded makes probe exit non-zero when a guarded rotation would be
// refused, so a script can ask the question without parsing the table.
var errUnguarded = errors.New("the provider does not enforce both conditional writes; " +
	"a rotation needs --allow-unconditional here")

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket probe --config <file> s3://<bucket>

Measures what the provider does with the conditional writes blindbucket relies
on, rather than assuming it.

A rotation guards two windows with a precondition each, and a provider that
ignores one looks exactly like a provider that allowed the write: Garage v2.4.1
completes a multipart upload whatever If-Match says. So this asks with a
condition that must fail and reports what happened to it -- enforced, ignored,
or refused. It is the same measurement a rotation makes before it starts
(ADR-020), without the rotation. A third condition, If-None-Match on the
completion, is the one migrate-names relies on (ADR-022), and is reported
separately.

It writes one small object under .blindbucket/probe/ and removes it again. The
keyring is not needed. Exits 0 when both conditions a rotation relies on are
enforced, 1 otherwise; the migration's condition does not change the exit
status, so read it from the output.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		jsonOut = jsonFlag(fs, "the result")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errUsage
	}
	bucket, prefix, err := parseS3Target(fs.Arg(0))
	if err != nil {
		return err
	}
	if prefix != "" {
		return fmt.Errorf("probe measures a bucket, not a prefix: use s3://%s", bucket)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	client, _, err := upstreamClient(cfg, nil)
	if err != nil {
		return err
	}

	conditions, err := probe.ConditionalWrites(ctx, client, bucket)
	if err != nil {
		return err
	}
	if *jsonOut {
		data, err := marshalProbeJSON(bucket, conditions)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
	} else {
		printProbe(os.Stdout, bucket, conditions)
	}
	if !conditions.SafeForRotation() {
		return errUnguarded
	}
	return nil
}

func printProbe(w io.Writer, bucket string, c probe.Conditions) {
	_, _ = fmt.Fprintf(w, "conditional writes on %s:\n", bucket)
	for _, check := range append(c.RotationChecks(), c.MigrationChecks()...) {
		_, _ = fmt.Fprintf(w, "  %-46s %s\n", check.Name, check.Outcome)
		if check.Detail != "" {
			_, _ = fmt.Fprintf(w, "  %-46s %s\n", "", check.Detail)
		}
	}
	for _, verdict := range []struct {
		what    string
		guarded bool
	}{
		{"rotation", c.SafeForRotation()},
		{"migrate-names", c.SafeForMigration()},
	} {
		if verdict.guarded {
			_, _ = fmt.Fprintf(w, "%s: guarded\n", verdict.what)
		} else {
			_, _ = fmt.Fprintf(w, "%s: refused without --allow-unconditional\n", verdict.what)
		}
	}
}

// probeJSON is the `probe --json` document. checks and guarded are about
// rotation and mean what they meant in 1.0 (ADR-021); the condition a name
// migration relies on came later and has a field of its own, so that a consumer
// that reads checks to decide about a rotation does not change its answer.
type probeJSON struct {
	Bucket    string           `json:"bucket"`
	Checks    []probeCheckJSON `json:"checks"`
	Guarded   bool             `json:"guarded"`
	Migration probeVerdictJSON `json:"migration"`
}

type probeVerdictJSON struct {
	Checks  []probeCheckJSON `json:"checks"`
	Guarded bool             `json:"guarded"`
}

type probeCheckJSON struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

func marshalProbeJSON(bucket string, c probe.Conditions) ([]byte, error) {
	out := probeJSON{
		Bucket: bucket, Guarded: c.SafeForRotation(), Checks: checksJSON(c.RotationChecks()),
		Migration: probeVerdictJSON{
			Guarded: c.SafeForMigration(), Checks: checksJSON(c.MigrationChecks()),
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func checksJSON(checks []probe.Check) []probeCheckJSON {
	out := []probeCheckJSON{}
	for _, check := range checks {
		out = append(out, probeCheckJSON{
			Name: check.Name, Outcome: check.Outcome.String(), Detail: check.Detail,
		})
	}
	return out
}
