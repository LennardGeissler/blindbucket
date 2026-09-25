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
	"github.com/LennardGeissler/blindbucket/internal/upstream"
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
(ADR-020), without the rotation.

It writes one small object under .blindbucket/probe/ and removes it again. The
keyring is not needed. Exits 0 when both conditions are enforced, 1 otherwise.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		jsonOut = fs.Bool("json", false, "emit the result as JSON")
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
	if !conditions.Safe() {
		return errUnguarded
	}
	return nil
}

func printProbe(w io.Writer, bucket string, c probe.Conditions) {
	_, _ = fmt.Fprintf(w, "conditional writes on %s:\n", bucket)
	for _, check := range c.Checks() {
		_, _ = fmt.Fprintf(w, "  %-46s %s\n", check.Name, check.Outcome)
		if check.Detail != "" {
			_, _ = fmt.Fprintf(w, "  %-46s %s\n", "", check.Detail)
		}
	}
	if c.Safe() {
		_, _ = fmt.Fprintln(w, "rotation: guarded")
	} else {
		_, _ = fmt.Fprintln(w, "rotation: refused without --allow-unconditional")
	}
}

type probeJSON struct {
	Bucket  string           `json:"bucket"`
	Checks  []probeCheckJSON `json:"checks"`
	Guarded bool             `json:"guarded"`
}

type probeCheckJSON struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

func marshalProbeJSON(bucket string, c probe.Conditions) ([]byte, error) {
	out := probeJSON{Bucket: bucket, Guarded: c.Safe(), Checks: []probeCheckJSON{}}
	for _, check := range c.Checks() {
		out.Checks = append(out.Checks, probeCheckJSON{
			Name: check.Name, Outcome: check.Outcome.String(), Detail: check.Detail,
		})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
