package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/awscreds"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/doctor"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket doctor [--config <file>] [flags] [s3://<bucket> ...]

Checks whether serve would start with this configuration, and whether clients
would then work: the configuration, the listener and its TLS, the keyring and
what seals it, the keys the configured features need, the audit log and the
rollback index, the provider's credentials, each bucket, the provider's
conditional writes, and this host's clock. Every check runs; none stops the
others, so one run shows everything that is wrong, and each finding names what
to change.

Without a bucket it checks every bucket clients[].buckets names.

It writes one small object under .blindbucket/probe/ in each bucket and
removes it again, to measure the conditional writes rotation relies on, as
probe does; --no-write skips that check. It opens the keyring the way serve
does, so a passphrase keyring needs its passphrase.

Exits 0 when no check failed, warnings included, and 1 when one did.

Flags:
`)
		fs.PrintDefaults()
	}
	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		jsonOut = jsonFlag(fs, "the checks")
		noWrite = fs.Bool("no-write", false,
			"skip the one check that writes to the provider (conditional_writes)")
		pass passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	defer pass.wipe()

	var buckets []string
	for _, target := range fs.Args() {
		bucket, prefix, err := parseS3Target(target)
		if err != nil {
			return err
		}
		if prefix != "" {
			return fmt.Errorf("doctor checks a bucket, not a prefix: use s3://%s", bucket)
		}
		buckets = append(buckets, bucket)
	}

	checks := diagnose(ctx, *cfgPath, buckets, *noWrite, &pass, time.Now())
	if *jsonOut {
		data, err := marshalDoctorJSON(*cfgPath, checks)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
	} else {
		printDoctor(os.Stdout, checks)
	}
	if n := doctor.Failures(checks); n > 0 {
		return fmt.Errorf("%d of %d checks failed", n, len(checks))
	}
	return nil
}

// diagnose runs every check, in the order of the names in internal/doctor. A
// check that depends on one that failed is reported as skipped rather than
// left out, so that the set of checks is the same on every run.
func diagnose(
	ctx context.Context, cfgPath string, buckets []string, noWrite bool, pass *passphraseFlags, now time.Time,
) []doctor.Check {
	var checks []doctor.Check
	add := func(c doctor.Check) { checks = append(checks, c) }

	cfg, err := config.Load(cfgPath)
	if err != nil {
		add(doctor.Fail(doctor.NameConfig, err.Error(), configFix(err)))
		why := "the configuration did not load"
		for _, name := range []string{
			doctor.NameListener, doctor.NameTLS, doctor.NameKeyring, doctor.NameFeatureKeys,
			doctor.NameTenants, doctor.NameAuditLog, doctor.NameFreshnessIndex, doctor.NameUpstreamCreds,
		} {
			add(doctor.Skip(name, why))
		}
		addSkippedBuckets(add, orNone(buckets), why)
		add(doctor.Skip(doctor.NameClock, why))
		return checks
	}
	add(doctor.Ok(doctor.NameConfig, "loaded "+cfgPath))
	add(listenerCheck(cfg))
	if cfg.Server.TLS.Enabled() {
		add(doctor.TLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile, now))
	} else {
		add(doctor.Skip(doctor.NameTLS, "server.tls is not configured"))
	}

	file, keyringCheck := checkKeyring(ctx, cfg, pass)
	add(keyringCheck)
	if file != nil {
		add(featureKeysCheck(cfg, file.Default))
		add(tenantsCheck(cfg, file))
	} else {
		add(doctor.Skip(doctor.NameFeatureKeys, "the keyring did not open"))
		add(doctor.Skip(doctor.NameTenants, "the keyring did not open"))
	}
	if cfg.Audit.Enabled() {
		add(doctor.Writable(doctor.NameAuditLog, "audit.log", cfg.Audit.Log))
	} else {
		add(doctor.Skip(doctor.NameAuditLog, "audit.log is not set"))
	}
	if cfg.Freshness.Enabled() {
		add(doctor.Writable(doctor.NameFreshnessIndex, "freshness.index", cfg.Freshness.Index))
	} else {
		add(doctor.Skip(doctor.NameFreshnessIndex, "freshness.index is not set"))
	}

	credsCheck := upstreamCredentialsCheck(ctx, cfg)
	add(credsCheck)

	if len(buckets) == 0 {
		buckets = configuredBuckets(cfg)
	}
	if len(buckets) == 0 {
		c := doctor.Fail(doctor.NameBucket, `clients[].buckets names only "*", so there is no bucket to check`,
			"name one: blindbucket doctor s3://<bucket>")
		add(c)
		add(doctor.Skip(doctor.NameConditionalWrites, "no bucket to check"))
		add(doctor.Skip(doctor.NameClock, "no request was made to the provider"))
		return checks
	}
	if credsCheck.Outcome == doctor.Failed {
		why := "the provider's credentials did not resolve"
		addSkippedBuckets(add, buckets, why)
		add(doctor.Skip(doctor.NameClock, why))
		return checks
	}

	// One attempt per request: a retried timeout would triple how long doctor
	// takes to say that nothing answers.
	httpClient := upstream.DefaultHTTPClient()
	recorder := doctor.NewRecorder(httpClient.Transport)
	httpClient.Transport = recorder
	client, _, err := upstreamClientWith(cfg, upstream.Config{HTTPClient: httpClient, MaxRetries: 1})
	if err != nil {
		for _, bucket := range buckets {
			c := doctor.Fail(doctor.NameBucket, err.Error(), "check the upstream section of the configuration")
			c.Bucket = bucket
			add(c)
			add(skipped(doctor.NameConditionalWrites, bucket, "the bucket check failed"))
		}
		add(doctor.Skip(doctor.NameClock, "no request was made to the provider"))
		return checks
	}
	provider := doctor.Provider{
		Client: client, Recorder: recorder, Endpoint: cfg.Upstream.Endpoint, Region: cfg.Upstream.Region,
	}
	for _, bucket := range buckets {
		access := provider.Bucket(ctx, bucket)
		add(access)
		switch {
		case access.Outcome != doctor.OK:
			add(skipped(doctor.NameConditionalWrites, bucket, "the bucket check failed"))
		case noWrite:
			add(skipped(doctor.NameConditionalWrites, bucket, "--no-write"))
		default:
			add(provider.ConditionalWrites(ctx, bucket))
		}
	}
	add(provider.Clock())
	return checks
}

func skipped(name, bucket, why string) doctor.Check {
	c := doctor.Skip(name, why)
	c.Bucket = bucket
	return c
}

func addSkippedBuckets(add func(doctor.Check), buckets []string, why string) {
	for _, bucket := range buckets {
		add(skipped(doctor.NameBucket, bucket, why))
		add(skipped(doctor.NameConditionalWrites, bucket, why))
	}
}

// orNone stands in for the buckets a configuration that did not load would
// have named, so that the per-bucket checks are still reported once.
func orNone(buckets []string) []string {
	if len(buckets) == 0 {
		return []string{""}
	}
	return buckets
}

// configuredBuckets are the buckets the clients may use, each once, in the
// order they first appear. "*" names none of them.
func configuredBuckets(cfg *config.Config) []string {
	var out []string
	for _, c := range cfg.Clients {
		for _, b := range c.Buckets {
			if b != "*" && !slices.Contains(out, b) {
				out = append(out, b)
			}
		}
	}
	return out
}

func configFix(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "--config names no file; `blindbucket init` writes one"
	case strings.Contains(msg, "which is not set"):
		return "set the variable before running; for a configuration `blindbucket init` wrote: " +
			"set -a; . ./blindbucket.env; set +a"
	}
	return "correct the setting the error names; blindbucket.example.yaml describes every one"
}

func listenerCheck(cfg *config.Config) doctor.Check {
	if cfg.ExposesPlaintextPublicly() {
		return doctor.Warn(doctor.NameListener,
			fmt.Sprintf("server.listen %s carries plaintext beyond loopback, without TLS", cfg.Server.Listen),
			"configure server.tls, or listen on loopback -- unless clients and gateway share a trust boundary")
	}
	how := "on loopback"
	if cfg.Server.TLS.Enabled() {
		how = "with TLS"
	}
	return doctor.Ok(doctor.NameListener, fmt.Sprintf("server.listen %s, %s", cfg.Server.Listen, how))
}

// checkKeyring opens the keyring by the route serve takes, every tenant
// keys.tenants can open included, and returns it for the checks that need
// what is inside.
func checkKeyring(ctx context.Context, cfg *config.Config, pass *passphraseFlags) (*keys.File, doctor.Check) {
	path := cfg.Keys.Keyring
	info, err := os.Stat(path)
	if err != nil {
		return nil, doctor.Fail(doctor.NameKeyring, err.Error(), fmt.Sprintf(
			"keys.keyring must name the keyring file; `blindbucket init` or `blindbucket keygen --out %s` creates one",
			path))
	}
	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	//nolint:gosec // the path comes from the operator's own configuration.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, doctor.Fail(doctor.NameKeyring, err.Error(),
			"the user doctor and serve run as must be able to read "+path)
	}
	// unlockFile rather than openFile: openFile also warns about the file's
	// mode on stderr, which this check reports itself.
	f, err := unlockFile(ctx, path, data, cfg.Keys, pass, openTenants(ctx, cfg.Keys))
	if err != nil {
		return nil, doctor.Fail(doctor.NameKeyring, err.Error(), keyringFix(cfg.Keys))
	}

	ring := f.Default
	detail := fmt.Sprintf("sealed by %s; %s, %s active", sealedBy(cfg.Keys), pluralize(len(ring.KIDs()), "key"), ring.ActiveKID())
	if f.Generation > 0 {
		detail += fmt.Sprintf("; generation %d", f.Generation)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return f, doctor.Warn(doctor.NameKeyring, fmt.Sprintf("%s; mode %04o", detail, mode),
			fmt.Sprintf("chmod 600 %s: it is readable beyond its owner", path))
	}
	return f, doctor.Ok(doctor.NameKeyring, detail)
}

// tenantsCheck reports what serve would make of the keyring's tenants
// (ADR-038). A tenant that does not open fails it: serve starts, but answers
// 503 for every one of its buckets. A tenant under the deployment's lock, and
// a keys.tenants entry for a tenant the keyring does not have, warn.
func tenantsCheck(cfg *config.Config, f *keys.File) doctor.Check {
	var unknown []string
	for name := range cfg.Keys.Tenants {
		if f.Tenant(name) == nil {
			unknown = append(unknown, name)
		}
	}
	slices.Sort(unknown)
	if len(f.Tenants) == 0 && len(unknown) == 0 {
		return doctor.Skip(doctor.NameTenants, "the keyring has no tenants")
	}

	var unopened, deployment, inactive, why []string
	for _, t := range f.Tenants {
		switch {
		case t.Ring == nil:
			unopened = append(unopened, t.Name)
			why = append(why, fmt.Sprintf("%s: %v", t.Name, t.Err))
		case t.Lock().Source == keys.LockDeployment:
			deployment = append(deployment, t.Name)
		}
		if t.ActiveKID == "" {
			inactive = append(inactive, t.Name)
		}
	}
	detail := fmt.Sprintf("%s, %d open", pluralize(len(f.Tenants), "tenant"), len(f.Tenants)-len(unopened))
	if len(f.Tombstones) > 0 {
		detail += fmt.Sprintf(", %d destroyed", len(f.Tombstones))
	}
	if len(inactive) > 0 {
		detail += "; not active yet: " + strings.Join(inactive, ", ")
	}

	switch {
	case len(unopened) > 0:
		return doctor.Fail(doctor.NameTenants,
			fmt.Sprintf("%s; did not open: %s", detail, strings.Join(why, "; ")),
			fmt.Sprintf("each tenant needs keys.tenants.<name> naming its lock, with credentials that may "+
				"decrypt with it; until then serve answers 503 for the buckets of %s",
				strings.Join(unopened, ", ")))
	case len(unknown) > 0:
		return doctor.Warn(doctor.NameTenants,
			fmt.Sprintf("%s; keys.tenants names %s, which the keyring does not have", detail, strings.Join(unknown, ", ")),
			"remove the entry, or check its spelling against `blindbucket tenants list`")
	case len(deployment) > 0:
		return doctor.Warn(doctor.NameTenants,
			fmt.Sprintf("%s; under the deployment's lock: %s", detail, strings.Join(deployment, ", ")),
			"every copy of the keyring opens their keys with the deployment's root key, so destroying "+
				"them rests on those copies; `blindbucket reseal --tenant <name>` gives each a lock of its own")
	}
	return doctor.Ok(doctor.NameTenants, detail)
}

func keyringFix(cfg config.Keys) string {
	switch cfg.Provider {
	case "vault":
		return "check keys.vault: the address, the token, and that the token may decrypt " +
			"with the Transit key " + cfg.Vault.KeyName
	case "awskms":
		return "check keys.awskms: the region, the key, and that the credentials may " +
			"kms:Decrypt with " + cfg.AWSKMS.KeyID
	}
	return "check the passphrase: $" + passphraseEnv + ", keys.passphrase_file or --passphrase-file -- " +
		"or, if the keyring was sealed by a service, set keys.provider to it"
}

// featureKeysCheck finds the keys the configured features need and the
// keyring lacks. serve refuses to start without them.
func featureKeysCheck(cfg *config.Config, ring *keys.Keyring) doctor.Check {
	type feature struct {
		on      bool
		setting string
		has     bool
		flag    string
	}
	_, hasName := ring.NameKey()
	_, hasAudit := ring.AuditKey()
	_, hasFresh := ring.FreshnessKey()
	features := []feature{
		{cfg.Names.Encrypt, "names.encrypt", hasName, "--add-name-key"},
		{cfg.Audit.Enabled(), "audit.log", hasAudit, "--add-audit-key"},
		{cfg.Freshness.Enabled(), "freshness.index", hasFresh, "--add-freshness-key"},
	}
	var on, missing, flags []string
	for _, f := range features {
		if !f.on {
			continue
		}
		on = append(on, f.setting)
		if !f.has {
			missing = append(missing, f.setting)
			flags = append(flags, f.flag)
		}
	}
	switch {
	case len(on) == 0:
		return doctor.Skip(doctor.NameFeatureKeys, "names.encrypt, audit.log and freshness.index are all off")
	case len(missing) > 0:
		return doctor.Fail(doctor.NameFeatureKeys,
			fmt.Sprintf("%s set, but the keyring has no key for it", strings.Join(missing, ", ")),
			fmt.Sprintf("blindbucket keygen --out %s %s", cfg.Keys.Keyring, strings.Join(flags, " ")))
	}
	return doctor.Ok(doctor.NameFeatureKeys, "the keyring has a key for "+strings.Join(on, ", "))
}

// upstreamCredentialsCheck asks a credential source for credentials once, as
// serve does at startup.
func upstreamCredentialsCheck(ctx context.Context, cfg *config.Config) doctor.Check {
	src := cfg.Upstream.CredentialSource
	if src == "" || src == awscreds.SourceStatic {
		return doctor.Skip(doctor.NameUpstreamCreds,
			"the configuration holds keys; the bucket check tests them")
	}
	creds, err := awsCredentials(src, cfg.Upstream.Region)
	if err == nil {
		got, rerr := creds.Retrieve(ctx)
		if rerr == nil {
			return doctor.Ok(doctor.NameUpstreamCreds,
				fmt.Sprintf("%s answered with access key %s", creds.Source(), got.AccessKeyID))
		}
		err = rerr
	}
	return doctor.Fail(doctor.NameUpstreamCreds, err.Error(), fmt.Sprintf(
		"upstream.credential_source %q gives no credentials on this host; ADR-024 says what each source needs",
		src))
}

func printDoctor(w io.Writer, checks []doctor.Check) {
	names := make([]string, len(checks))
	width := 0
	for i, c := range checks {
		names[i] = c.Name
		if c.Bucket != "" {
			names[i] += " " + c.Bucket
		}
		width = max(width, len(names[i]))
	}
	for i, c := range checks {
		_, _ = fmt.Fprintf(w, "%-8s %-*s  %s\n", c.Outcome, width, names[i], c.Detail)
		if c.Fix != "" {
			_, _ = fmt.Fprintf(w, "%-8s %-*s  fix: %s\n", "", width, "", c.Fix)
		}
	}
	_, _ = fmt.Fprintf(w, "\n%d failed, %s\n", doctor.Failures(checks), pluralize(doctor.Warnings(checks), "warning"))
}

// pluralize says n of what, in the singular for one.
func pluralize(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// doctorJSON is the `doctor --json` document, stable under ADR-021. Every
// check is present on every run, skipped ones included, so a consumer can look
// one up by name without asking whether it ran.
type doctorJSON struct {
	Config string            `json:"config"`
	OK     bool              `json:"ok"`
	Checks []doctorCheckJSON `json:"checks"`
}

type doctorCheckJSON struct {
	Name    string `json:"name"`
	Bucket  string `json:"bucket,omitempty"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	Fix     string `json:"fix,omitempty"`
}

func marshalDoctorJSON(cfgPath string, checks []doctor.Check) ([]byte, error) {
	out := doctorJSON{Config: cfgPath, OK: doctor.Failures(checks) == 0, Checks: []doctorCheckJSON{}}
	for _, c := range checks {
		out.Checks = append(out.Checks, doctorCheckJSON{
			Name: c.Name, Bucket: c.Bucket, Outcome: c.Outcome.String(), Detail: c.Detail, Fix: c.Fix,
		})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
