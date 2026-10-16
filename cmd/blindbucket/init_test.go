package main

import (
	"bufio"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/config"
)

// initEnv sets the environment a non-interactive init reads, clearing what a
// developer's shell or a CI runner might already hold.
func initEnv(t *testing.T) {
	t.Helper()
	t.Setenv(passphraseEnv, testPassphrase)
	t.Setenv(envUpstreamKeyID, "upstream-key")
	t.Setenv(envUpstreamSecret, "upstream-secret")
	for _, name := range []string{envVaultToken, envKMSKeyID, envKMSSecret, envClientKeyID, envClientSecret} {
		t.Setenv(name, "")
	}
}

// readInitEnv parses an environment file init wrote.
func readInitEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path) //nolint:gosec // a file the test just had written.
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = file.Close() }()
	vars := map[string]string{}
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		line := scan.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, quoted, ok := strings.Cut(line, "=")
		if !ok || len(quoted) < 2 || quoted[0] != '\'' || quoted[len(quoted)-1] != '\'' {
			t.Fatalf("%s: a line not of the form NAME='value': %q", filepath.Base(path), line)
		}
		vars[name] = quoted[1 : len(quoted)-1]
	}
	return vars
}

// loadInitConfig loads a configuration init wrote, with the environment its
// environment file holds, as `set -a; . blindbucket.env` would set it.
func loadInitConfig(t *testing.T, dir string) (*config.Config, map[string]string) {
	t.Helper()
	vars := readInitEnv(t, filepath.Join(dir, initEnvName))
	for name, value := range vars {
		t.Setenv(name, value)
	}
	cfg, err := config.Load(filepath.Join(dir, initConfigName))
	if err != nil {
		t.Fatalf("the written configuration does not load: %v", err)
	}
	return cfg, vars
}

func TestInitWritesWhatServeNeeds(t *testing.T) {
	initEnv(t)
	dir := filepath.Join(t.TempDir(), "not-there-yet")

	stdout, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
		"--endpoint", "http://localhost:9002", "--bucket", "photos", "--kid", "2026-10")
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	for _, name := range []string{initConfigName, initKeyringName, initEnvName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", name, mode)
		}
	}

	cfg, vars := loadInitConfig(t, dir)
	if cfg.Upstream.Endpoint != "http://localhost:9002" || cfg.Upstream.Region != "us-east-1" || !cfg.Upstream.PathStyle {
		t.Errorf("upstream = %+v", cfg.Upstream)
	}
	if cfg.Upstream.AccessKeyID != "upstream-key" || cfg.Upstream.SecretAccessKey != "upstream-secret" {
		t.Error("the upstream credentials did not come through the environment file")
	}
	if want := filepath.Join(dir, initKeyringName); cfg.Keys.Keyring != want {
		t.Errorf("keys.keyring = %q, want the absolute %q: serve resolves it against its working directory",
			cfg.Keys.Keyring, want)
	}
	if cfg.Names.Encrypt {
		t.Error("names are encrypted without --encrypt-names")
	}
	if len(cfg.Clients) != 1 || !slices.Equal(cfg.Clients[0].Buckets, []string{"photos"}) {
		t.Fatalf("clients = %+v", cfg.Clients)
	}
	client := cfg.Clients[0]
	if len(client.AccessKeyID) != 20 || !strings.HasPrefix(client.AccessKeyID, "BB") || len(client.SecretAccessKey) != 40 {
		t.Errorf("client credentials %q / %d characters", client.AccessKeyID, len(client.SecretAccessKey))
	}

	ring, err := openKeyring(t.Context(), cfg.Keys.Keyring, cfg.Keys, &passphraseFlags{})
	if err != nil {
		t.Fatalf("the keyring does not open with the configuration: %v", err)
	}
	if ring.ActiveKID() != "2026-10" {
		t.Errorf("active key %q, want 2026-10", ring.ActiveKID())
	}
	if _, ok := ring.NameKey(); !ok {
		t.Error("the keyring has no name key, so names.encrypt could never be turned on")
	}

	// Secrets live in the environment file only, and the passphrase nowhere.
	yaml, err := os.ReadFile(filepath.Join(dir, initConfigName)) //nolint:gosec // written by the test.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, secret := range []string{"upstream-secret", client.SecretAccessKey, testPassphrase} {
		if strings.Contains(string(yaml), secret) {
			t.Errorf("the configuration holds a secret in clear: %q", secret)
		}
	}
	for name, value := range vars {
		if value == testPassphrase {
			t.Errorf("the environment file holds the keyring passphrase as $%s", name)
		}
	}

	for _, want := range []string{client.AccessKeyID, client.SecretAccessKey, "blindbucket serve --config", "blindbucket doctor --config"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the summary does not mention %q:\n%s", want, stdout)
		}
	}
}

// TestInitEnvFileReadsTheSameInAShell checks the one reader the format was
// chosen to be safe for that a test can run: a value with what a shell would
// otherwise expand or split comes back as it went in.
func TestInitEnvFileReadsTheSameInAShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	initEnv(t)
	secret := `a/b+c $HOME "d" e\f` + "`g`"
	t.Setenv(envUpstreamSecret, secret)
	dir := t.TempDir()
	if _, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
		"--endpoint", "http://localhost:9002", "--bucket", "b"); err != nil {
		t.Fatalf("init: %v", err)
	}

	//nolint:gosec // a fixed script; the path is the test's own.
	out, err := exec.CommandContext(t.Context(), sh, "-c",
		`set -a; . "$1"; set +a; printf %s "$`+envUpstreamSecret+`"`,
		"sh", filepath.Join(dir, initEnvName)).Output()
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	if string(out) != secret {
		t.Errorf("sh read %q, want %q", out, secret)
	}
}

func TestInitRefusesAValueTheEnvFileCannotHold(t *testing.T) {
	initEnv(t)
	t.Setenv(envUpstreamSecret, "it's")
	dir := t.TempDir()
	_, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
		"--endpoint", "http://localhost:9002", "--bucket", "b")
	if err == nil || !strings.Contains(err.Error(), envUpstreamSecret) {
		t.Fatalf("err = %v, want a refusal naming $%s", err, envUpstreamSecret)
	}
	assertEmptyDir(t, dir)
}

func TestInitNeverOverwrites(t *testing.T) {
	for _, existing := range []string{initConfigName, initKeyringName, initEnvName} {
		t.Run(existing, func(t *testing.T) {
			initEnv(t)
			dir := t.TempDir()
			path := filepath.Join(dir, existing)
			if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			_, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
				"--endpoint", "http://localhost:9002", "--bucket", "b")
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("err = %v, want a refusal", err)
			}
			if data, _ := os.ReadFile(path); string(data) != "precious" { //nolint:gosec // the test's own file.
				t.Errorf("%s was changed", existing)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Errorf("init wrote beside the existing file: %v", entries)
			}
		})
	}
}

// TestInitNonInteractiveNamesWhatIsMissing pins what --non-interactive
// promises: it never asks, and a missing answer names what supplies it.
func TestInitNonInteractiveNamesWhatIsMissing(t *testing.T) {
	base := []string{"init", "--non-interactive", "--endpoint", "http://localhost:9002", "--bucket", "b"}
	cases := map[string]struct {
		args  []string
		unset []string
		want  string
	}{
		"no endpoint":          {[]string{"init", "--non-interactive", "--bucket", "b"}, nil, "--endpoint"},
		"no bucket":            {[]string{"init", "--non-interactive", "--endpoint", "http://x"}, nil, "--bucket"},
		"no provider keys":     {base, []string{envUpstreamSecret}, envUpstreamSecret},
		"no passphrase":        {base, []string{passphraseEnv}, passphraseEnv},
		"vault, no address":    {append(slices.Clone(base), "--keys-provider", "vault"), nil, "--vault-address"},
		"vault, no token":      {append(slices.Clone(base), "--keys-provider", "vault", "--vault-address", "http://127.0.0.1:1"), nil, envVaultToken},
		"kms, no key":          {append(slices.Clone(base), "--keys-provider", "awskms"), nil, "--kms-key-id"},
		"kms, no credentials":  {append(slices.Clone(base), "--keys-provider", "awskms", "--kms-key-id", "alias/x"), nil, envKMSKeyID},
		"an unknown provider":  {append(slices.Clone(base), "--keys-provider", "hsm"), nil, "--keys-provider"},
		"an unknown source":    {append(slices.Clone(base), "--credential-source", "magic"), nil, "not one of"},
		"a stray argument":     {append(slices.Clone(base), "s3://b"), nil, "unexpected argument"},
		"a source, no kms key": {append(slices.Clone(base), "--credential-source", "chain", "--keys-provider", "awskms"), nil, "--kms-key-id"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			initEnv(t)
			for _, v := range c.unset {
				t.Setenv(v, "")
			}
			dir := t.TempDir()
			_, _, err := runCLI(t, append(slices.Clone(c.args), "--dir", dir)...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one naming %q", err, c.want)
			}
			assertEmptyDir(t, dir)
		})
	}
}

// TestInitRemovesWhatItWroteWhenSealingFails covers the one failure that
// comes after files are written: the keyring cannot be sealed. The two files
// written before it go again, and no keyring was created to be left behind.
func TestInitRemovesWhatItWroteWhenSealingFails(t *testing.T) {
	initEnv(t)
	t.Setenv(envVaultToken, "a-token")
	dir := t.TempDir()
	_, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
		"--endpoint", "http://localhost:9002", "--bucket", "b",
		"--keys-provider", "vault", "--vault-address", "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("init succeeded against a Vault that is not there")
	}
	assertEmptyDir(t, dir)
}

func TestInitWithoutATerminalPointsAtNonInteractive(t *testing.T) {
	// Whatever go test was started from, stdin here is not a terminal.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = devNull.Close() }()
	stdin := os.Stdin
	os.Stdin = devNull
	defer func() { os.Stdin = stdin }()

	_, _, err = runCLI(t, "init", "--dir", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "--non-interactive") {
		t.Fatalf("err = %v, want a pointer to --non-interactive", err)
	}
}

// interactiveInit answers init's questions from script, as a person at a
// terminal would, with args as the flags given.
func interactiveInit(t *testing.T, script string, args ...string) (initFlags, initAnswers, string, error) {
	t.Helper()
	var f initFlags
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	f.register(fs)
	if err := f.parse(fs, args); err != nil {
		t.Fatalf("flags: %v", err)
	}
	in := bufio.NewReader(strings.NewReader(script))
	var out strings.Builder
	p := &prompter{in: in, out: &out, secret: func() (string, error) {
		s, err := in.ReadString('\n')
		return strings.TrimSpace(s), err
	}}
	a, err := initInteractively(p, f)
	return f, a, out.String(), err
}

func TestInitInteractiveR2(t *testing.T) {
	initEnv(t)
	t.Setenv(envUpstreamKeyID, "")
	t.Setenv(envUpstreamSecret, "")
	// R2, the account, the bucket, a key and its secret, a passphrase, and
	// names left in clear.
	f, a, prompts, err := interactiveInit(t, "3\nacc123\nphotos\nR2KEY\nR2SECRET\n\n\n")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, prompts)
	}
	if a.endpoint != "https://acc123.r2.cloudflarestorage.com" || a.region != "auto" || !a.pathStyle {
		t.Errorf("answers = %+v", a)
	}
	if a.upstreamKeyID != "R2KEY" || a.upstreamSecret != "R2SECRET" || a.keys.Provider != "file" || a.encryptNames {
		t.Errorf("answers = %+v", a)
	}
	if strings.Contains(prompts, "Credential source") {
		t.Error("a provider other than AWS was asked for a credential source")
	}

	f.dir = t.TempDir()
	var summary strings.Builder
	if err := writeInit(t.Context(), f, a, &passphraseFlags{}, &summary); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(summary.String(), "Cloudflare R2 has not been measured") {
		t.Errorf("the summary does not say R2 is unmeasured:\n%s", summary.String())
	}
	cfg, _ := loadInitConfig(t, f.dir)
	if cfg.Upstream.Endpoint != a.endpoint || cfg.Upstream.SecretAccessKey != "R2SECRET" {
		t.Errorf("upstream = %+v", cfg.Upstream)
	}
}

func TestInitInteractiveAWSWithPlatformCredentialsAndKMS(t *testing.T) {
	initEnv(t)
	// AWS in eu-central-1, the bucket, credentials from the platform via web
	// identity, KMS with the provider's region, and names encrypted.
	_, a, prompts, err := interactiveInit(t, "2\neu-central-1\nb\n2\nweb_identity\n3\nalias/bb\n\ny\n")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, prompts)
	}
	if a.endpoint != "https://s3.eu-central-1.amazonaws.com" || a.pathStyle || a.credentialSource != "web_identity" {
		t.Errorf("answers = %+v", a)
	}
	k := a.keys.AWSKMS
	if a.keys.Provider != "awskms" || k.KeyID != "alias/bb" || k.Region != "eu-central-1" || k.CredentialSource != "web_identity" {
		t.Errorf("kms = %+v", k)
	}
	if !a.encryptNames {
		t.Error("names are not encrypted")
	}

	// Sealing needs KMS, so this checks the configuration rather than writing
	// it: it loads, and it holds no keys for either section.
	a.keys.Keyring, a.clientKeyID, a.clientSecret = "/k.json", "BBID", "secret"
	path := filepath.Join(t.TempDir(), initConfigName)
	if err := os.WriteFile(path, renderInitConfig(a), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv(envClientKeyID, a.clientKeyID)
	t.Setenv(envClientSecret, a.clientSecret)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Upstream.CredentialSource != "web_identity" || cfg.Keys.AWSKMS.CredentialSource != "web_identity" || !cfg.Names.Encrypt {
		t.Errorf("config = %+v / %+v", cfg.Upstream, cfg.Keys.AWSKMS)
	}
}

func TestInitInteractiveAsksAgainAndHonoursFlags(t *testing.T) {
	initEnv(t)
	// An answer out of range is asked again; the bucket is given as a flag
	// and not asked; the environment's provider keys are taken.
	_, a, prompts, err := interactiveInit(t, "9\n1\n\n\n\n\n", "--bucket", "given")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, prompts)
	}
	if !strings.Contains(prompts, "Answer with a number from 1 to 6") {
		t.Errorf("an out-of-range choice was not asked again:\n%s", prompts)
	}
	if strings.Contains(prompts, "Bucket") || a.bucket != "given" {
		t.Errorf("the bucket flag was not honoured (bucket %q):\n%s", a.bucket, prompts)
	}
	if a.endpoint != "http://localhost:9002" || a.upstreamKeyID != "upstream-key" {
		t.Errorf("answers = %+v", a)
	}
}

func TestInitInteractiveInputEndingEarly(t *testing.T) {
	initEnv(t)
	_, _, _, err := interactiveInit(t, "1\n")
	if err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("err = %v", err)
	}
}

// TestInitWithRootKeyServices seals through Vault and the KMS emulator, where
// they are running, and opens the result with the written configuration.
func TestInitWithRootKeyServices(t *testing.T) {
	t.Run("vault", func(t *testing.T) {
		addr, token := os.Getenv("BLINDBUCKET_TEST_VAULT_ADDR"), os.Getenv("BLINDBUCKET_TEST_VAULT_TOKEN")
		if addr == "" || token == "" {
			t.Skip("set BLINDBUCKET_TEST_VAULT_ADDR and _TOKEN (docker compose --profile keys up -d)")
		}
		initEnv(t)
		t.Setenv(envVaultToken, token)
		dir := t.TempDir()
		stdout, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
			"--endpoint", "http://localhost:9002", "--bucket", "b",
			"--keys-provider", "vault", "--vault-address", addr)
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		if !strings.Contains(stdout, "export "+envVaultToken) {
			t.Errorf("the summary does not say serve needs $%s:\n%s", envVaultToken, stdout)
		}
		cfg, vars := loadInitConfig(t, dir)
		if _, ok := vars[envVaultToken]; ok {
			t.Errorf("$%s is in the environment file, beside the keyring it opens", envVaultToken)
		}
		if _, err := openKeyring(t.Context(), cfg.Keys.Keyring, cfg.Keys, &passphraseFlags{}); err != nil {
			t.Fatalf("open: %v", err)
		}
	})
	t.Run("awskms", func(t *testing.T) {
		endpoint := os.Getenv("BLINDBUCKET_TEST_KMS_ENDPOINT")
		if endpoint == "" {
			t.Skip("set BLINDBUCKET_TEST_KMS_ENDPOINT (docker compose --profile keys up -d)")
		}
		initEnv(t)
		t.Setenv(envKMSKeyID, "test")
		t.Setenv(envKMSSecret, "test")
		dir := t.TempDir()
		stdout, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
			"--endpoint", "http://localhost:9002", "--bucket", "b",
			"--keys-provider", "awskms", "--kms-key-id", emulatorKey(t, endpoint),
			"--kms-endpoint", endpoint)
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		if !strings.Contains(stdout, "export "+envKMSKeyID) {
			t.Errorf("the summary does not say serve needs $%s:\n%s", envKMSKeyID, stdout)
		}
		cfg, vars := loadInitConfig(t, dir)
		if _, ok := vars[envKMSSecret]; ok {
			t.Errorf("$%s is in the environment file, beside the keyring it opens", envKMSSecret)
		}
		if _, err := openKeyring(t.Context(), cfg.Keys.Keyring, cfg.Keys, &passphraseFlags{}); err != nil {
			t.Fatalf("open: %v", err)
		}
	})
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) > 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("a failed init left %v behind", names)
	}
}
