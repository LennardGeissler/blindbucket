package main

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/LennardGeissler/blindbucket/internal/awscreds"
	"github.com/LennardGeissler/blindbucket/internal/config"
)

// The three files init writes, by their names in --dir.
const (
	initConfigName  = "blindbucket.yaml"
	initKeyringName = "keyring.json"
	initEnvName     = "blindbucket.env"
)

// The environment variables the written configuration references. The names
// are the ones blindbucket.example.yaml uses, so that the two read alike --
// except KMS's: AWS_ACCESS_KEY_ID is also what the AWS CLI reads, and init
// prints a line exporting the client's credentials under that name.
const (
	envUpstreamKeyID  = "UPSTREAM_ACCESS_KEY_ID"
	envUpstreamSecret = "UPSTREAM_SECRET_ACCESS_KEY"
	envClientKeyID    = "BB_ACCESS_KEY_ID"
	envClientSecret   = "BB_SECRET_ACCESS_KEY"
	envVaultToken     = "VAULT_TOKEN"
	envKMSKeyID       = "KMS_ACCESS_KEY_ID"
	envKMSSecret      = "KMS_SECRET_ACCESS_KEY" //nolint:gosec // a variable name, not a credential.
)

// initFlags are init's flags, and which of them were given. A question is
// asked only for what no flag answered, so the defaults below are what a
// script gets, not what an interactive run starts from.
type initFlags struct {
	dir                                string
	batch                              bool
	endpoint, region, bucket           string
	pathStyle                          bool
	credentialSource                   string
	provider                           string
	vaultAddress, vaultMount, vaultKey string
	kmsKeyID, kmsRegion, kmsEndpoint   string
	encryptNames                       bool
	kid                                string
	set                                map[string]bool
}

// initAnswers is everything the three files are written from. Secrets are held
// as values here; the configuration gets references to them, and the
// environment file the values.
type initAnswers struct {
	endpoint, region string
	pathStyle        bool
	bucket           string
	// credentialSource, when set, replaces the upstream keys, and the KMS
	// keys too: one principal for both is what a platform role gives.
	credentialSource              string
	upstreamKeyID, upstreamSecret string
	// keys is what seals the keyring, with the Vault token and the KMS keys as
	// values. Keyring and PassphraseFile are absolute paths.
	keys                      config.Keys
	encryptNames              bool
	clientKeyID, clientSecret string
	// unmeasured names a provider the gateway has not been measured against,
	// so the summary can say so rather than imply otherwise.
	unmeasured string
}

func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket init [flags]

Writes what a gateway needs to start into one directory: a configuration
(%s), a keyring (%s), and the secrets the configuration
references (%s), among them a generated credential for the
gateway's first client.

On a terminal it asks for what no flag answers. With --non-interactive it
never asks, and a missing answer is an error naming the flag or the variable
that supplies it; secrets then come from the environment, never from flags:
$%s and $%s for the provider, $%s for
Vault, $%s and $%s for KMS.

No file is ever overwritten: if any of the three exists, nothing is written.
Nothing that opens the keyring is stored beside it: not the passphrase, not
the Vault token, not KMS keys. serve needs them from the environment.

Flags:
`, initConfigName, initKeyringName, initEnvName,
			envUpstreamKeyID, envUpstreamSecret, envVaultToken, envKMSKeyID, envKMSSecret)
		fs.PrintDefaults()
	}

	var (
		f    initFlags
		pass passphraseFlags
	)
	f.register(fs)
	pass.register(fs)
	if err := f.parse(fs, args); err != nil {
		return err
	}
	defer pass.wipe()

	var (
		a   initAnswers
		err error
	)
	if f.batch {
		a, err = initFromFlags(f)
		// keygen would ask for a passphrase on a terminal; with
		// --non-interactive nothing asks, so it has to come from somewhere.
		if err == nil && a.keys.Provider == "file" && pass.file == "" && os.Getenv(passphraseEnv) == "" {
			err = fmt.Errorf("the keyring passphrase comes from $%s or --passphrase-file "+
				"with --non-interactive", passphraseEnv)
		}
	} else {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return errors.New("init asks its questions on a terminal; without one, pass " +
				"--non-interactive and the answers as flags (`blindbucket init -h`)")
		}
		p := &prompter{in: bufio.NewReader(os.Stdin), out: os.Stderr, secret: func() (string, error) {
			s, err := term.ReadPassword(fd)
			return string(s), err
		}}
		a, err = initInteractively(p, f)
	}
	if err != nil {
		return err
	}
	return writeInit(ctx, f, a, &pass, os.Stdout)
}

// register defines init's flags on fs.
func (f *initFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.dir, "dir", ".", "directory to write the three files into; created if missing")
	fs.BoolVar(&f.batch, "non-interactive", false,
		"never ask; a missing answer is an error naming the flag or variable that supplies it")
	fs.StringVar(&f.endpoint, "endpoint", "", "the provider's S3 endpoint, such as https://s3.eu-central-1.amazonaws.com")
	fs.StringVar(&f.region, "region", "us-east-1", `the provider's region ("auto" for Cloudflare R2)`)
	fs.BoolVar(&f.pathStyle, "path-style", true, "name the bucket in the path rather than in the host name")
	fs.StringVar(&f.bucket, "bucket", "", "the bucket the generated client may use")
	fs.StringVar(&f.credentialSource, "credential-source", "",
		"take AWS credentials from env, profile, web_identity, container, imds or chain instead of keys (ADR-024)")
	fs.StringVar(&f.provider, "keys-provider", "file", "what seals the keyring: file (a passphrase), vault or awskms")
	fs.StringVar(&f.vaultAddress, "vault-address", "", "Vault or OpenBao address, for --keys-provider vault")
	fs.StringVar(&f.vaultMount, "vault-mount", "transit", "where the Transit engine is mounted")
	fs.StringVar(&f.vaultKey, "vault-key-name", "blindbucket", "the Transit key that seals the keyring")
	fs.StringVar(&f.kmsKeyID, "kms-key-id", "", "KMS key id, alias or ARN, for --keys-provider awskms")
	fs.StringVar(&f.kmsRegion, "kms-region", "", "KMS region (default: the provider's region)")
	fs.StringVar(&f.kmsEndpoint, "kms-endpoint", "", "override for an AWS-compatible KMS endpoint")
	fs.BoolVar(&f.encryptNames, "encrypt-names", false,
		"encrypt object names (ADR-015); only for a bucket that holds no objects yet")
	fs.StringVar(&f.kid, "kid", defaultKID(), "id of the keyring's first key-encryption key")
}

// parse parses args and records which flags were given.
func (f *initFlags) parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	f.set = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return nil
}

// initFromFlags builds the answers for --non-interactive, where a missing one
// is an error that names what supplies it.
func initFromFlags(f initFlags) (initAnswers, error) {
	a := initAnswers{
		endpoint: f.endpoint, region: f.region, pathStyle: f.pathStyle,
		bucket: f.bucket, credentialSource: f.credentialSource, encryptNames: f.encryptNames,
	}
	if a.endpoint == "" {
		return a, errors.New("--endpoint is required with --non-interactive")
	}
	if a.bucket == "" {
		return a, errors.New("--bucket is required with --non-interactive")
	}
	if err := checkCredentialSource(a.credentialSource); err != nil {
		return a, err
	}
	if a.credentialSource == "" {
		a.upstreamKeyID, a.upstreamSecret = os.Getenv(envUpstreamKeyID), os.Getenv(envUpstreamSecret)
		if a.upstreamKeyID == "" || a.upstreamSecret == "" {
			return a, fmt.Errorf("the provider's credentials come from $%s and $%s; set both, "+
				"or pass --credential-source", envUpstreamKeyID, envUpstreamSecret)
		}
	}

	a.keys = config.Keys{Provider: f.provider}
	switch f.provider {
	case "file":
	case "vault":
		a.keys.Vault = config.VaultKeys{
			Address: f.vaultAddress, Mount: f.vaultMount, KeyName: f.vaultKey,
			Token: os.Getenv(envVaultToken),
		}
		if a.keys.Vault.Address == "" {
			return a, errors.New("--vault-address is required with --keys-provider vault")
		}
		if a.keys.Vault.Token == "" {
			return a, fmt.Errorf("the Vault token comes from $%s; set it", envVaultToken)
		}
	case "awskms":
		a.keys.AWSKMS = config.AWSKMSKeys{
			KeyID: f.kmsKeyID, Region: cmp.Or(f.kmsRegion, a.region), Endpoint: f.kmsEndpoint,
			CredentialSource: a.credentialSource,
		}
		if a.keys.AWSKMS.KeyID == "" {
			return a, errors.New("--kms-key-id is required with --keys-provider awskms")
		}
		if a.credentialSource == "" {
			a.keys.AWSKMS.AccessKeyID, a.keys.AWSKMS.SecretAccessKey = os.Getenv(envKMSKeyID), os.Getenv(envKMSSecret)
			if a.keys.AWSKMS.AccessKeyID == "" || a.keys.AWSKMS.SecretAccessKey == "" {
				return a, fmt.Errorf("the KMS credentials come from $%s and $%s; set both, "+
					"or pass --credential-source", envKMSKeyID, envKMSSecret)
			}
		}
	default:
		return a, fmt.Errorf("--keys-provider must be file, vault or awskms, not %q", f.provider)
	}
	return a, nil
}

// initInteractively asks for what no flag answered.
func initInteractively(p *prompter, f initFlags) (initAnswers, error) {
	a := initAnswers{
		endpoint: f.endpoint, region: f.region, pathStyle: f.pathStyle,
		bucket: f.bucket, credentialSource: f.credentialSource, encryptNames: f.encryptNames,
	}
	if err := checkCredentialSource(a.credentialSource); err != nil {
		return a, err
	}
	// Only AWS is asked about a credential source: the others have no
	// platform to take credentials from. The flag is honoured for any.
	aws := false
	if !f.set["endpoint"] {
		var err error
		if aws, err = askProvider(p, f, &a); err != nil {
			return a, err
		}
	}

	if !f.set["bucket"] {
		var err error
		if a.bucket, err = p.required("Bucket", ""); err != nil {
			return a, err
		}
	}

	if err := askUpstreamCredentials(p, aws, &a); err != nil {
		return a, err
	}
	if err := askRootKey(p, f, &a); err != nil {
		return a, err
	}

	if !f.set["encrypt-names"] {
		_, _ = fmt.Fprint(p.out, "\nObject names can be encrypted too, so that the provider sees no key in\n"+
			"clear. Choose it only for a bucket that holds no objects yet: switching later\n"+
			"means moving every object with `blindbucket migrate-names` (ADR-015).\n")
		var err error
		if a.encryptNames, err = p.yesNo("Encrypt object names?", false); err != nil {
			return a, err
		}
	}
	return a, nil
}

// askProvider sets endpoint, region and addressing from a provider preset, and
// reports whether the provider is AWS. Presets exist only here: as flags they
// would be one more thing ADR-021 has to keep stable, for no answer the
// --endpoint, --region and --path-style flags cannot already give.
func askProvider(p *prompter, f initFlags, a *initAnswers) (bool, error) {
	choice, err := p.choose("Where are the objects stored?", []string{
		"MinIO, or another S3 server on this machine",
		"AWS S3",
		"Cloudflare R2",
		"Backblaze B2",
		"Garage",
		"another S3-compatible provider",
	}, 0)
	if err != nil {
		return false, err
	}
	region := func(def string) (string, error) {
		if f.set["region"] {
			return f.region, nil
		}
		return p.required("Region", def)
	}

	switch choice {
	case 0:
		// Not :9000, which is where the gateway itself listens: :9002 is the
		// MinIO docker-compose.yml starts for exactly that reason.
		if a.endpoint, err = p.required("Endpoint", "http://localhost:9002"); err != nil {
			return false, err
		}
		a.region, err = region("us-east-1")
		a.pathStyle = true
	case 1:
		if a.region, err = region("us-east-1"); err != nil {
			return false, err
		}
		a.endpoint = "https://s3." + a.region + ".amazonaws.com"
		a.pathStyle = false
		return true, nil
	case 2:
		var account string
		if account, err = p.required("Cloudflare account ID", ""); err != nil {
			return false, err
		}
		a.endpoint = "https://" + account + ".r2.cloudflarestorage.com"
		a.region, a.pathStyle, a.unmeasured = "auto", true, "Cloudflare R2"
	case 3:
		if a.region, err = region("us-west-004"); err != nil {
			return false, err
		}
		a.endpoint = "https://s3." + a.region + ".backblazeb2.com"
		a.pathStyle, a.unmeasured = true, "Backblaze B2"
	case 4:
		if a.endpoint, err = p.required("Endpoint", "http://localhost:3900"); err != nil {
			return false, err
		}
		a.region, err = region("garage")
		a.pathStyle = true
	default:
		if a.endpoint, err = p.required("Endpoint", ""); err != nil {
			return false, err
		}
		if a.region, err = region("us-east-1"); err != nil {
			return false, err
		}
		a.pathStyle, err = p.yesNo("Name the bucket in the path (path-style)?", true)
	}
	return false, err
}

// askUpstreamCredentials takes the provider's keys from the environment if
// they are there, and asks otherwise -- the secret without echo.
func askUpstreamCredentials(p *prompter, aws bool, a *initAnswers) error {
	if a.credentialSource != "" {
		return nil
	}
	if aws {
		choice, err := p.choose("Where do the gateway's AWS credentials come from?", []string{
			"an access key",
			"the platform: IRSA, EKS Pod Identity, an ECS task role or the instance role (ADR-024)",
		}, 0)
		if err != nil {
			return err
		}
		if choice == 1 {
			src, err := p.required("Credential source (env, profile, web_identity, container, imds, chain)",
				awscreds.SourceChain)
			if err != nil {
				return err
			}
			a.credentialSource = src
			return checkCredentialSource(src)
		}
	}
	id, secret := os.Getenv(envUpstreamKeyID), os.Getenv(envUpstreamSecret)
	if id != "" && secret != "" {
		_, _ = fmt.Fprintf(p.out, "Using the provider's access key from $%s and $%s.\n",
			envUpstreamKeyID, envUpstreamSecret)
		a.upstreamKeyID, a.upstreamSecret = id, secret
		return nil
	}
	var err error
	if a.upstreamKeyID, err = p.required("Provider access key ID", ""); err != nil {
		return err
	}
	a.upstreamSecret, err = p.hidden("Provider secret access key")
	return err
}

// askRootKey settles what seals the keyring.
func askRootKey(p *prompter, f initFlags, a *initAnswers) error {
	provider := f.provider
	if !f.set["keys-provider"] {
		choice, err := p.choose("What seals the keyring?", []string{
			"a passphrase",
			"Vault or OpenBao Transit",
			"AWS KMS",
		}, 0)
		if err != nil {
			return err
		}
		provider = []string{"file", "vault", "awskms"}[choice]
	}
	a.keys = config.Keys{Provider: provider}

	var err error
	ask := func(flagName, value, question, def string) (string, error) {
		if f.set[flagName] {
			return value, nil
		}
		return p.required(question, def)
	}
	switch provider {
	case "file":
		return nil
	case "vault":
		v := &a.keys.Vault
		if v.Address, err = ask("vault-address", f.vaultAddress, "Vault address", ""); err != nil {
			return err
		}
		if v.Mount, err = ask("vault-mount", f.vaultMount, "Transit mount", f.vaultMount); err != nil {
			return err
		}
		if v.KeyName, err = ask("vault-key-name", f.vaultKey, "Transit key name", f.vaultKey); err != nil {
			return err
		}
		if v.Token = os.Getenv(envVaultToken); v.Token != "" {
			_, _ = fmt.Fprintf(p.out, "Using the Vault token from $%s.\n", envVaultToken)
			return nil
		}
		v.Token, err = p.hidden("Vault token")
		return err
	case "awskms":
		k := &a.keys.AWSKMS
		k.Endpoint, k.CredentialSource = f.kmsEndpoint, a.credentialSource
		if k.KeyID, err = ask("kms-key-id", f.kmsKeyID, "KMS key ID, alias or ARN", ""); err != nil {
			return err
		}
		if k.Region, err = ask("kms-region", f.kmsRegion, "KMS region", a.region); err != nil {
			return err
		}
		if k.CredentialSource != "" {
			return nil
		}
		k.AccessKeyID, k.SecretAccessKey = os.Getenv(envKMSKeyID), os.Getenv(envKMSSecret)
		if k.AccessKeyID != "" && k.SecretAccessKey != "" {
			_, _ = fmt.Fprintf(p.out, "Using the KMS access key from $%s and $%s.\n", envKMSKeyID, envKMSSecret)
			return nil
		}
		if k.AccessKeyID, err = p.required("KMS access key ID", ""); err != nil {
			return err
		}
		k.SecretAccessKey, err = p.hidden("KMS secret access key")
		return err
	default:
		return fmt.Errorf("--keys-provider must be file, vault or awskms, not %q", provider)
	}
}

func checkCredentialSource(src string) error {
	sources := []string{
		awscreds.SourceEnv, awscreds.SourceProfile, awscreds.SourceWebIdentity,
		awscreds.SourceContainer, awscreds.SourceIMDS, awscreds.SourceChain,
	}
	if src == "" || slices.Contains(sources, src) {
		return nil
	}
	return fmt.Errorf("credential source %q is not one of %s", src, strings.Join(sources, ", "))
}

// writeInit writes the three files, or none of them.
//
// The keyring is written last, so that a failure is never cleaned up by
// deleting one. Sealing is where init can fail for reasons outside it -- a
// passphrase repeated wrongly, a Vault that does not answer -- and when it
// does, the configuration and the environment file just written are removed
// again; they hold nothing that cannot be written a second time. A keyring,
// once it exists, is left alone even here, by the rule keygen follows: it is
// the only copy of its keys, and init cannot know that nothing was encrypted
// under it since.
func writeInit(ctx context.Context, f initFlags, a initAnswers, pass *passphraseFlags, out io.Writer) error {
	dir, err := filepath.Abs(f.dir)
	if err != nil {
		return err
	}
	paths := map[string]string{}
	for _, name := range []string{initConfigName, initKeyringName, initEnvName} {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists; init writes nothing over an existing file, "+
				"so move it away or choose another --dir", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		paths[name] = path
	}

	a.clientKeyID, a.clientSecret = newClientCredentials()
	a.keys.Keyring = paths[initKeyringName]
	if pass.file != "" {
		if a.keys.PassphraseFile, err = filepath.Abs(pass.file); err != nil {
			return err
		}
	}
	envFile, err := renderInitEnv(a)
	if err != nil {
		return err
	}
	configFile := renderInitConfig(a)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var written []string
	undo := func() {
		for _, path := range written {
			_ = os.Remove(path)
		}
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{initConfigName, configFile}, {initEnvName, envFile}} {
		if err := writeNewFile(paths[file.name], file.data); err != nil {
			undo()
			return err
		}
		written = append(written, paths[file.name])
	}
	if err := createKeyring(ctx, paths[initKeyringName], f.kid, a.keys, pass); err != nil {
		undo()
		return err
	}
	if err := syncDir(paths[initConfigName]); err != nil {
		return err
	}
	printInitSummary(out, paths, a)
	return nil
}

// newClientCredentials generates the first client's access key. The ID is not
// a secret but is random anyway, so that two gateways set up by init never
// share one; the secret carries 200 bits.
func newClientCredentials() (id, secret string) {
	// rand.Text is base32: upper case and digits, 26 characters, 130 bits.
	return "BB" + rand.Text()[:18], (rand.Text() + rand.Text())[:40]
}

// writeNewFile creates a file that must not exist yet, mode 0600, synced.
func writeNewFile(path string, data []byte) error {
	//nolint:gosec // the path is the operator's --dir and a fixed name.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

// renderInitEnv writes the secrets the configuration references -- those that
// do not open the keyring. The passphrase, the Vault token and KMS keys are
// left out, all three for the same reason: beside the keyring, any one of them
// opens it for whoever can read the directory, which is the second door
// ADR-013 and ADR-023 keep shut. A Vault token at least stays revocable, but
// the rule is easier to state, check and trust without an exception.
//
// They are written in the one
// format a shell (set -a; . file), Docker Compose's env_file and systemd's
// EnvironmentFile all read the same way: NAME='value'. A value that holds a
// quote or a line break cannot be written that way, and is refused rather
// than escaped in a way one of the three reads differently.
func renderInitEnv(a initAnswers) ([]byte, error) {
	vars := [][2]string{{envClientKeyID, a.clientKeyID}, {envClientSecret, a.clientSecret}}
	if a.credentialSource == "" {
		vars = append(vars, [2]string{envUpstreamKeyID, a.upstreamKeyID}, [2]string{envUpstreamSecret, a.upstreamSecret})
	}

	var b strings.Builder
	b.WriteString("# Secrets for " + initConfigName + ", written by `blindbucket init`. Keep this file\n" +
		"# as private as the keyring. To load it into a shell:\n" +
		"#   set -a; . ./" + initEnvName + "; set +a\n" +
		"# Docker Compose reads it as an env_file, systemd as an EnvironmentFile.\n")
	b.WriteString("#\n# What unseals the keyring -- a passphrase, a Vault token, KMS keys -- is not\n" +
		"# here, on purpose: beside the keyring it would open it for anyone who can\n" +
		"# read this directory. serve takes it from the environment.\n")
	for _, v := range vars {
		if strings.ContainsAny(v[1], "'\r\n\x00") {
			return nil, fmt.Errorf("the value for $%s contains a quote or a line break, "+
				"which %s cannot hold the same way for every reader of it", v[0], initEnvName)
		}
		_, _ = fmt.Fprintf(&b, "%s='%s'\n", v[0], v[1])
	}
	return []byte(b.String()), nil
}

// renderInitConfig writes the configuration: only what init asked about, with
// every secret as a reference, and a pointer to the example for the rest.
func renderInitConfig(a initAnswers) []byte {
	q := strconv.Quote
	var b strings.Builder
	w := func(format string, args ...any) { _, _ = fmt.Fprintf(&b, format, args...) }

	w(`# blindbucket configuration, written by %[1]sblindbucket init%[1]s.
#
# Secrets are referenced, never written here: each ${VAR} is resolved from the
# environment at startup, and %[2]s beside this file holds them.
# Everything not set here has its default. blindbucket.example.yaml in the
# repository describes every setting -- TLS, the audit log and rollback
# detection among them, none of which is on yet.

server:
  # Loopback: between client and gateway the body is plaintext, so a public
  # listener needs TLS first.
  listen: "127.0.0.1:9000"

# Metrics and health, for operators rather than storage clients.
admin:
  listen: "127.0.0.1:9100"

upstream:
  endpoint: %[3]s
  region: %[4]s
  path_style: %[5]t
`, "`", initEnvName, q(a.endpoint), q(a.region), a.pathStyle)
	if a.credentialSource != "" {
		w("  credential_source: %s\n", q(a.credentialSource))
	} else {
		w("  access_key_id: ${%s}\n  secret_access_key: ${%s}\n", envUpstreamKeyID, envUpstreamSecret)
	}

	w("\nkeys:\n  provider: %s\n  keyring: %s\n", a.keys.Provider, q(a.keys.Keyring))
	switch a.keys.Provider {
	case "file":
		if a.keys.PassphraseFile != "" {
			w("  passphrase_file: %s\n", q(a.keys.PassphraseFile))
		} else {
			w("  # The passphrase comes from $%s, or serve asks for it on a terminal.\n", passphraseEnv)
		}
	case "vault":
		v := a.keys.Vault
		w("  vault:\n    address: %s\n    token: ${%s}\n    mount: %s\n    key_name: %s\n",
			q(v.Address), envVaultToken, q(v.Mount), q(v.KeyName))
	case "awskms":
		k := a.keys.AWSKMS
		w("  awskms:\n    region: %s\n    key_id: %s\n", q(k.Region), q(k.KeyID))
		if k.CredentialSource != "" {
			w("    credential_source: %s\n", q(k.CredentialSource))
		} else {
			w("    access_key_id: ${%s}\n    secret_access_key: ${%s}\n", envKMSKeyID, envKMSSecret)
		}
		if k.Endpoint != "" {
			w("    endpoint: %s\n", q(k.Endpoint))
		}
	}

	if a.encryptNames {
		w("\n# Object names are encrypted (ADR-015). Not a switch to turn off again: an\n" +
			"# object lives at the encrypted form of its key.\nnames:\n  encrypt: true\n")
	} else {
		w("\n# Object names are stored in clear. To encrypt them, turn this on before the\n" +
			"# bucket holds objects, or move them across with `blindbucket migrate-names`\n" +
			"# (ADR-015, ADR-022).\n# names:\n#   encrypt: true\n")
	}

	w(`
# The credentials the gateway accepts from its clients -- not the provider's,
# which a client never sees.
clients:
  - name: default
    access_key_id: ${%s}
    secret_access_key: ${%s}
    buckets: [%s]
`, envClientKeyID, envClientSecret, q(a.bucket))
	return []byte(b.String())
}

// printInitSummary says what was written and what to run next.
func printInitSummary(out io.Writer, paths map[string]string, a initAnswers) {
	w := func(format string, args ...any) { _, _ = fmt.Fprintf(out, format, args...) }
	shown := map[string]string{}
	for name, path := range paths {
		shown[name] = displayPath(path)
	}
	conf, env := shellQuote(shown[initConfigName]), shellQuote(shown[initEnvName])

	w("Wrote %s, %s and %s.\n\n", shown[initConfigName], shown[initKeyringName], shown[initEnvName])
	w("Start the gateway:\n  set -a; . %s; set +a\n", env)
	switch {
	case a.keys.Provider == "file" && a.keys.PassphraseFile == "":
		w("  export %s=...      # the passphrase you chose; it is stored nowhere\n", passphraseEnv)
	case a.keys.Provider == "vault":
		w("  export %s=...      # not stored beside the keyring, which it opens\n", envVaultToken)
	case a.keys.Provider == "awskms" && a.keys.AWSKMS.CredentialSource == "":
		w("  export %s=... %s=...      # for KMS; not stored beside the keyring, which they open\n",
			envKMSKeyID, envKMSSecret)
	}
	w("  blindbucket serve --config %s\n\n", conf)

	w("Then point any S3 client at it. These are the client's credentials, also in\n%s:\n", shown[initEnvName])
	w("  export AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s\n", a.clientKeyID, a.clientSecret)
	w("  export AWS_ENDPOINT_URL=http://127.0.0.1:9000\n")
	w("  aws s3 cp <file> s3://%s/\n\n", a.bucket)

	w("To check all of it -- the keyring, the provider, the bucket, this host's clock,\n" +
		"and the conditional writes key rotation relies on -- with the environment\n" +
		"loaded as for serve:\n")
	w("  blindbucket doctor --config %s\n", conf)
	if a.unmeasured != "" {
		w("\n%s has not been measured against the gateway yet; see docs/COMPATIBILITY.md,\n"+
			"and please report what you find.\n", a.unmeasured)
	}
}

// displayPath shortens a path under the working directory to ./relative, for
// the commands printed above. The ./ is not decoration: `. file` without a
// slash searches $PATH rather than the working directory.
func displayPath(path string) string {
	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(wd, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return "." + string(filepath.Separator) + rel
}

// shellQuote quotes a path for the commands printed above.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// prompter asks init's questions. It reads answers line by line, and secrets
// through secret, which on a terminal does not echo them.
type prompter struct {
	in     *bufio.Reader
	out    io.Writer
	secret func() (string, error)
}

func (p *prompter) readLine() (string, error) {
	s, err := p.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || s == "") {
		if errors.Is(err, io.EOF) {
			return "", errors.New("the input ended before every question was answered; nothing was written")
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// required asks until the answer, or the default, is not empty.
func (p *prompter) required(question, def string) (string, error) {
	for {
		if def != "" {
			_, _ = fmt.Fprintf(p.out, "%s [%s]: ", question, def)
		} else {
			_, _ = fmt.Fprintf(p.out, "%s: ", question)
		}
		s, err := p.readLine()
		if err != nil {
			return "", err
		}
		if s == "" {
			s = def
		}
		if s != "" {
			return s, nil
		}
		_, _ = fmt.Fprintln(p.out, "This one needs an answer.")
	}
}

func (p *prompter) hidden(question string) (string, error) {
	for {
		_, _ = fmt.Fprintf(p.out, "%s: ", question)
		s, err := p.secret()
		_, _ = fmt.Fprintln(p.out)
		if err != nil {
			return "", err
		}
		if s = strings.TrimSpace(s); s != "" {
			return s, nil
		}
		_, _ = fmt.Fprintln(p.out, "This one needs an answer.")
	}
}

func (p *prompter) yesNo(question string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		_, _ = fmt.Fprintf(p.out, "%s [%s]: ", question, hint)
		s, err := p.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		_, _ = fmt.Fprintln(p.out, "Answer y or n.")
	}
}

// choose asks for one of options by number, and returns its index.
func (p *prompter) choose(question string, options []string, def int) (int, error) {
	_, _ = fmt.Fprintf(p.out, "\n%s\n", question)
	for i, o := range options {
		_, _ = fmt.Fprintf(p.out, "  %d) %s\n", i+1, o)
	}
	for {
		_, _ = fmt.Fprintf(p.out, "Choose 1-%d [%d]: ", len(options), def+1)
		s, err := p.readLine()
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		_, _ = fmt.Fprintf(p.out, "Answer with a number from 1 to %d.\n", len(options))
	}
}
