// Package config loads and validates blindbucket's configuration file.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// Config is the whole configuration file.
type Config struct {
	Server   Server   `yaml:"server"`
	Upstream Upstream `yaml:"upstream"`
	Clients  Clients  `yaml:"clients"`
	Keys     Keys     `yaml:"keys"`
	Crypto   Crypto   `yaml:"crypto"`
	Admin    Admin    `yaml:"admin"`
	Audit    Audit    `yaml:"audit"`
	Names    Names    `yaml:"names"`
}

// Audit configures the hash-chained, signed record of what the gateway served
// (ADR-016).
//
// It is off unless a path is given. A gateway that wrote an audit log by default
// would write one to a path nobody chose, with a key nobody published, and the
// result would look like evidence without being any.
type Audit struct {
	// Log is the file to append to. Empty disables audit logging entirely.
	Log string `yaml:"log"`
	// Chain names this chain. Empty generates one per file, which is what a
	// deployment wants: instances must not share a chain, because a chain is a
	// sequence and two writers would fight over its order.
	Chain string `yaml:"chain"`
	// CheckpointEvery is how many entries pass before the chain is signed and
	// flushed. Together with CheckpointInterval it bounds how much of the tail
	// an attacker holding the file could remove undetectably.
	CheckpointEvery int `yaml:"checkpoint_every"`
	// CheckpointInterval bounds the same window in time, for a gateway too
	// quiet to reach the entry count. A Go duration: "30s", "5m".
	CheckpointInterval string `yaml:"checkpoint_interval"`
	// RotateBytes is the size at which the log is archived and a new file
	// started. Opening a log verifies it from the beginning, so this is what
	// keeps startup bounded.
	RotateBytes int64 `yaml:"rotate_bytes"`
	// FailClosed refuses requests once an append has failed, rather than
	// serving on with a record known to be incomplete. It defaults to true,
	// because the attack it guards against -- filling a disk to switch auditing
	// off -- is cheap against a log that degrades quietly.
	FailClosed bool `yaml:"fail_closed"`
}

// Enabled reports whether audit logging was asked for.
func (a Audit) Enabled() bool { return a.Log != "" }

// Interval parses CheckpointInterval. Zero selects the package default.
func (a Audit) Interval() (time.Duration, error) {
	if a.CheckpointInterval == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(a.CheckpointInterval)
	if err != nil {
		return 0, fmt.Errorf("audit.checkpoint_interval: %w", err)
	}
	return d, nil
}

// Admin is the operator-facing listener: metrics, health and, if asked for,
// profiles.
//
// It is a separate address from the S3 port because none of it is for storage
// clients. Leaving it on loopback is the default for the same reason.
type Admin struct {
	// Listen is the address to serve on. Empty disables the listener entirely;
	// the gateway then serves S3 and exports nothing.
	Listen string `yaml:"listen"`
	// Pprof exposes /debug/pprof on the admin listener. Off by default:
	// profiles carry goroutine stacks and heap contents.
	Pprof bool `yaml:"pprof"`
}

// Client is one credential the proxy accepts from its own clients.
//
// These are unrelated to the upstream credentials, which a client never sees.
// That separation is what stops a client bypassing the gateway to read
// ciphertext directly, or to write plaintext.
type Client struct {
	Name            string `yaml:"name"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	// Buckets lists the buckets this credential may use. "*" means all.
	Buckets []string `yaml:"buckets"`
}

// Server configures the S3 listener.
type Server struct {
	// Listen is the address to serve on. The default binds to loopback only:
	// between client and proxy the data is plaintext, so exposing the port
	// without TLS would undo the point of the gateway.
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
	// BaseDomain enables virtual-hosted-style addressing: with
	// "s3.internal.example" set, bucket.s3.internal.example addresses that
	// bucket. Empty accepts path-style only.
	BaseDomain string `yaml:"base_domain"`
	// AllowUnsignedPayload permits UNSIGNED-PAYLOAD from clients. Off by
	// default: without it the request body is covered by the signature, and
	// turning it on only makes sense behind TLS or in a sidecar, where the hop
	// between client and proxy is already trusted.
	AllowUnsignedPayload bool `yaml:"allow_unsigned_payload"`
}

// TLS configures transport security towards clients.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether a certificate was configured.
func (t TLS) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Upstream configures the storage provider.
type Upstream struct {
	Endpoint        string `yaml:"endpoint"`
	Region          string `yaml:"region"`
	PathStyle       bool   `yaml:"path_style"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"`
}

// Keys configures where the root key that unlocks the keyring comes from.
//
// Whichever source is named, it is consulted once at startup: the KEKs are then
// in memory and no request pays a round trip to a key service.
type Keys struct {
	// Provider selects the root-key source: "file" derives it from a passphrase
	// with Argon2id, "vault" asks Vault's Transit engine to decrypt it, and
	// "awskms" asks AWS KMS. The keyring file records which one sealed it, and
	// a mismatch is refused rather than guessed at.
	Provider string `yaml:"provider"`
	Keyring  string `yaml:"keyring"`
	// PassphraseFile holds the keyring passphrase, for provider "file". If
	// empty, the passphrase is read from $BLINDBUCKET_PASSPHRASE.
	PassphraseFile string `yaml:"passphrase_file"`

	Vault  VaultKeys  `yaml:"vault"`
	AWSKMS AWSKMSKeys `yaml:"awskms"`
}

// VaultKeys addresses the Transit key that seals the keyring.
type VaultKeys struct {
	Address string `yaml:"address"`
	Token   string `yaml:"token"`
	// Mount is where the Transit engine lives. Defaults to "transit".
	Mount     string `yaml:"mount"`
	KeyName   string `yaml:"key_name"`
	Namespace string `yaml:"namespace"`
}

// AWSKMSKeys addresses the KMS key that seals the keyring.
type AWSKMSKeys struct {
	Region string `yaml:"region"`
	// KeyID is a key id, alias or ARN.
	KeyID           string `yaml:"key_id"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"`
	// EncryptionContext is added to the AWS KMS encryption context of a keyring
	// sealed by `keygen`, on top of the fixed "blindbucket" entry every one
	// carries. Put something that identifies the deployment here, and a key
	// policy can then require it. It is not a secret: KMS logs it in
	// CloudTrail, and the keyring file records it.
	EncryptionContext map[string]string `yaml:"encryption_context"`
	// Endpoint overrides kms.<region>.amazonaws.com, for LocalStack and for
	// AWS-compatible endpoints.
	Endpoint string `yaml:"endpoint"`
}

// Names configures object-name encryption (ADR-015).
//
// Off by default, and not a switch that can be flipped back and forth on a
// bucket that has objects in it: with it on, an object is stored under the
// encrypted form of its key, so turning it on makes everything written before
// invisible, and turning it off again makes everything written since invisible.
// Moving an existing bucket across is a rewrite of every object's key.
type Names struct {
	// Encrypt turns object-name encryption on. The keyring must hold a name
	// key; a gateway configured this way against a keyring without one refuses
	// to start rather than serving with names in clear.
	Encrypt bool `yaml:"encrypt"`

	// MaxListingKeys bounds how many keys one listing will sort at once.
	//
	// The provider orders by the encrypted key, so a listing is only in the
	// client's order once its whole prefix has been read -- and the client waits
	// on every one of those round trips. The bound therefore comes from a
	// latency budget rather than a memory one: 100 000 keys is about 2.3 seconds
	// to the first page against a same-region provider and 20 MiB held while it
	// happens. A prefix past the bound is refused rather than served in an order
	// the client cannot use. Zero means the default. See ADR-017.
	MaxListingKeys int `yaml:"max_listing_keys"`

	// MaxConcurrentListings bounds how many of those run at once, because the
	// memory is per listing in flight rather than per gateway: the bound above
	// at 64 clients would be 1.27 GiB. Listings past it wait. Zero means the
	// default.
	MaxConcurrentListings int `yaml:"max_concurrent_listings"`
}

// Crypto configures the segment format.
type Crypto struct {
	// Log2ChunkSize selects the chunk size for new objects. It is also the
	// fallback when reading an object whose metadata does not record one.
	Log2ChunkSize uint8 `yaml:"log2_chunk_size"`
}

// LogValue redacts the upstream credentials.
//
// Nothing logs a Config today. This exists so that nothing can start to: the
// same argument as keys.DEK, which redacts itself rather than relying on every
// call site to remember. Both this and String are needed -- LogValue covers
// slog, String covers the %s and %v that a hurried debug line reaches for.
func (u Upstream) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("endpoint", u.Endpoint),
		slog.String("region", u.Region),
		slog.Bool("path_style", u.PathStyle),
		slog.String("access_key_id", u.AccessKeyID),
		slog.String("secret_access_key", "[REDACTED]"),
		slog.String("session_token", "[REDACTED]"),
	)
}

// String redacts the secrets, so %s and %v cannot print them either.
func (u Upstream) String() string {
	return fmt.Sprintf("upstream{endpoint:%s region:%s access_key_id:%s secret:[REDACTED]}",
		u.Endpoint, u.Region, u.AccessKeyID)
}

// Clients is a list of client credentials.
//
// It is a named type solely so that it can redact itself. slog resolves
// LogValuer on the value it is handed, but not on the elements of a plain slice
// inside it -- so `slog.Any("clients", []Client{...})` marshals the structs and
// prints every secret, which is what a test of this caught after the per-element
// redaction below was already in place.
type Clients []Client

// LogValue redacts every credential in the list.
func (c Clients) LogValue() slog.Value {
	out := make([]slog.Attr, 0, len(c))
	for i, client := range c {
		out = append(out, slog.Any(strconv.Itoa(i), client.LogValue()))
	}
	return slog.GroupValue(out...)
}

// String redacts every credential in the list.
func (c Clients) String() string {
	rendered := make([]string, 0, len(c))
	for _, client := range c {
		rendered = append(rendered, client.String())
	}
	return "[" + strings.Join(rendered, " ") + "]"
}

// LogValue redacts a client credential.
func (c Client) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", c.Name),
		slog.String("access_key_id", c.AccessKeyID),
		slog.String("secret_access_key", "[REDACTED]"),
		slog.Any("buckets", c.Buckets),
	)
}

// String redacts a client credential.
func (c Client) String() string {
	return fmt.Sprintf("client{name:%s access_key_id:%s secret:[REDACTED] buckets:%v}",
		c.Name, c.AccessKeyID, c.Buckets)
}

// envRef matches a ${VARIABLE} reference.
var envRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) {
	//nolint:gosec // the path is a command-line argument; reading it is the point.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Server: Server{Listen: "127.0.0.1:9000"},
		Keys:   Keys{Provider: "file"},
		Crypto: Crypto{Log2ChunkSize: stream.DefaultLog2ChunkSize},
		// Defaults that are not the zero value go here rather than after the
		// decode: yaml.v3 leaves a field alone when the file does not mention
		// it, so this is also what makes an explicit "fail_closed: false"
		// distinguishable from an absent one.
		Audit: Audit{FailClosed: true},
	}
	// KnownFields makes a typo in a key an error rather than a silently ignored
	// setting -- which for something like path_style would mean every request
	// failing for no visible reason.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	// Credentials are only ever referenced, never written in the file.
	for name, field := range map[string]*string{
		"upstream.access_key_id":     &cfg.Upstream.AccessKeyID,
		"upstream.secret_access_key": &cfg.Upstream.SecretAccessKey,
		"upstream.session_token":     &cfg.Upstream.SessionToken,
	} {
		if err := expandEnv(name, field); err != nil {
			return nil, err
		}
	}
	for i := range cfg.Clients {
		for name, field := range map[string]*string{
			"access_key_id":     &cfg.Clients[i].AccessKeyID,
			"secret_access_key": &cfg.Clients[i].SecretAccessKey,
		} {
			if err := expandEnv("clients["+strconv.Itoa(i)+"]."+name, field); err != nil {
				return nil, err
			}
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// expandEnv resolves a ${VAR} reference in place.
func expandEnv(name string, field *string) error {
	match := envRef.FindStringSubmatch(*field)
	if match == nil {
		return nil
	}
	value, ok := os.LookupEnv(match[1])
	if !ok {
		return fmt.Errorf("config: %s references $%s, which is not set", name, match[1])
	}
	*field = value
	return nil
}

// validate checks the root-key source names everything it needs.
//
// A missing field here is a process that starts and then cannot open its
// keyring, which is worse than one that refuses to start.
func (k Keys) validate() error {
	switch k.Provider {
	case "file":
		return nil
	case "vault":
		switch {
		case k.Vault.Address == "":
			return fmt.Errorf("keys.vault.address is required for provider \"vault\"")
		case k.Vault.Token == "":
			return fmt.Errorf("keys.vault.token is required for provider \"vault\"")
		case k.Vault.KeyName == "":
			return fmt.Errorf("keys.vault.key_name is required for provider \"vault\"")
		}
		return nil
	case "awskms":
		switch {
		case k.AWSKMS.Region == "":
			return fmt.Errorf("keys.awskms.region is required for provider \"awskms\"")
		case k.AWSKMS.KeyID == "":
			return fmt.Errorf("keys.awskms.key_id is required for provider \"awskms\"")
		case k.AWSKMS.AccessKeyID == "" || k.AWSKMS.SecretAccessKey == "":
			return fmt.Errorf("keys.awskms credentials are required for provider \"awskms\"")
		}
		return nil
	default:
		return fmt.Errorf("keys.provider %q is not one of \"file\", \"vault\", \"awskms\"", k.Provider)
	}
}

func (c *Config) validate() error {
	switch {
	case c.Server.Listen == "":
		return fmt.Errorf("server.listen must not be empty")
	case c.Upstream.Endpoint == "":
		return fmt.Errorf("upstream.endpoint is required")
	case c.Upstream.Region == "":
		return fmt.Errorf("upstream.region is required")
	case c.Upstream.AccessKeyID == "" || c.Upstream.SecretAccessKey == "":
		return fmt.Errorf("upstream credentials are required")
	case len(c.Clients) == 0:
		return fmt.Errorf("at least one entry under clients is required; " +
			"the proxy does not serve unauthenticated requests")
	case c.Keys.Keyring == "":
		return fmt.Errorf("keys.keyring is required")
	}
	if err := c.Keys.validate(); err != nil {
		return err
	}
	for i, client := range c.Clients {
		switch {
		case client.Name == "":
			return fmt.Errorf("clients[%d] has no name", i)
		case client.AccessKeyID == "":
			return fmt.Errorf("client %q has no access_key_id", client.Name)
		case client.SecretAccessKey == "":
			return fmt.Errorf("client %q has no secret_access_key", client.Name)
		case len(client.Buckets) == 0:
			// An empty list would deny everything silently, which looks like a
			// broken proxy rather than a configuration mistake.
			return fmt.Errorf("client %q lists no buckets (use \"*\" for all)", client.Name)
		}
	}
	if err := stream.ValidateLog2ChunkSize(c.Crypto.Log2ChunkSize); err != nil {
		return fmt.Errorf("crypto.log2_chunk_size: %w", err)
	}
	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		return fmt.Errorf("server.tls needs both cert_file and key_file, or neither")
	}
	return c.Audit.validate()
}

func (a Audit) validate() error {
	if !a.Enabled() {
		return nil
	}
	switch {
	case a.CheckpointEvery < 0:
		return fmt.Errorf("audit.checkpoint_every must not be negative")
	case a.RotateBytes < 0:
		return fmt.Errorf("audit.rotate_bytes must not be negative")
	}
	interval, err := a.Interval()
	if err != nil {
		return err
	}
	if interval < 0 {
		return fmt.Errorf("audit.checkpoint_interval must not be negative")
	}
	return nil
}

// ExposesPlaintextPublicly reports whether the listener would carry plaintext
// beyond the loopback interface without TLS.
//
// Between client and proxy the body is not encrypted -- that is the entire
// point of the gateway -- so this is worth saying out loud at startup rather
// than leaving an operator to discover it.
func (c *Config) ExposesPlaintextPublicly() bool {
	if c.Server.TLS.Enabled() {
		return false
	}
	// net.SplitHostPort rather than a manual split: an IPv6 listener is written
	// "[::1]:9000", and cutting at the first colon yields "[".
	host, _, err := net.SplitHostPort(c.Server.Listen)
	switch {
	case err != nil:
		return true
	case host == "":
		// ":9000" means every interface.
		return true
	case host == "localhost":
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	return true
}
