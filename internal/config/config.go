// Package config loads and validates blindbucket's configuration file.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/awscreds"
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

	Freshness Freshness `yaml:"freshness"`
}

// Freshness configures rollback detection (ADR-018).
//
// Off unless a path is given, and deliberately so. The index is memory
// proportional to live objects -- about 112 MiB per million -- which is a shape
// of cost nothing else in this gateway has. And in a deployment where several
// instances write the same objects it cannot tell a rollback from a peer's
// write, because the tag it records carries no order. Neither should arrive by
// upgrade.
type Freshness struct {
	// Index is the file to keep the index in. Empty disables rollback detection
	// entirely. The directory must exist and must not be shared between
	// instances: two gateways writing one index would fight over it, and the
	// guarantee is per instance in any case.
	Index string `yaml:"index"`
	// TombstoneRetention is how long a delete is remembered, as a Go duration.
	// Tombstones are the one entry that does not shrink when the bucket does, so
	// they expire -- and past this a suppressed delete stops being detectable.
	// Empty selects the package default of 90 days.
	TombstoneRetention string `yaml:"tombstone_retention"`
	// SyncEvery is how many index records may be written between fsyncs. A lost
	// tail costs detection for the objects in it and nothing else, which is why
	// this is amortised rather than one fsync per write: syncing every record
	// costs 3.69 ms against 21 µs. Zero selects the package default.
	SyncEvery int64 `yaml:"sync_every"`
}

// Enabled reports whether rollback detection was asked for.
func (f Freshness) Enabled() bool { return f.Index != "" }

// Retention parses TombstoneRetention. Zero selects the package default.
func (f Freshness) Retention() (time.Duration, error) {
	if f.TombstoneRetention == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(f.TombstoneRetention)
	if err != nil {
		return 0, fmt.Errorf("freshness.tombstone_retention: %w", err)
	}
	return d, nil
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
	// Export configures streaming audit records to an external SIEM over
	// syslog (RFC 5424 over TLS) or OTLP logs. The export stream is not
	// signed; verification runs on the file.
	Export AuditExport `yaml:"export"`
}

// AuditExport configures exporting audit entries over syslog and/or OTLP.
type AuditExport struct {
	Syslog *SyslogExport `yaml:"syslog"`
	OTLP   *OTLPExport   `yaml:"otlp"`
}

// Enabled reports whether any export destination is configured.
func (e AuditExport) Enabled() bool {
	return (e.Syslog != nil && e.Syslog.Endpoint != "") ||
		(e.OTLP != nil && e.OTLP.Endpoint != "")
}

// SyslogExport configures exporting audit entries over syslog (RFC 5424 over TLS).
type SyslogExport struct {
	Endpoint string `yaml:"endpoint"`
	Network  string `yaml:"network"`
	CACert   string `yaml:"ca_cert"`
	AppName  string `yaml:"app_name"`
	Facility *int   `yaml:"facility"`
	Severity *int   `yaml:"severity"`
}

// OTLPExport configures exporting audit entries over OTLP logs (HTTPS).
type OTLPExport struct {
	Endpoint string            `yaml:"endpoint"`
	Headers  map[string]string `yaml:"headers"`
	CACert   string            `yaml:"ca_cert"`
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
	// Dashboard is the read-only status page, on a listener of its own
	// (ADR-035).
	Dashboard Dashboard `yaml:"dashboard"`
}

// Dashboard configures the read-only status page.
type Dashboard struct {
	// Listen is the address to serve the page on. Empty, the default, serves
	// none. It must be a loopback address: the page is reached from elsewhere
	// through kubectl port-forward or an SSH tunnel, never directly, until it
	// has an authentication of its own (ADR-035).
	Listen string `yaml:"listen"`
}

// validate refuses a dashboard address that is not loopback.
func (d Dashboard) validate() error {
	if d.Listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(d.Listen)
	if err != nil {
		return fmt.Errorf("admin.dashboard.listen %q is not host:port: %w", d.Listen, err)
	}
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("admin.dashboard.listen %q is not a loopback address. The dashboard "+
		"has no authentication of its own, so it serves only on loopback, such as "+
		"127.0.0.1:9101; reach it from elsewhere with kubectl port-forward or an SSH tunnel "+
		"(ADR-035)", d.Listen)
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
	// AllowUnsignedPayload accepts UNSIGNED-PAYLOAD from clients. On by
	// default (ADR-029): AWS CLI 2.38 and later send it on every GET and on
	// multipart control requests, and the bodies that carry data reach the
	// gateway unsigned anyway, as STREAMING-UNSIGNED-PAYLOAD-TRAILER, which no
	// setting here has ever refused. An explicit false still refuses
	// UNSIGNED-PAYLOAD and nothing else.
	AllowUnsignedPayload bool `yaml:"allow_unsigned_payload"`
	// RequireSignedPayload refuses every request whose body the signature does
	// not cover -- UNSIGNED-PAYLOAD and STREAMING-UNSIGNED-PAYLOAD-TRAILER
	// alike -- whatever allow_unsigned_payload says. For a deployment where
	// the hop between client and gateway is plaintext and not trusted; the
	// clients then have to sign their bodies, which the AWS CLI does only over
	// HTTP and with preferred_transfer_client = classic.
	RequireSignedPayload bool `yaml:"require_signed_payload"`

	Presign Presign `yaml:"presign"`

	// CORS lets browser pages on the listed origins call the gateway: a
	// presigned upload from a page, above all (ADR-036). Off unless origins
	// are listed.
	CORS CORS `yaml:"cors"`
}

// CORS configures the gateway's own answers to browsers. The S3 bucket-CORS
// sub-resource stays refused: the provider would store it, and it describes
// the provider's endpoint, which a browser never reaches.
type CORS struct {
	// AllowedOrigins are origins exactly as a browser sends them in Origin:
	// scheme, host and a port only if it is not the default,
	// "https://app.example". There is no wildcard.
	AllowedOrigins []string `yaml:"allowed_origins"`
}

func (c CORS) validate() error {
	for _, origin := range c.AllowedOrigins {
		if origin == "*" {
			return fmt.Errorf("server.cors.allowed_origins: \"*\" is not accepted; list the " +
				"origins of the pages that call the gateway")
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("server.cors.allowed_origins: %q is not an origin; write it as "+
				"a browser sends it, https://app.example, with no path or trailing slash", origin)
		}
		if origin != strings.ToLower(origin) {
			return fmt.Errorf("server.cors.allowed_origins: %q has capitals, and a browser "+
				"sends an origin in lower case, so it would never match", origin)
		}
		if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
			return fmt.Errorf("server.cors.allowed_origins: %q names the default port, which a "+
				"browser leaves out of Origin, so it would never match", origin)
		}
	}
	return nil
}

// Presign configures presigned URLs (ADR-019).
//
// Unlike name encryption, the audit log and the rollback index, this is **on** by
// default: it removes a refusal of something every S3 client expects rather than
// adding a cost or weakening a hop. A presigned URL can do nothing the credential
// that signed it could not already do.
//
// What it does change is that a credential holder can delegate -- before it,
// handing someone access meant handing over the secret key. That is strictly less
// dangerous than the alternative people actually use, and it is still new for a
// deployment, which is why it can be switched off.
type Presign struct {
	// Enabled accepts signatures that arrive in the query string. Defaults to
	// true; set it to false to refuse presigned URLs outright.
	Enabled bool `yaml:"enabled"`
	// MaxExpiry caps the window a presigned URL may name, as a Go duration.
	// Empty selects S3's own maximum of seven days, which is what keeps working
	// clients working; most deployments should set something far shorter, and
	// the cost of doing so is only that longer URLs are refused.
	MaxExpiry string `yaml:"max_expiry"`

	// Uploads serves presigned PutObject and UploadPart (ADR-036). Off unless
	// its max_size is set.
	Uploads PresignUploads `yaml:"uploads"`
}

// PresignUploads configures presigned uploads, the browser-upload pattern: a
// backend that holds a credential hands a browser a URL to upload one file to.
//
// There is no default size. Setting one is what turns uploads on, so that no
// configuration serves a URL that uploads without a bound.
type PresignUploads struct {
	// MaxSize is the most one presigned request may upload, in bytes or with
	// a binary suffix: "100MiB", "2GiB". It holds per request, so for a
	// multipart upload per part; the total stays the backend's to bound.
	MaxSize string `yaml:"max_size"`
	// MaxExpiry caps an upload URL's window, separately from the cap on
	// downloads, as a Go duration. Empty selects one hour.
	MaxExpiry string `yaml:"max_expiry"`
}

// maxPresignUpload is S3's own limit on one PUT, and on one part.
const maxPresignUpload = 5 << 30

// Size parses MaxSize. Zero means uploads are not served.
func (u PresignUploads) Size() (int64, error) {
	if u.MaxSize == "" {
		return 0, nil
	}
	n, err := parseBytes(u.MaxSize)
	if err != nil {
		return 0, fmt.Errorf("server.presign.uploads.max_size: %w", err)
	}
	return n, nil
}

// Expiry parses MaxExpiry. Zero selects the package default.
func (u PresignUploads) Expiry() (time.Duration, error) {
	if u.MaxExpiry == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(u.MaxExpiry)
	if err != nil {
		return 0, fmt.Errorf("server.presign.uploads.max_expiry: %w", err)
	}
	return d, nil
}

// parseBytes reads a byte count with an optional binary suffix. Decimal ones,
// "MB" and the like, are refused rather than guessed at.
func parseBytes(s string) (int64, error) {
	units := []struct {
		suffix string
		factor int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"B", 1}}
	number, factor := strings.TrimSpace(s), int64(1)
	for _, u := range units {
		if rest, ok := strings.CutSuffix(number, u.suffix); ok {
			number, factor = strings.TrimSpace(rest), u.factor
			break
		}
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a positive number of bytes; write it as 104857600 or 100MiB", s)
	}
	if n > math.MaxInt64/factor {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return n * factor, nil
}

// Expiry parses MaxExpiry. Zero selects the package default.
func (p Presign) Expiry() (time.Duration, error) {
	if p.MaxExpiry == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(p.MaxExpiry)
	if err != nil {
		return 0, fmt.Errorf("server.presign.max_expiry: %w", err)
	}
	return d, nil
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
	// CredentialSource says where the upstream credentials come from when they
	// are not the keys above: env, profile, web_identity, container, imds or
	// chain (ADR-024). Empty means the keys, as "static" does.
	CredentialSource string `yaml:"credential_source"`
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
	// CredentialSource is the upstream's credential_source, for KMS.
	CredentialSource string `yaml:"credential_source"`
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
// `blindbucket migrate-names` moves an existing bucket across, once every
// instance has it on (ADR-022); nothing moves one back.
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
		slog.String("credential_source", u.CredentialSource),
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

// envRef matches a ${VARIABLE} reference that is the whole value.
var envRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// envRefWithin matches a ${VARIABLE} reference anywhere in a value. Only an
// HTTP header takes one, because only a header carries a credential inside
// other text: "Bearer ${OTLP_TOKEN}".
var envRefWithin = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) {
	//nolint:gosec // the path is a command-line argument; reading it is the point.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("config: %w; pass --config, or write one with `blindbucket init`", err)
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	cfg := &Config{
		Keys:   Keys{Provider: "file"},
		Crypto: Crypto{Log2ChunkSize: stream.DefaultLog2ChunkSize},
		// Defaults that are not the zero value go here rather than after the
		// decode: yaml.v3 leaves a field alone when the file does not mention
		// it, so this is also what makes an explicit "fail_closed: false"
		// distinguishable from an absent one.
		Audit: Audit{FailClosed: true},
		// Presigned URLs are on by default for ADR-019's reasons, unsigned
		// payloads for ADR-029's. Here rather than after the decode, so that an
		// explicit false is distinguishable from an absent key.
		Server: Server{
			Listen:               "127.0.0.1:9000",
			Presign:              Presign{Enabled: true},
			AllowUnsignedPayload: true,
		},
	}
	// KnownFields makes a typo in a key an error rather than a silently ignored
	// setting -- which for something like path_style would mean every request
	// failing for no visible reason.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: %s: %w; blindbucket.example.yaml lists every setting, "+
			"with its type", path, err)
	}

	// Credentials are only ever referenced, never written in the file.
	for name, field := range map[string]*string{
		"upstream.access_key_id":        &cfg.Upstream.AccessKeyID,
		"upstream.secret_access_key":    &cfg.Upstream.SecretAccessKey,
		"upstream.session_token":        &cfg.Upstream.SessionToken,
		"keys.vault.token":              &cfg.Keys.Vault.Token,
		"keys.awskms.access_key_id":     &cfg.Keys.AWSKMS.AccessKeyID,
		"keys.awskms.secret_access_key": &cfg.Keys.AWSKMS.SecretAccessKey,
		"keys.awskms.session_token":     &cfg.Keys.AWSKMS.SessionToken,
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
	if cfg.Audit.Export.OTLP != nil {
		for k, v := range cfg.Audit.Export.OTLP.Headers {
			val, err := expandEnvWithin("audit.export.otlp.headers["+k+"]", v)
			if err != nil {
				return nil, err
			}
			cfg.Audit.Export.OTLP.Headers[k] = val
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
	value, err := lookupEnv(name, match[1])
	if err != nil {
		return err
	}
	*field = value
	return nil
}

// expandEnvWithin resolves every ${VAR} reference in a value, in one pass: a
// variable's value is never itself searched for references.
func expandEnvWithin(name, value string) (string, error) {
	var firstErr error
	out := envRefWithin.ReplaceAllStringFunc(value, func(ref string) string {
		resolved, err := lookupEnv(name, envRefWithin.FindStringSubmatch(ref)[1])
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return resolved
	})
	return out, firstErr
}

func lookupEnv(name, variable string) (string, error) {
	value, ok := os.LookupEnv(variable)
	if !ok {
		return "", fmt.Errorf("config: %s references $%s, which is not set; set it, or load the file "+
			"that holds it -- for a configuration `blindbucket init` wrote: "+
			"set -a; . ./blindbucket.env; set +a", name, variable)
	}
	return value, nil
}

// validateCredentials checks one section's AWS credentials: keys, or a source
// to resolve them from, and never both (ADR-024). Neither is an error, as it
// always was -- falling back to whatever the environment offers would let a
// forgotten key quietly pick up an instance role.
func validateCredentials(section, source, id, secret, token string) error {
	switch source {
	case "", awscreds.SourceStatic:
		if id == "" || secret == "" {
			return fmt.Errorf("%s credentials are required: access_key_id and secret_access_key, "+
				"or a credential_source -- env, profile, web_identity, container, imds or chain "+
				"(ADR-024)", section)
		}
		return nil
	}
	if !slices.Contains(awscreds.Sources, source) {
		return fmt.Errorf("%s.credential_source %q is not one of %s", section, source,
			strings.Join(awscreds.Sources, ", "))
	}
	if id != "" || secret != "" || token != "" {
		return fmt.Errorf("%s has keys and credential_source %q; set one or the other", section, source)
	}
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
		return validateURL("keys.vault.address", k.Vault.Address)
	case "awskms":
		switch {
		case k.AWSKMS.Region == "":
			return fmt.Errorf("keys.awskms.region is required for provider \"awskms\"")
		case k.AWSKMS.KeyID == "":
			return fmt.Errorf("keys.awskms.key_id is required for provider \"awskms\"")
		}
		return validateCredentials("keys.awskms", k.AWSKMS.CredentialSource,
			k.AWSKMS.AccessKeyID, k.AWSKMS.SecretAccessKey, k.AWSKMS.SessionToken)
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
	case validateURL("upstream.endpoint", c.Upstream.Endpoint) != nil:
		return validateURL("upstream.endpoint", c.Upstream.Endpoint)
	case c.Upstream.Region == "":
		return fmt.Errorf("upstream.region is required")
	case len(c.Clients) == 0:
		return fmt.Errorf("at least one entry under clients is required; " +
			"the proxy does not serve unauthenticated requests")
	case c.Keys.Keyring == "":
		return fmt.Errorf("keys.keyring is required")
	}
	if err := validateCredentials("upstream", c.Upstream.CredentialSource,
		c.Upstream.AccessKeyID, c.Upstream.SecretAccessKey, c.Upstream.SessionToken); err != nil {
		return err
	}
	if err := c.Keys.validate(); err != nil {
		return err
	}
	if err := c.Admin.Dashboard.validate(); err != nil {
		return err
	}
	keyOwner := map[string]int{}
	for i, client := range c.Clients {
		switch {
		case client.Name == "":
			return fmt.Errorf("clients[%d].name is empty", i)
		case client.AccessKeyID == "":
			return fmt.Errorf("clients[%d].access_key_id is empty (client %q)", i, client.Name)
		case client.SecretAccessKey == "":
			return fmt.Errorf("clients[%d].secret_access_key is empty (client %q)", i, client.Name)
		case len(client.Buckets) == 0:
			// An empty list would deny everything silently, which looks like a
			// broken proxy rather than a configuration mistake.
			return fmt.Errorf("clients[%d].buckets is empty (client %q); list the buckets "+
				"it may use, or \"*\" for all", i, client.Name)
		}
		// Caught here as well as in internal/auth, because only here is the
		// configuration's own path to the key known.
		if first, ok := keyOwner[client.AccessKeyID]; ok {
			return fmt.Errorf("clients[%d].access_key_id is also clients[%d]'s; each client "+
				"needs a key of its own", i, first)
		}
		keyOwner[client.AccessKeyID] = i
	}
	if err := stream.ValidateLog2ChunkSize(c.Crypto.Log2ChunkSize); err != nil {
		return fmt.Errorf("crypto.log2_chunk_size: %w", err)
	}
	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		return fmt.Errorf("server.tls needs both cert_file and key_file, or neither")
	}
	if err := c.Audit.validate(); err != nil {
		return err
	}
	if err := c.Server.Presign.validate(); err != nil {
		return err
	}
	if err := c.Server.CORS.validate(); err != nil {
		return err
	}
	// A presigned body is unsigned by construction: at signing time it did
	// not exist. A listener that requires signed bodies cannot serve one.
	if c.Server.Presign.Uploads.MaxSize != "" && c.Server.RequireSignedPayload {
		return fmt.Errorf("server.presign.uploads.max_size is set, but server.require_signed_payload " +
			"refuses every body a signature does not cover, and a presigned upload's never is")
	}
	return c.Freshness.validate()
}

// validateURL checks that a setting holds an http or https URL with a host:
// a bare host:port parses as a URL whose scheme is the host, and fails much
// later with a message about the scheme.
func validateURL(setting, value string) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s %q must be a URL starting with http:// or https://", setting, value)
	}
	return nil
}

func (p Presign) validate() error {
	expiry, err := p.Expiry()
	if err != nil {
		return err
	}
	if expiry < 0 {
		return fmt.Errorf("server.presign.max_expiry must not be negative")
	}
	if expiry > auth.MaxPresignExpiry {
		return fmt.Errorf("server.presign.max_expiry is %s; S3's own maximum is %s",
			expiry, auth.MaxPresignExpiry)
	}
	size, err := p.Uploads.Size()
	if err != nil {
		return err
	}
	if size > maxPresignUpload {
		return fmt.Errorf("server.presign.uploads.max_size is %d bytes; S3 takes at most 5GiB "+
			"in one PUT, and a larger file goes up in parts", size)
	}
	uploadExpiry, err := p.Uploads.Expiry()
	if err != nil {
		return err
	}
	if uploadExpiry < 0 || uploadExpiry > auth.MaxPresignExpiry {
		return fmt.Errorf("server.presign.uploads.max_expiry is %s; it must lie between 0 and %s",
			uploadExpiry, auth.MaxPresignExpiry)
	}
	if size > 0 && !p.Enabled {
		return fmt.Errorf("server.presign.uploads.max_size is set, but server.presign.enabled is " +
			"false, which refuses every presigned URL")
	}
	return nil
}

func (f Freshness) validate() error {
	if !f.Enabled() {
		return nil
	}
	if f.SyncEvery < 0 {
		return fmt.Errorf("freshness.sync_every must not be negative")
	}
	retention, err := f.Retention()
	if err != nil {
		return err
	}
	if retention < 0 {
		return fmt.Errorf("freshness.tombstone_retention must not be negative")
	}
	return nil
}

// syslogName reports whether s fits an RFC 5424 header field: 1 to max
// printable ASCII characters, none of them a space.
func syslogName(s string, maxLen int) bool {
	if len(s) == 0 || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func (a Audit) validate() error {
	if !a.Enabled() {
		if a.Export.Enabled() {
			return fmt.Errorf("audit.export requires audit.log to be configured")
		}
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
	if a.Export.Syslog != nil {
		if a.Export.Syslog.Endpoint == "" {
			return fmt.Errorf("audit.export.syslog.endpoint is required when syslog export is configured")
		}
		switch a.Export.Syslog.Network {
		case "", "tcp", "tcp4", "tcp6":
		default:
			return fmt.Errorf("audit.export.syslog.network must be tcp, tcp4 or tcp6, not %q: "+
				"the export runs over TLS", a.Export.Syslog.Network)
		}
		if name := a.Export.Syslog.AppName; name != "" && !syslogName(name, 48) {
			return fmt.Errorf("audit.export.syslog.app_name must be 1 to 48 printable ASCII "+
				"characters without spaces (RFC 5424), not %q", name)
		}
		if a.Export.Syslog.Facility != nil {
			if *a.Export.Syslog.Facility < 0 || *a.Export.Syslog.Facility > 23 {
				return fmt.Errorf("audit.export.syslog.facility must be between 0 and 23")
			}
		}
		if a.Export.Syslog.Severity != nil {
			if *a.Export.Syslog.Severity < 0 || *a.Export.Syslog.Severity > 7 {
				return fmt.Errorf("audit.export.syslog.severity must be between 0 and 7")
			}
		}
	}
	if a.Export.OTLP != nil {
		if a.Export.OTLP.Endpoint == "" {
			return fmt.Errorf("audit.export.otlp.endpoint is required when otlp export is configured")
		}
		u, err := url.Parse(a.Export.OTLP.Endpoint)
		if err != nil || u.Scheme != "https" {
			return fmt.Errorf("audit.export.otlp.endpoint must be a valid https URL")
		}
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
