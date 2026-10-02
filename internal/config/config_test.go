package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

const minimal = `
upstream:
  endpoint: http://localhost:9002
  region: us-east-1
  path_style: true
  access_key_id: AKID
  secret_access_key: SECRET
clients:
  - name: test
    access_key_id: CLIENTKEY
    secret_access_key: CLIENTSECRET
    buckets: ["*"]
keys:
  keyring: keyring.json
`

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q, want the loopback default", cfg.Server.Listen)
	}
	if cfg.Keys.Provider != "file" {
		t.Errorf("provider = %q, want file", cfg.Keys.Provider)
	}
	if cfg.Crypto.Log2ChunkSize != 16 {
		t.Errorf("log2_chunk_size = %d, want 16", cfg.Crypto.Log2ChunkSize)
	}
}

// TestLoadResolvesEnvReferences covers the rule that secrets are referenced,
// never written into the file.
func TestLoadResolvesEnvReferences(t *testing.T) {
	t.Setenv("TEST_UPSTREAM_KEY", "resolved-key")
	t.Setenv("TEST_UPSTREAM_SECRET", "resolved-secret")

	t.Setenv("TEST_CLIENT_KEY", "resolved-client-key")

	cfg, err := Load(write(t, `
upstream:
  endpoint: http://localhost:9002
  region: us-east-1
  access_key_id: ${TEST_UPSTREAM_KEY}
  secret_access_key: ${TEST_UPSTREAM_SECRET}
clients:
  - name: test
    access_key_id: ${TEST_CLIENT_KEY}
    secret_access_key: literal-secret
    buckets: ["backups"]
keys:
  keyring: keyring.json
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Upstream.AccessKeyID != "resolved-key" {
		t.Errorf("access_key_id = %q, want the resolved value", cfg.Upstream.AccessKeyID)
	}
	if cfg.Upstream.SecretAccessKey != "resolved-secret" {
		t.Errorf("secret_access_key = %q, want the resolved value", cfg.Upstream.SecretAccessKey)
	}
	// Client credentials are referenced the same way, and a literal value is
	// left alone.
	if cfg.Clients[0].AccessKeyID != "resolved-client-key" {
		t.Errorf("client access_key_id = %q, want the resolved value", cfg.Clients[0].AccessKeyID)
	}
	if cfg.Clients[0].SecretAccessKey != "literal-secret" {
		t.Errorf("client secret_access_key = %q, want it untouched", cfg.Clients[0].SecretAccessKey)
	}
}

// TestLoadResolvesRootKeyCredentials holds the root-key sources to the same
// rule: a Vault token or a set of KMS credentials is as much a secret as the
// upstream's, and a file that has to spell one out is a file that cannot be
// committed or mounted from a ConfigMap.
func TestLoadResolvesRootKeyCredentials(t *testing.T) {
	t.Setenv("TEST_KMS_KEY", "resolved-kms-key")
	t.Setenv("TEST_KMS_SECRET", "resolved-kms-secret")
	t.Setenv("TEST_KMS_TOKEN", "resolved-kms-token")
	t.Setenv("TEST_VAULT_TOKEN", "resolved-vault-token")

	base := strings.TrimSuffix(minimal, "keys:\n  keyring: keyring.json\n")
	cfg, err := Load(write(t, base+`
keys:
  provider: awskms
  keyring: keyring.json
  awskms:
    region: eu-central-1
    key_id: alias/blindbucket
    access_key_id: ${TEST_KMS_KEY}
    secret_access_key: ${TEST_KMS_SECRET}
    session_token: ${TEST_KMS_TOKEN}
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	kms := cfg.Keys.AWSKMS
	if kms.AccessKeyID != "resolved-kms-key" || kms.SecretAccessKey != "resolved-kms-secret" ||
		kms.SessionToken != "resolved-kms-token" {
		t.Errorf("awskms credentials = %q, %q, %q, want the resolved values",
			kms.AccessKeyID, kms.SecretAccessKey, kms.SessionToken)
	}

	cfg, err = Load(write(t, base+`
keys:
  provider: vault
  keyring: keyring.json
  vault:
    address: http://127.0.0.1:8200
    token: ${TEST_VAULT_TOKEN}
    key_name: blindbucket
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Keys.Vault.Token != "resolved-vault-token" {
		t.Errorf("vault token = %q, want the resolved value", cfg.Keys.Vault.Token)
	}
}

// TestLoadFailsOnMissingEnvReference matters because the alternative is starting
// with an empty credential and failing on every request instead.
func TestLoadFailsOnMissingEnvReference(t *testing.T) {
	_, err := Load(write(t, `
upstream:
  endpoint: http://localhost:9002
  region: us-east-1
  access_key_id: ${DEFINITELY_NOT_SET_ANYWHERE}
  secret_access_key: SECRET
clients:
  - name: test
    access_key_id: k
    secret_access_key: s
    buckets: ["*"]
keys:
  keyring: keyring.json
`))
	if err == nil {
		t.Fatal("an unset environment reference was accepted")
	}
	if !strings.Contains(err.Error(), "DEFINITELY_NOT_SET_ANYWHERE") {
		t.Errorf("error = %v, want it to name the missing variable", err)
	}
}

// TestLoadRejectsUnknownFields catches typos. A misspelled path_style would
// otherwise be ignored and every request would fail for no visible reason.
func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(write(t, minimal+"\nupstrem:\n  endpoint: typo\n"))
	if err == nil {
		t.Fatal("an unknown top-level field was accepted")
	}
}

func TestValidation(t *testing.T) {
	const withClients = `
clients:
  - name: test
    access_key_id: k
    secret_access_key: s
    buckets: ["*"]`

	tests := map[string]string{
		"no clients": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}`,
		"client without a name": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}
clients: [{access_key_id: k, secret_access_key: s, buckets: ["*"]}]`,
		"client without buckets": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}
clients: [{name: n, access_key_id: k, secret_access_key: s}]`,
		"no endpoint": `
upstream: {region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}`,
		"no region": `
upstream: {endpoint: "http://x", access_key_id: a, secret_access_key: b}
keys: {keyring: k}` + withClients + `,`,
		"no credentials": `
upstream: {endpoint: "http://x", region: r}
keys: {keyring: k}`,
		"no keyring": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {}`,
		"unsupported key provider": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {provider: vault, keyring: k}` + withClients,
		"chunk size out of range": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}
crypto: {log2_chunk_size: 30}` + withClients,
		"half-configured TLS": `
server: {tls: {cert_file: /tmp/c}}
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}` + withClients,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Error("an invalid configuration was accepted")
			}
		})
	}
}

// TestExposesPlaintextPublicly drives the startup warning. Between client and
// proxy the body is plaintext, so a non-loopback listener without TLS is worth
// saying out loud.
func TestExposesPlaintextPublicly(t *testing.T) {
	tests := []struct {
		listen string
		tls    bool
		want   bool
	}{
		{"127.0.0.1:9000", false, false},
		{"localhost:9000", false, false},
		{"[::1]:9000", false, false},
		{"0.0.0.0:9000", false, true},
		{":9000", false, true},
		{"10.0.0.5:9000", false, true},
		{"0.0.0.0:9000", true, false},
	}
	for _, tc := range tests {
		cfg := &Config{Server: Server{Listen: tc.listen}}
		if tc.tls {
			cfg.Server.TLS = TLS{CertFile: "c", KeyFile: "k"}
		}
		if got := cfg.ExposesPlaintextPublicly(); got != tc.want {
			t.Errorf("listen=%q tls=%t: got %t, want %t", tc.listen, tc.tls, got, tc.want)
		}
	}
}

func TestAuditIsOffUnlessAPathIsGiven(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.Enabled() {
		t.Error("audit logging is on without a path")
	}
}

// TestAuditFailsClosedByDefault is the one default here that has to be the safe
// one: the attack it guards against is filling a disk to switch auditing off.
func TestAuditFailsClosedByDefault(t *testing.T) {
	cfg, err := Load(write(t, minimal+`
audit:
  log: /var/lib/blindbucket/audit.log
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	switch {
	case !cfg.Audit.Enabled():
		t.Error("audit logging is off although a path was given")
	case !cfg.Audit.FailClosed:
		t.Error("fail_closed defaults to false; it must default to true")
	}
}

// TestAuditFailClosedCanBeTurnedOff checks that an explicit false survives the
// default above, which a plain bool with a non-zero default would otherwise eat.
func TestAuditFailClosedCanBeTurnedOff(t *testing.T) {
	cfg, err := Load(write(t, minimal+`
audit:
  log: /var/lib/blindbucket/audit.log
  fail_closed: false
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.FailClosed {
		t.Error("an explicit fail_closed: false was overwritten by the default")
	}
}

func TestAuditIntervalIsParsed(t *testing.T) {
	cfg, err := Load(write(t, minimal+`
audit:
  log: /var/lib/blindbucket/audit.log
  checkpoint_interval: 90s
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	interval, err := cfg.Audit.Interval()
	if err != nil {
		t.Fatalf("Interval: %v", err)
	}
	if interval != 90*time.Second {
		t.Errorf("checkpoint_interval parsed to %s, want 90s", interval)
	}
}

func TestAuditRejectsNonsense(t *testing.T) {
	cases := map[string]string{
		"an unparseable interval": "checkpoint_interval: soon",
		"a negative interval":     "checkpoint_interval: -5s",
		"a negative count":        "checkpoint_every: -1",
		"a negative rotate size":  "rotate_bytes: -1",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, minimal+`
audit:
  log: /var/lib/blindbucket/audit.log
  `+line+"\n"))
			if err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// TestCredentialSourcesAreAccepted: a section names a source instead of
// keys, for every source ADR-024 defines, and "static" with keys is the same
// as no source at all.
func TestCredentialSourcesAreAccepted(t *testing.T) {
	const clientsOK = `clients: [{name: c, access_key_id: k, secret_access_key: s, buckets: ["*"]}]`
	for _, source := range []string{"env", "profile", "web_identity", "container", "imds", "chain"} {
		body := fmt.Sprintf("upstream: {endpoint: \"http://x\", region: r, credential_source: %s}\n%s\n"+
			"keys: {provider: awskms, keyring: k, awskms: {region: r, key_id: i, credential_source: %s}}\n",
			source, clientsOK, source)
		cfg, err := Load(write(t, body))
		if err != nil {
			t.Errorf("%s: %v", source, err)
			continue
		}
		if cfg.Upstream.CredentialSource != source || cfg.Keys.AWSKMS.CredentialSource != source {
			t.Errorf("%s: read as %q and %q", source, cfg.Upstream.CredentialSource,
				cfg.Keys.AWSKMS.CredentialSource)
		}
	}
	if _, err := Load(write(t, "upstream: {endpoint: \"http://x\", region: r, access_key_id: a, "+
		"secret_access_key: b, credential_source: static}\n"+clientsOK+"\nkeys: {keyring: k}\n")); err != nil {
		t.Errorf("static with keys: %v", err)
	}
}

// TestValidationNamesTheProblem complements TestValidation, which only requires
// a refusal: here each case must be refused for its own reason, so a check that
// stopped working cannot hide behind another one that fires first.
func TestValidationNamesTheProblem(t *testing.T) {
	const (
		upstreamOK = `upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}`
		clientsOK  = `clients: [{name: c, access_key_id: k, secret_access_key: s, buckets: ["*"]}]`
		keysOK     = `keys: {keyring: k}`
	)
	doc := func(parts ...string) string { return strings.Join(parts, "\n") + "\n" }

	for name, tc := range map[string]struct{ body, want string }{
		"an empty listen address": {doc(`server: {listen: ""}`, upstreamOK, clientsOK, keysOK),
			"server.listen must not be empty"},
		"no region": {doc(`upstream: {endpoint: "http://x", region: "", access_key_id: a, secret_access_key: b}`,
			clientsOK, keysOK), "upstream.region is required"},
		"a client without an access key": {doc(upstreamOK,
			`clients: [{name: c, secret_access_key: s, buckets: ["*"]}]`, keysOK), `client "c" has no access_key_id`},
		"a client without a secret": {doc(upstreamOK,
			`clients: [{name: c, access_key_id: k, buckets: ["*"]}]`, keysOK), `client "c" has no secret_access_key`},
		"an unknown key provider": {doc(upstreamOK, clientsOK, `keys: {provider: hsm, keyring: k}`),
			`keys.provider "hsm" is not one of`},
		"vault without a token": {doc(upstreamOK, clientsOK,
			`keys: {provider: vault, keyring: k, vault: {address: "http://v", key_name: n}}`), "keys.vault.token is required"},
		"vault without a key name": {doc(upstreamOK, clientsOK,
			`keys: {provider: vault, keyring: k, vault: {address: "http://v", token: t}}`), "keys.vault.key_name is required"},
		"kms without a region": {doc(upstreamOK, clientsOK,
			`keys: {provider: awskms, keyring: k, awskms: {key_id: i, access_key_id: a, secret_access_key: s}}`),
			"keys.awskms.region is required"},
		"kms without a key id": {doc(upstreamOK, clientsOK,
			`keys: {provider: awskms, keyring: k, awskms: {region: r, access_key_id: a, secret_access_key: s}}`),
			"keys.awskms.key_id is required"},
		"kms without credentials": {doc(upstreamOK, clientsOK,
			`keys: {provider: awskms, keyring: k, awskms: {region: r, key_id: i}}`), "keys.awskms credentials are required"},
		"upstream without keys or a source": {doc(`upstream: {endpoint: "http://x", region: r}`,
			clientsOK, keysOK), "upstream credentials are required"},
		"upstream with keys and a source": {doc(`upstream: {endpoint: "http://x", region: r, `+
			`access_key_id: a, secret_access_key: b, credential_source: env}`, clientsOK, keysOK),
			"set one or the other"},
		"upstream with an unknown source": {doc(`upstream: {endpoint: "http://x", region: r, `+
			`credential_source: sso}`, clientsOK, keysOK), `upstream.credential_source "sso" is not one of`},
		"kms with keys and a source": {doc(upstreamOK, clientsOK,
			`keys: {provider: awskms, keyring: k, awskms: {region: r, key_id: i, session_token: t, `+
				`credential_source: web_identity}}`), "keys.awskms has keys"},
		"a presign window that does not parse": {doc(`server: {presign: {max_expiry: "a week"}}`,
			upstreamOK, clientsOK, keysOK), "max_expiry"},
		"a negative presign window": {doc(`server: {presign: {max_expiry: "-1h"}}`,
			upstreamOK, clientsOK, keysOK), "must not be negative"},
		"a presign window past S3's maximum": {doc(`server: {presign: {max_expiry: "169h"}}`,
			upstreamOK, clientsOK, keysOK), "S3's own maximum"},
		"a negative freshness sync interval": {doc(upstreamOK, clientsOK, keysOK,
			`freshness: {index: /tmp/f.idx, sync_every: -1}`), "freshness.sync_every must not be negative"},
		"a tombstone retention that does not parse": {doc(upstreamOK, clientsOK, keysOK,
			`freshness: {index: /tmp/f.idx, tombstone_retention: "forever"}`), "tombstone_retention"},
		"a negative tombstone retention": {doc(upstreamOK, clientsOK, keysOK,
			`freshness: {index: /tmp/f.idx, tombstone_retention: "-1h"}`), "tombstone_retention must not be negative"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// Empty means the freshness package's own default, which it applies; a
	// value is parsed as given.
	for body, want := range map[string]time.Duration{
		`freshness: {index: /tmp/f.idx}`:                              0,
		`freshness: {index: /tmp/f.idx, tombstone_retention: "720h"}`: 720 * time.Hour,
	} {
		cfg, err := Load(write(t, doc(upstreamOK, clientsOK, keysOK, body)))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if d, err := cfg.Freshness.Retention(); err != nil || d != want {
			t.Errorf("%s: retention = %v, %v; want %v", body, d, err, want)
		}
	}
}
