package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// clearAWSEnvironment empties every variable a credential source reads, so
// that a test sees only what it sets -- a developer's AWS_PROFILE, or CI's
// session keys, would otherwise decide the outcome.
func clearAWSEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY",
		"AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
		"AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_ENDPOINT_URL_STS",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("HOME", t.TempDir())
}

// TestUpstreamCredentialsFromTheEnvironment: a configuration that names a
// credential source instead of keys reaches the provider with what the source
// resolves -- here the environment, against the real provider under test.
func TestUpstreamCredentialsFromTheEnvironment(t *testing.T) {
	p := testprovider.Require(t)
	clearAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", p.AccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", p.SecretKey)
	t.Setenv("AWS_SESSION_TOKEN", p.SessionToken)
	cfg := keysConfigFile(t, "  provider: file")
	body := mustRead(t, cfg)
	cfgWithUpstream := strings.Replace(string(body),
		`upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }`,
		fmt.Sprintf(`upstream: { endpoint: %q, region: %q, path_style: %t, credential_source: env }`,
			p.Endpoint, p.Region, p.PathStyle), 1)
	if err := os.WriteFile(cfg, []byte(cfgWithUpstream), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "probe", "--config", cfg, "--json", "s3://"+p.Bucket)
	if err != nil && !errors.Is(err, errUnguarded) {
		t.Fatalf("probe through credential_source env: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, `"guarded"`) {
		t.Errorf("the probe measured nothing:\n%s", stdout)
	}

	// The same configuration with the environment emptied cannot start.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	if _, _, err := runCLI(t, "probe", "--config", cfg, "s3://"+p.Bucket); err == nil ||
		!strings.Contains(err.Error(), "the environment") {
		t.Errorf("got %v, want the empty environment named", err)
	}
}

// TestUpstreamCredentialsFromWebIdentity takes the whole web identity path
// to a real provider: a token file, an AssumeRoleWithWebIdentity answered by a
// stub of STS with the provider's own keys, and the probe signing with what
// came back. The AWS workflow does the same against real STS.
func TestUpstreamCredentialsFromWebIdentity(t *testing.T) {
	p := testprovider.Require(t)
	clearAWSEnvironment(t)
	var assumed atomic.Int64
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("Action") != "AssumeRoleWithWebIdentity" || r.FormValue("WebIdentityToken") != "a.b.c" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assumed.Add(1)
		_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>`+
			`<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey>`+
			`<SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials>`+
			`</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			p.AccessKey, p.SecretKey, p.SessionToken,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(sts.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("a.b.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/gateway")
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)

	cfg := keysConfigFile(t, "  provider: file")
	body := strings.Replace(string(mustRead(t, cfg)),
		`upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }`,
		fmt.Sprintf(`upstream: { endpoint: %q, region: %q, path_style: %t, credential_source: web_identity }`,
			p.Endpoint, p.Region, p.PathStyle), 1)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runCLI(t, "probe", "--config", cfg, "--json", "s3://"+p.Bucket)
	if err != nil && !errors.Is(err, errUnguarded) {
		t.Fatalf("probe through web identity: %v\n%s", err, stdout)
	}
	if assumed.Load() != 1 {
		t.Errorf("STS was asked %d times for one run", assumed.Load())
	}
}

// TestKMSCredentialsFromTheEnvironment seals a keyring through the KMS
// emulator with credentials the environment supplies, then opens it the same
// way. The emulator does not check them; what this establishes is that the
// source reaches the KMS client at all.
func TestKMSCredentialsFromTheEnvironment(t *testing.T) {
	endpoint := os.Getenv("BLINDBUCKET_TEST_KMS_ENDPOINT")
	if endpoint == "" {
		t.Skip("set BLINDBUCKET_TEST_KMS_ENDPOINT (docker compose --profile keys up -d)")
	}
	clearAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	cfg := keysConfigFile(t, fmt.Sprintf(`  provider: awskms
  awskms: { region: us-east-1, key_id: %q, endpoint: %q, credential_source: env }`,
		emulatorKey(t, endpoint), endpoint))
	keyring := filepath.Join(t.TempDir(), "keyring.json")

	if _, stderr, err := runCLI(t, "keygen", "--config", cfg, "--out", keyring, "--kid", "env"); err != nil {
		t.Fatalf("keygen: %v\n%s", err, stderr)
	}
	if _, _, err := runCLI(t, "keys", "list", "--config", cfg, "--keyring", keyring); err != nil {
		t.Errorf("opening it again: %v", err)
	}
}

// TestServeStopsOnAFailingCredentialSource: a source that does not answer --
// here a role STS will not let the token assume -- stops the start with the
// reason, rather than failing every request after it.
func TestServeStopsOnAFailingCredentialSource(t *testing.T) {
	clearAWSEnvironment(t)
	provider, _ := stubProvider(t)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code>`+
			`<Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error></ErrorResponse>`)
	}))
	t.Cleanup(sts.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("a.b.c"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", token)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/gateway")
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)

	keyring := setupKeyring(t, "2026-10")
	cfg := fmt.Sprintf(`
server: { listen: %q }
admin: { listen: "" }
upstream: { endpoint: %q, region: us-east-1, path_style: true, credential_source: web_identity }
keys: { provider: file, keyring: %q }
clients:
  - { name: t, access_key_id: T, secret_access_key: s, buckets: ["*"] }
`, freeAddr(t), provider.URL, keyring)
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "serve", "--config", path)
	if err == nil {
		t.Fatal("serve started with credentials STS refused")
	}
	for _, want := range []string{"upstream credentials", "web identity", "AccessDenied"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}
