package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// freeAddr returns a loopback address with a port nothing is listening on.
// Closing the probe listener leaves a window in which something else could
// take the port; on a test machine that is a risk worth taking to avoid
// teaching the command a way to report its address.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// selfSignedCert writes a certificate for 127.0.0.1 and returns the paths and
// a pool that trusts it.
func selfSignedCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// stubProvider answers the one call readiness makes, a bucket HEAD, and counts
// it; anything else is a 501 so that a test relying on more notices.
func stubProvider(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var heads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.Trim(r.URL.Path, "/") == "readybucket" {
			heads.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	t.Cleanup(srv.Close)
	return srv, &heads
}

// startServe runs `blindbucket serve` in the background and returns a function
// that stops it the way a signal would and reports how it ended.
func startServe(t *testing.T, configYAML string) (stop func() error) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "blindbucket.yaml")
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "--config", cfgPath}) }()
	var once atomic.Bool
	stop = func() error {
		if !once.CompareAndSwap(false, true) {
			return nil
		}
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			return errors.New("serve did not return after its context was cancelled")
		}
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// waitFor polls url until it answers with want, or fails the test.
func waitFor(t *testing.T, client *http.Client, url string, want int) *http.Response {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == want {
			return resp
		}
		if err == nil {
			_ = resp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not answer %d in time (last error: %v)", url, want, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServeLifecycle starts the gateway with every optional part switched on,
// checks what an operator relies on from outside, stops it the way a signal
// would, and then holds the audit log it wrote to the audit CLI.
func TestServeLifecycle(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	provider, heads := stubProvider(t)
	certFile, keyFile, pool := selfSignedCert(t)
	state := t.TempDir()
	s3Addr, adminAddr := freeAddr(t), freeAddr(t)
	auditLog := filepath.Join(state, "audit.log")

	stop := startServe(t, fmt.Sprintf(`
server:
  listen: %q
  tls: { cert_file: %q, key_file: %q }
admin:
  listen: %q
upstream:
  endpoint: %q
  region: us-east-1
  path_style: true
  access_key_id: upstream-id
  secret_access_key: upstream-secret
keys:
  provider: file
  keyring: %q
names:
  encrypt: true
audit:
  log: %q
freshness:
  index: %q
clients:
  - name: tester
    access_key_id: TESTCLIENT
    secret_access_key: test-client-secret
    buckets: ["readybucket"]
`, s3Addr, certFile, keyFile, adminAddr, provider.URL, keyring, auditLog,
		filepath.Join(state, "freshness.idx")))

	plain := &http.Client{Timeout: 5 * time.Second}
	_ = waitFor(t, plain, "http://"+adminAddr+"/healthz", http.StatusOK).Body.Close()

	// Readiness asks the provider, and the provider saw the question.
	_ = waitFor(t, plain, "http://"+adminAddr+"/readyz", http.StatusOK).Body.Close()
	if heads.Load() == 0 {
		t.Error("/readyz answered without asking the provider")
	}

	resp := waitFor(t, plain, "http://"+adminAddr+"/metrics", http.StatusOK)
	metrics, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, want := range []string{
		`blindbucket_build_info{`,
		`blindbucket_keyring_keys 1`,
		`blindbucket_integrity_failures_total{kind="chunk"} 0`,
	} {
		if !strings.Contains(string(metrics), want) {
			t.Errorf("/metrics lacks %s", want)
		}
	}

	// The S3 port speaks TLS with the configured certificate, and refuses a
	// credential it does not know.
	secure := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	req, err := http.NewRequest(http.MethodGet, "https://"+s3Addr+"/readybucket/secret.txt", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	now := time.Now().UTC()
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIANOTOURS/"+now.Format("20060102")+
		"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+
		strings.Repeat("0", 64))
	resp, err = secure.Do(req)
	if err != nil {
		t.Fatalf("a TLS request to the S3 port failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("an unknown credential got %d, want 403", resp.StatusCode)
	}

	// Plain HTTP on the TLS port is not answered as S3.
	if resp, err := plain.Get("http://" + s3Addr + "/readybucket/secret.txt"); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("the TLS listener served plain HTTP")
		}
	}

	if err := stop(); err != nil {
		t.Fatalf("serve returned %v on an orderly shutdown", err)
	}

	// Shutdown closes the audit log with a final checkpoint, so everything it
	// recorded is signed -- including the rejected request, under the key the
	// client presented, with the object name decrypted only by the keyring.
	out, err := auditVerify(t, "--keyring", keyring, "--print", auditLog)
	if err != nil {
		t.Fatalf("the audit log did not verify after shutdown: %v\n%s", err, out)
	}
	if !strings.Contains(out, "chain and signatures verified") {
		t.Errorf("the audit log is not fully signed after shutdown:\n%s", out)
	}
	if !strings.Contains(out, "AKIANOTOURS (rejected)") || !strings.Contains(out, "readybucket/secret.txt") {
		t.Errorf("the rejected request is not in the audit log:\n%s", out)
	}
}

// TestServeWarnsAboutWhatItCannotProtect covers the start-up warnings: each
// names a setting that gives up part of what the gateway is for.
func TestServeWarnsAboutWhatItCannotProtect(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	provider, _ := stubProvider(t)
	adminAddr := freeAddr(t)
	_, port, _ := net.SplitHostPort(freeAddr(t))

	var stopErr error
	logs := captureStderr(t, func() {
		stop := startServe(t, fmt.Sprintf(`
server:
  listen: "0.0.0.0:%s"
  presign: { enabled: true }
admin:
  listen: %q
upstream:
  endpoint: %q
  region: us-east-1
  path_style: true
  access_key_id: upstream-id
  secret_access_key: upstream-secret
keys:
  provider: file
  keyring: %q
audit:
  log: %q
  fail_closed: false
clients:
  - name: tester
    access_key_id: TESTCLIENT
    secret_access_key: test-client-secret
    buckets: ["*"]
`, port, adminAddr, provider.URL, keyring, filepath.Join(t.TempDir(), "audit.log")))
		_ = waitFor(t, &http.Client{Timeout: time.Second}, "http://"+adminAddr+"/healthz", http.StatusOK).Body.Close()
		stopErr = stop()
	})
	if stopErr != nil {
		t.Fatalf("serve: %v", stopErr)
	}
	for _, want := range []string{
		"plaintext beyond loopback without TLS",
		"set server.require_signed_payload",
		"presigned URLs may name a window of up to",
		"audit.fail_closed is off",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no warning containing %q in:\n%s", want, logs)
		}
	}
}

// TestServeStartupFailures pins, for each way serve can fail before it
// listens, both the symptom and the setting or command the error names: the
// operator should be able to fix it from the error line alone (#121), and a
// renamed setting should not leave a stale hint behind.
func TestServeStartupFailures(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	provider, _ := stubProvider(t)

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer busy.Close() //nolint:errcheck // test cleanup.

	// A path below a regular file: no directory can be created there, on any
	// platform, whatever the permissions.
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	notAKeyring := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(notAKeyring, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	noNameKey := setupKeyring(t, "2026-09")
	stripKeys(t, noNameKey, "name_key")

	base := func(listen, extra string) string {
		return fmt.Sprintf(`
server: { listen: %q }
admin: { listen: "" }
upstream:
  endpoint: %q
  region: us-east-1
  path_style: true
  access_key_id: upstream-id
  secret_access_key: upstream-secret
keys: { provider: file, keyring: %q }
clients:
  - { name: t, access_key_id: T, secret_access_key: s, buckets: ["*"] }
%s`, listen, provider.URL, keyring, extra)
	}
	ok := func(extra string) string { return base(freeAddr(t), extra) }
	swap := func(config, old, replacement string) string {
		if !strings.Contains(config, old) {
			t.Fatalf("the configuration holds no %q", old)
		}
		return strings.Replace(config, old, replacement, 1)
	}

	for name, tc := range map[string]struct {
		config string
		env    map[string]string
		want   []string
	}{
		"the S3 port is taken": {config: base(busy.Addr().String(), ""),
			want: []string{"server.listen", "address already in use", "another process"}},
		"the admin port is taken": {config: swap(ok(""), `admin: { listen: "" }`,
			fmt.Sprintf("admin: { listen: %q }", busy.Addr().String())),
			want: []string{"admin.listen", "address already in use"}},
		"the keyring is missing": {config: swap(ok(""), keyring, filepath.Join(t.TempDir(), "missing.json")),
			want: []string{"keys.keyring", "no such file", "blindbucket keygen --out"}},
		"the keyring is not a keyring": {config: swap(ok(""), keyring, notAKeyring),
			want: []string{"keys.keyring", "not a keyring"}},
		"the passphrase is wrong": {config: ok(""), env: map[string]string{passphraseEnv: "not it"},
			want: []string{"wrong passphrase", "$" + passphraseEnv, "keys.passphrase_file"}},
		"the passphrase file is missing": {config: swap(ok(""), "provider: file,",
			`provider: file, passphrase_file: "/nonexistent/passphrase",`),
			want: []string{"keys.passphrase_file", "/nonexistent/passphrase"}},
		"names need a key the keyring lacks": {config: swap(ok("names: { encrypt: true }"), keyring, noNameKey),
			want: []string{"names.encrypt", "--add-name-key"}},
		"the audit log cannot be created": {config: ok(fmt.Sprintf("audit: { log: %q }",
			filepath.Join(notADir, "audit.log"))), want: []string{"audit.log", "not a directory"}},
		"the freshness index cannot be created": {config: ok(fmt.Sprintf("freshness: { index: %q }",
			filepath.Join(notADir, "fresh.idx"))), want: []string{"freshness.index", "not a directory"}},
		"the TLS certificate is missing": {config: swap(ok(""), "server: { listen: ",
			`server: { tls: { cert_file: /nonexistent/tls.crt, key_file: /nonexistent/tls.key }, listen: `),
			want: []string{"server.tls", "cert_file and key_file"}},
		"the endpoint has no scheme": {config: swap(ok(""), provider.URL, strings.TrimPrefix(provider.URL, "http://")),
			want: []string{"upstream.endpoint", "http://"}},
		"a referenced variable is not set": {config: swap(ok(""), "secret_access_key: upstream-secret",
			"secret_access_key: ${BLINDBUCKET_TEST_NOT_SET}"), env: map[string]string{"BLINDBUCKET_TEST_NOT_SET": ""},
			want: []string{"upstream.secret_access_key", "$BLINDBUCKET_TEST_NOT_SET", "blindbucket.env"}},
		"a setting is misspelt": {config: ok("lisen: 1"),
			want: []string{"lisen", "blindbucket.example.yaml"}},
		"the credential source gives nothing": {config: swap(ok(""),
			"access_key_id: upstream-id\n  secret_access_key: upstream-secret", "credential_source: web_identity"),
			env:  map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_ROLE_ARN": ""},
			want: []string{"upstream.credential_source", "web_identity"}},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
				if v == "" {
					_ = os.Unsetenv(k)
				}
			}
			cfgPath := filepath.Join(t.TempDir(), "blindbucket.yaml")
			if err := os.WriteFile(cfgPath, []byte(tc.config), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			// A case that starts by mistake must not hang the run.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			var err error
			captureStderr(t, func() { err = run(ctx, []string{"serve", "--config", cfgPath}) })
			if err == nil {
				t.Fatal("serve started")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error does not name %q:\n%v", want, err)
				}
			}
		})
	}

	t.Run("no configuration file", func(t *testing.T) {
		err := run(t.Context(), []string{"serve", "--config", filepath.Join(t.TempDir(), "absent.yaml")})
		if err == nil || !strings.Contains(err.Error(), "blindbucket init") {
			t.Errorf("got %v, want a pointer to blindbucket init", err)
		}
	})
}
