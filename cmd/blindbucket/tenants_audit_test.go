package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

// auditTenantsKeyring is a keyring with acme, under the deployment's lock and
// not yet active, owning acme-*, and globex destroyed, owning globex-*.
func auditTenantsKeyring(t *testing.T) string {
	t.Helper()
	path := setupKeyring(t, "2026-09")
	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--deployment-lock",
		"--kid", "acme-1", "acme", "acme-*"); err != nil {
		t.Fatal(err)
	}
	f := openWhole(t, path)
	f.Tombstones = []keys.Tombstone{{Name: "globex", Buckets: []string{"globex-*"}, KIDs: []string{"globex-1"},
		Locks: []keys.Lock{{Source: keys.LockDeployment}}, Destroyed: time.Now().UTC()}}
	data, err := f.Marshal([]byte(testPassphrase), keys.DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// rejectedRequests sends one request per bucket and key under a credential
// the gateway does not know. Each is refused and recorded, names included.
func rejectedRequests(t *testing.T, addr string, paths ...string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	for _, p := range paths {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/"+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIANOTOURS/"+now.Format("20060102")+
			"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+
			strings.Repeat("0", 64))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

// serveAuditTenants serves keyring with an audit log and tenantsYAML under
// keys, sends the requests, and returns the log's path once the gateway has
// stopped.
func serveAuditTenants(t *testing.T, keyring, tenantsYAML string, paths ...string) string {
	t.Helper()
	provider, _ := stubProvider(t)
	s3Addr, adminAddr := freeAddr(t), freeAddr(t)
	auditLog := filepath.Join(t.TempDir(), "audit.log")
	stop := startServe(t, fmt.Sprintf(`
server: { listen: %q }
admin: { listen: %q }
upstream: { endpoint: %q, region: us-east-1, path_style: true, access_key_id: a, secret_access_key: b }
keys:
  provider: file
  keyring: %q
%s
audit: { log: %q }
clients: [{ name: tester, access_key_id: TESTCLIENT, secret_access_key: s, buckets: ["*"] }]
`, s3Addr, adminAddr, provider.URL, keyring, tenantsYAML, auditLog))
	_ = waitFor(t, &http.Client{Timeout: time.Second}, "http://"+adminAddr+"/healthz", http.StatusOK).Body.Close()
	rejectedRequests(t, s3Addr, paths...)
	if err := stop(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	return auditLog
}

// The gateway's audit log encrypts the names of entries about a tenant's
// buckets under the tenant's key, from before it is active, and records those
// about a destroyed tenant's buckets as digests.
func TestServeAuditNamesPerTenant(t *testing.T) {
	keyring := auditTenantsKeyring(t)
	auditLog := serveAuditTenants(t, keyring, "",
		"other/notes.txt", "acme-data/q3/report.pdf", "globex-data/plan.txt")

	f := openWhole(t, keyring)
	ak, _ := f.Default.AuditKey()
	pub, err := ak.Public()
	if err != nil {
		t.Fatal(err)
	}
	coder := func(key []byte, err error) *names.Encrypter {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		enc, err := names.New(key)
		if err != nil {
			t.Fatal(err)
		}
		return enc
	}
	deployment := coder(ak.NameKey())
	nk, _ := f.Tenant("acme").Ring.NameKey()
	acme := coder(nk.AuditNameKey())

	data, err := os.ReadFile(auditLog) //nolint:gosec // a test's own file.
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*audit.Entry{}
	if _, err := audit.Verify(bytes.NewReader(data), audit.VerifyOptions{PublicKey: pub, OnEntry: func(e *audit.Entry) error {
		if b, err := deployment.DecryptKey(e.Bucket); err == nil {
			got["deployment:"+b] = e
		} else if b, err := acme.DecryptKey(e.Bucket); err == nil {
			got["acme:"+b] = e
		} else {
			got["opaque:"+e.Bucket] = e
		}
		return nil
	}}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if e := got["deployment:other"]; e == nil {
		t.Errorf("the default tenant's entry is not under the deployment's key: %v", keysOf(got))
	}
	if e := got["acme:acme-data"]; e == nil {
		t.Errorf("acme's entry is not under acme's key: %v", keysOf(got))
	} else if k, err := acme.DecryptKey(e.Key); err != nil || k != "q3/report.pdf" {
		t.Errorf("acme's object name: %q, %v", k, err)
	}
	var digests int
	for k, e := range got {
		if strings.HasPrefix(k, "opaque:h:") && strings.HasPrefix(e.Key, "h:") {
			digests++
		}
	}
	if digests != 1 || len(got) != 3 {
		t.Errorf("want one entry of digests, for globex, among three: %v", keysOf(got))
	}
}

func keysOf(m map[string]*audit.Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// audit verify --print reads every name a key it holds opens: the
// deployment's, and each tenant's that opens with --config. A tenant that
// does not open is named, and a destroyed one's names stay opaque.
func TestAuditVerifyWithTenants(t *testing.T) {
	keyring := auditTenantsKeyring(t)
	addPassphraseTenant(t, keyring, "zed", "zed-1", "zed's passphrase", "zed-*")
	phrase := writePassphraseFile(t, "zed's passphrase")
	auditLog := serveAuditTenants(t, keyring,
		fmt.Sprintf("  tenants:\n    zed: { provider: file, passphrase_file: %q }", phrase),
		"other/notes.txt", "acme-data/q3/report.pdf", "globex-data/plan.txt", "zed-data/ledger.csv")

	stdout, stderr, err := runCLI(t, "audit", "verify", "--keyring", keyring, "--print", auditLog)
	if err != nil {
		t.Fatalf("audit verify: %v\n%s", err, stderr)
	}
	for _, want := range []string{"chain and signatures verified", "other/notes.txt", "acme-data/q3/report.pdf"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("audit verify --print lacks %q:\n%s", want, stdout)
		}
	}
	for _, never := range []string{"globex-data", "plan.txt", "zed-data", "ledger"} {
		if strings.Contains(stdout, never) {
			t.Errorf("audit verify --print shows %q without its tenant's key:\n%s", never, stdout)
		}
	}
	if !strings.Contains(stderr, "tenant zed did not open") {
		t.Errorf("audit verify does not say zed did not open:\n%s", stderr)
	}

	// With zed's lock in the configuration, zed's names open too.
	conf := tenantPassphraseConfig(t, "zed", phrase)
	stdout, _, err = runCLI(t, "audit", "verify", "--keyring", keyring, "--config", conf, "--print", auditLog)
	if err != nil {
		t.Fatalf("audit verify --config: %v", err)
	}
	if !strings.Contains(stdout, "zed-data/ledger.csv") || strings.Contains(stdout, "globex-data") {
		t.Errorf("audit verify --config --print:\n%s", stdout)
	}
}

// audit pubkey reads and derives the deployment's key from a keyring with
// tenants alike.
func TestAuditPubkeyWithTenants(t *testing.T) {
	keyring := auditTenantsKeyring(t)
	recorded, _, err := runCLI(t, "audit", "pubkey", "--keyring", keyring)
	if err != nil {
		t.Fatal(err)
	}
	derived, _, err := runCLI(t, "audit", "pubkey", "--keyring", keyring, "--open")
	if err != nil {
		t.Fatalf("audit pubkey --open: %v", err)
	}
	if recorded == "" || recorded != derived {
		t.Errorf("recorded %q, derived %q", recorded, derived)
	}
}
