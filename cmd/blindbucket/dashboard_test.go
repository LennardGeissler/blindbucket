package main

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/config"
)

// TestServeDashboard runs the gateway with the dashboard on (ADR-035) and reads
// the page the way an operator would through a tunnel: ready, the keyring's
// key, the audit log verified in the background -- and nothing secret on it,
// and nothing for a request under someone else's name or one that writes.
func TestServeDashboard(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	provider, _ := stubProvider(t)
	state := t.TempDir()
	dashAddr := freeAddr(t)

	startServe(t, fmt.Sprintf(`
server:
  listen: %q
admin:
  listen: ""
  dashboard:
    listen: %q
upstream:
  endpoint: %q
  region: us-east-1
  path_style: true
  access_key_id: upstream-id
  secret_access_key: upstream-secret-not-on-the-page
keys:
  provider: file
  keyring: %q
audit:
  log: %q
clients:
  - name: tester
    access_key_id: TESTCLIENT
    secret_access_key: client-secret-not-on-the-page
    buckets: ["readybucket"]
`, freeAddr(t), dashAddr, provider.URL, keyring, filepath.Join(state, "audit.log")))

	client := &http.Client{Timeout: 5 * time.Second}
	var page string
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(page, "Verifies") {
		if time.Now().After(deadline) {
			t.Fatalf("the page never showed the audit log verified:\n%s", page)
		}
		resp := waitFor(t, client, "http://"+dashAddr+"/", http.StatusOK)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		page = string(b)
		time.Sleep(50 * time.Millisecond)
	}
	for _, want := range []string{"Ready", "2026-09", "active", "a passphrase", "audit.log"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	for _, secret := range []string{"upstream-secret-not-on-the-page", "client-secret-not-on-the-page", "upstream-id", "TESTCLIENT"} {
		if strings.Contains(page, secret) {
			t.Errorf("the page shows %q", secret)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+dashAddr+"/", nil)
	req.Host = "attacker.example"
	if resp, err := client.Do(req); err != nil || resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("a request named attacker.example: %v %v, want 421", resp, err)
	} else {
		_ = resp.Body.Close()
	}
	if resp, err := client.Post("http://"+dashAddr+"/", "text/plain", strings.NewReader("x")); err != nil ||
		resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST: %v %v, want 405", resp, err)
	} else {
		_ = resp.Body.Close()
	}
}

// TestDashboardSealingNamesNoCredential: what the page says seals the keyring
// names the service and the key, never a token or an access key.
func TestDashboardSealingNamesNoCredential(t *testing.T) {
	for _, tc := range []struct {
		keys config.Keys
		want string
	}{
		{config.Keys{Provider: "file"}, "a passphrase"},
		{config.Keys{Provider: "vault", Vault: config.VaultKeys{
			Address: "https://vault:8200", Token: "hvs.secret", KeyName: "blindbucket",
		}}, "Vault or OpenBao Transit at https://vault:8200, key transit/blindbucket"},
		{config.Keys{Provider: "awskms", AWSKMS: config.AWSKMSKeys{
			KeyID: "arn:aws:kms:eu-central-1:1:key/k", Region: "eu-central-1",
			AccessKeyID: "AKIASECRET", SecretAccessKey: "kms-secret",
		}}, "AWS KMS, key arn:aws:kms:eu-central-1:1:key/k in eu-central-1"},
	} {
		got := sealing(tc.keys)
		if got != tc.want {
			t.Errorf("sealing(%s) = %q, want %q", tc.keys.Provider, got, tc.want)
		}
		for _, secret := range []string{"hvs.secret", "AKIASECRET", "kms-secret"} {
			if strings.Contains(got, secret) {
				t.Errorf("sealing(%s) names %q", tc.keys.Provider, secret)
			}
		}
	}
}
