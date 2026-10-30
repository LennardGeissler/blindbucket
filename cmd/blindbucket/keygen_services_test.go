package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serviceSettings returns a provider's settings as one YAML line, its own key
// first, skipping when the service is not running.
func serviceSettings(t *testing.T, provider string) string {
	t.Helper()
	switch provider {
	case "vault":
		addr, token := os.Getenv("BLINDBUCKET_TEST_VAULT_ADDR"), os.Getenv("BLINDBUCKET_TEST_VAULT_TOKEN")
		if addr == "" || token == "" {
			t.Skip("set BLINDBUCKET_TEST_VAULT_ADDR and _TOKEN (docker compose --profile keys up -d)")
		}
		return fmt.Sprintf(`vault: { address: %q, token: %q, key_name: blindbucket }`, addr, token)
	case "awskms":
		endpoint := os.Getenv("BLINDBUCKET_TEST_KMS_ENDPOINT")
		if endpoint == "" {
			t.Skip("set BLINDBUCKET_TEST_KMS_ENDPOINT (docker compose --profile keys up -d)")
		}
		return fmt.Sprintf(`awskms: { region: us-east-1, key_id: %q, access_key_id: test, secret_access_key: test, endpoint: %q }`,
			emulatorKey(t, endpoint), endpoint)
	}
	t.Fatalf("no settings for provider %q", provider)
	return ""
}

// serviceConfig writes a configuration whose keys section names a root-key
// service, skipping when the service is not running.
func serviceConfig(t *testing.T, provider string) string {
	t.Helper()
	keysYAML := "\n  " + serviceSettings(t, provider)
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	body := fmt.Sprintf(`
upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }
clients: [{ name: c, access_key_id: k, secret_access_key: s, buckets: ["*"] }]
keys:
  provider: %s
  keyring: unused.json%s
`, provider, keysYAML)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// emulatorKey creates a key in the KMS emulator, which answers without
// authentication; real AWS is exercised by the AWS workflow instead.
func emulatorKey(t *testing.T, endpoint string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-Amz-Target", "TrentService.CreateKey")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var created struct {
		KeyMetadata struct {
			KeyID string `json:"KeyId"`
		} `json:"KeyMetadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil || created.KeyMetadata.KeyID == "" {
		t.Fatalf("CreateKey returned no key: %v", err)
	}
	return created.KeyMetadata.KeyID
}

// TestKeygenSealedByAService runs the key commands against a keyring whose root
// key a service holds, end to end through the CLI: no passphrase anywhere, and
// every command that opens the keyring asking the service instead.
func TestKeygenSealedByAService(t *testing.T) {
	for provider, sealedBy := range map[string]string{
		"vault":  "Vault Transit key blindbucket",
		"awskms": "AWS KMS key",
	} {
		t.Run(provider, func(t *testing.T) {
			cfg := serviceConfig(t, provider)
			// No passphrase is available, so anything that fell back to one fails.
			t.Setenv(passphraseEnv, "")
			keyring := filepath.Join(t.TempDir(), "keyring.json")

			_, stderr, err := runCLI(t, "keygen", "--out", keyring, "--kid", "2026-09", "--config", cfg)
			if err != nil {
				t.Fatalf("keygen: %v\n%s", err, stderr)
			}
			if !strings.Contains(stderr, "sealed by "+sealedBy) {
				t.Errorf("keygen does not say what sealed the keyring:\n%s", stderr)
			}

			if _, stderr, err := runCLI(t, "keygen", "--out", keyring, "--kid", "2026-10", "--add",
				"--config", cfg); err != nil {
				t.Fatalf("keygen --add: %v\n%s", err, stderr)
			}
			stdout, _, err := runCLI(t, "keys", "list", "--keyring", keyring, "--config", cfg, "--json")
			if err != nil {
				t.Fatalf("keys list: %v", err)
			}
			for _, kid := range []string{"2026-09", "2026-10"} {
				if !strings.Contains(stdout, kid) {
					t.Errorf("%s is not in the keyring:\n%s", kid, stdout)
				}
			}

			// An older keyring upgraded through the service, and the audit key
			// derived by opening it matches the one recorded in the file.
			stripKeys(t, keyring, "audit_key")
			if _, stderr, err := runCLI(t, "keygen", "--out", keyring, "--add-audit-key",
				"--config", cfg); err != nil {
				t.Fatalf("keygen --add-audit-key: %v\n%s", err, stderr)
			}
			recorded := auditPubkey(t, keyring)
			if derived := auditPubkey(t, keyring, "--open", "--config", cfg); derived != recorded {
				t.Errorf("derived audit key %s, recorded %s", derived, recorded)
			}

			// Without the configuration, the keyring names what it needs.
			if _, _, err := runCLI(t, "keys", "list", "--keyring", keyring); err == nil {
				t.Error("a service-sealed keyring opened without its service")
			}

			// The offline commands work against the same keyring (#46). Before
			// --config they could not: they opened the file with a passphrase
			// and had no flag to name the provider with, so an operator who
			// moved their root key to a service lost encrypt and decrypt.
			t.Run("encrypt and decrypt round trip", func(t *testing.T) {
				dir := t.TempDir()
				plain := filepath.Join(dir, "plain")
				sealed := filepath.Join(dir, "sealed.bb")
				opened := filepath.Join(dir, "opened")
				body := []byte("a service holds the root key, and these commands still work\n")
				if err := os.WriteFile(plain, body, 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}

				if _, stderr, err := runCLI(t, "encrypt", "--keyring", keyring, "--config", cfg,
					"-i", plain, "-o", sealed); err != nil {
					t.Fatalf("encrypt: %v\n%s", err, stderr)
				}
				if ciphertext, err := os.ReadFile(sealed); err != nil {
					t.Fatalf("read the ciphertext: %v", err)
				} else if bytes.Contains(ciphertext, body) {
					t.Error("the plaintext is in the output")
				}

				if _, stderr, err := runCLI(t, "decrypt", "--keyring", keyring, "--config", cfg,
					"-i", sealed, "-o", opened); err != nil {
					t.Fatalf("decrypt: %v\n%s", err, stderr)
				}
				got, err := os.ReadFile(opened)
				if err != nil {
					t.Fatalf("read what was decrypted: %v", err)
				}
				if !bytes.Equal(got, body) {
					t.Errorf("decrypted %q, want %q", got, body)
				}
			})

			// And without --config they say which flag is missing, rather than
			// asking for a passphrase that cannot work.
			t.Run("without --config the error names the flag", func(t *testing.T) {
				dir := t.TempDir()
				plain := filepath.Join(dir, "plain")
				if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				for _, command := range []string{"encrypt", "decrypt"} {
					_, _, err := runCLI(t, command, "--keyring", keyring,
						"-i", plain, "-o", filepath.Join(dir, command+".out"))
					if err == nil {
						t.Fatalf("%s opened a service-sealed keyring with no --config", command)
					}
					for _, want := range []string{"--config", "sealed by"} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("%s: the error does not mention %q: %v", command, want, err)
						}
					}
					// The complaint in #46 is that the operator was sent after a
					// passphrase. Saying "not a passphrase" is the point; telling
					// them to go and check one is the thing that must not happen.
					for _, unwanted := range []string{"check the passphrase", "--passphrase-file"} {
						if strings.Contains(err.Error(), unwanted) {
							t.Errorf("%s: the error still sends the operator after a passphrase (%q): %v",
								command, unwanted, err)
						}
					}
				}
			})
		})
	}
}
