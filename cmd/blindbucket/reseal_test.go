package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePassphraseFile stores a passphrase where --new-passphrase-file or
// --passphrase-file can read it.
func writePassphraseFile(t *testing.T, phrase string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte(phrase+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// keysConfigFile writes a configuration whose only meaningful part is the keys
// section; the rest is what config.Load insists on.
func keysConfigFile(t *testing.T, keysYAML string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	body := fmt.Sprintf(`
upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }
clients: [{ name: c, access_key_id: k, secret_access_key: s, buckets: ["*"] }]
keys:
  keyring: unused.json
%s
`, keysYAML)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return data
}

// TestResealChangesThePassphrase is the smallest reseal: a passphrase to
// another passphrase. The keyring opens with the new one and not the old, and
// a file encrypted before the reseal decrypts after it -- the keys inside did
// not change, which is the whole claim.
func TestResealChangesThePassphrase(t *testing.T) {
	keyring := setupKeyring(t, "2026-10")
	plain := []byte("written before the reseal")
	cipher := encryptFile(t, keyring, plain)
	newPhrase := writePassphraseFile(t, "a new passphrase, not the test one")

	_, stderr, err := runCLI(t, "reseal", "--keyring", keyring, "--new-passphrase-file", newPhrase)
	if err != nil {
		t.Fatalf("reseal: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "from a passphrase to a passphrase") ||
		!strings.Contains(stderr, "still opens with a passphrase") {
		t.Errorf("the summary does not say what happened and what it leaves:\n%s", stderr)
	}

	if _, _, err := runCLI(t, "keys", "list", "--keyring", keyring); err == nil {
		t.Error("the keyring still opens with the old passphrase")
	}
	t.Setenv(passphraseEnv, "a new passphrase, not the test one")
	got, err := decryptFile(t, keyring, cipher)
	if err != nil {
		t.Fatalf("decrypting what was encrypted before the reseal: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("the plaintext changed across the reseal")
	}
	info, err := os.Stat(keyring)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the resealed keyring is mode %04o", mode)
	}
	assertNoTemporaries(t, keyring)
}

func TestResealRefusesTheSamePassphrase(t *testing.T) {
	keyring := setupKeyring(t, "2026-10")
	before := mustRead(t, keyring)
	same := writePassphraseFile(t, testPassphrase)

	_, _, err := runCLI(t, "reseal", "--keyring", keyring, "--new-passphrase-file", same)
	if !errors.Is(err, errSamePassphrase) {
		t.Fatalf("got %v, want errSamePassphrase", err)
	}
	if !bytes.Equal(mustRead(t, keyring), before) {
		t.Error("the keyring was rewritten")
	}
}

func TestResealDryRunWritesNothing(t *testing.T) {
	keyring := setupKeyring(t, "2026-10")
	before := mustRead(t, keyring)
	newPhrase := writePassphraseFile(t, "another passphrase")

	_, stderr, err := runCLI(t, "reseal", "--keyring", keyring, "--new-passphrase-file", newPhrase, "--dry-run")
	if err != nil {
		t.Fatalf("reseal --dry-run: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "would reseal") || !strings.Contains(stderr, "nothing written") {
		t.Errorf("the dry run does not say what it did:\n%s", stderr)
	}
	if !bytes.Equal(mustRead(t, keyring), before) {
		t.Error("the dry run rewrote the keyring")
	}
	assertNoTemporaries(t, keyring)
}

// encryptOnlyVault answers Transit's encrypt and refuses its decrypt, as Vault
// does for a token whose policy grants only transit/encrypt -- or as KMS does
// for a principal with kms:Encrypt and no kms:Decrypt. Sealing under it works;
// nothing sealed under it can be opened.
func encryptOnlyVault(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/transit/encrypt/blindbucket"):
			var in struct {
				Plaintext string `json:"plaintext"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			_, _ = fmt.Fprintf(w, `{"data":{"ciphertext":"vault:v1:%s"}}`, in.Plaintext)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestResealRefusesATargetThatCannotUnseal is the failure reseal exists to
// survive. Replacing the file with what such a target sealed would leave a
// keyring nobody can open -- every object locked away -- so the reseal opens
// its own result before anything is written, and refuses.
func TestResealRefusesATargetThatCannotUnseal(t *testing.T) {
	keyring := setupKeyring(t, "2026-10")
	before := mustRead(t, keyring)
	vault := encryptOnlyVault(t)
	target := keysConfigFile(t, fmt.Sprintf(`  provider: vault
  vault: { address: %q, token: encrypt-only, key_name: blindbucket }`, vault.URL))

	for _, dry := range []bool{true, false} {
		args := []string{"reseal", "--keyring", keyring, "--to-config", target}
		if dry {
			args = append(args, "--dry-run")
		}
		_, _, err := runCLI(t, args...)
		if err == nil {
			t.Fatalf("dry run %t: a target that cannot unseal was accepted", dry)
		}
		for _, want := range []string{"cannot open it again", "permission denied", "nothing was written"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("dry run %t: the refusal does not say %q: %v", dry, want, err)
			}
		}
		if !bytes.Equal(mustRead(t, keyring), before) {
			t.Fatalf("dry run %t: the keyring was rewritten", dry)
		}
		assertNoTemporaries(t, keyring)
	}
}

// TestResealOpensWithTheCurrentSourceOnly: --config names what seals the
// keyring now, and a mismatch is the error every other command gives, before
// anything is sealed.
func TestResealOpensWithTheCurrentSourceOnly(t *testing.T) {
	keyring := setupKeyring(t, "2026-10")
	before := mustRead(t, keyring)
	vault := encryptOnlyVault(t)
	wrong := keysConfigFile(t, fmt.Sprintf(`  provider: vault
  vault: { address: %q, token: t, key_name: blindbucket }`, vault.URL))

	_, _, err := runCLI(t, "reseal", "--keyring", keyring, "--config", wrong)
	if err == nil || !strings.Contains(err.Error(), "sealed with a passphrase") {
		t.Fatalf("got %v, want the mismatch named", err)
	}
	if !bytes.Equal(mustRead(t, keyring), before) {
		t.Error("the keyring was rewritten")
	}
}

func TestResealCommandLineMistakes(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no keyring":       {[]string{"reseal"}, "--keyring is required"},
		"an argument":      {[]string{"reseal", "--keyring", "k.json", "extra"}, ""},
		"a missing config": {[]string{"reseal", "--keyring", "k.json", "--to-config", "/nonexistent.yaml"}, "no such file"},
		"a missing file":   {[]string{"reseal", "--keyring", "/nonexistent/keyring.json"}, "no such file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runCLI(t, tc.args...)
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want == "" {
				if !errors.Is(err, errUsage) {
					t.Errorf("got %v, want the usage error", err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestResealAcrossEverySource walks one keyring through every source and back:
// passphrase, Vault, KMS, a new passphrase. At each stop it opens with the new
// source and not with the one before, and at the end a file encrypted at the
// start decrypts -- four reseals and the keys never changed.
//
// Against Vault in dev mode and the KMS emulator, as the other service tests
// run: docker compose --profile keys up -d.
func TestResealAcrossEverySource(t *testing.T) {
	vault, kms := serviceConfig(t, "vault"), serviceConfig(t, "awskms")
	keyring := setupKeyring(t, "2026-10")
	plain := []byte("written before four reseals")
	cipher := encryptFile(t, keyring, plain)
	final := writePassphraseFile(t, "the passphrase it ends under")

	for _, step := range []struct {
		from, to []string
		opens    []string
		refused  []string
		says     string
	}{
		{nil, []string{"--to-config", vault}, []string{"--config", vault}, []string{},
			"from a passphrase to Vault Transit key blindbucket"},
		{[]string{"--config", vault}, []string{"--to-config", kms}, []string{"--config", kms},
			[]string{"--config", vault}, "from Vault Transit key blindbucket to AWS KMS key"},
		{[]string{"--config", kms}, []string{"--new-passphrase-file", final},
			[]string{"--passphrase-file", final}, []string{"--config", kms},
			"to a passphrase"},
	} {
		args := append(append([]string{"reseal", "--keyring", keyring}, step.from...), step.to...)
		_, stderr, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", step.to, err, stderr)
		}
		if !strings.Contains(stderr, step.says) {
			t.Errorf("%v: the summary does not say %q:\n%s", step.to, step.says, stderr)
		}
		if _, _, err := runCLI(t, append([]string{"keys", "list", "--keyring", keyring}, step.opens...)...); err != nil {
			t.Errorf("after resealing %v, the new source does not open it: %v", step.to, err)
		}
		if step.refused != nil {
			if _, _, err := runCLI(t, append([]string{"keys", "list", "--keyring", keyring}, step.refused...)...); err == nil {
				t.Errorf("after resealing %v, the previous source still opens it", step.to)
			}
		}
	}

	if _, err := decryptFile(t, keyring, cipher); err == nil {
		t.Fatal("the test passphrase still opens the keyring at the end")
	}
	t.Setenv(passphraseEnv, "the passphrase it ends under")
	got, err := decryptFile(t, keyring, cipher)
	if err != nil {
		t.Fatalf("decrypting what was encrypted before the reseals: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("the plaintext changed across the reseals")
	}
}

// TestResealRefusesAnEncryptOnlyVaultToken is the stub's case against the real
// thing: a Vault token whose policy grants transit/encrypt and nothing else.
// Vault seals the root key for it and will not unseal it, and the keyring is
// left as it was.
func TestResealRefusesAnEncryptOnlyVaultToken(t *testing.T) {
	serviceConfig(t, "vault") // skips without Vault
	addr, root := os.Getenv("BLINDBUCKET_TEST_VAULT_ADDR"), os.Getenv("BLINDBUCKET_TEST_VAULT_TOKEN")
	vaultCall := func(method, path string, body any) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(t.Context(), method, addr+"/v1/"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", root)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode/100 != 2 {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	policy := "reseal-encrypt-only"
	vaultCall(http.MethodPut, "sys/policies/acl/"+policy, map[string]string{
		"policy": `path "transit/encrypt/blindbucket" { capabilities = ["update"] }`,
	})
	created := vaultCall(http.MethodPost, "auth/token/create", map[string]any{
		"policies": []string{policy}, "ttl": "10m",
	})
	auth, _ := created["auth"].(map[string]any)
	token, _ := auth["client_token"].(string)
	if token == "" {
		t.Fatalf("Vault created no token: %v", created)
	}

	keyring := setupKeyring(t, "2026-10")
	before := mustRead(t, keyring)
	target := keysConfigFile(t, fmt.Sprintf(`  provider: vault
  vault: { address: %q, token: %q, key_name: blindbucket }`, addr, token))

	_, _, err := runCLI(t, "reseal", "--keyring", keyring, "--to-config", target)
	if err == nil || !strings.Contains(err.Error(), "cannot open it again") {
		t.Fatalf("got %v, want the reseal refused", err)
	}
	if !bytes.Equal(mustRead(t, keyring), before) {
		t.Error("the keyring was rewritten")
	}
}
