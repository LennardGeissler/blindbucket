package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// A keyring and the configuration that opens it have to agree. Neither
// mismatch can be recovered from by guessing, and both are things an operator
// does: pointing a Vault-configured gateway at an old passphrase keyring, or
// the reverse after moving a file between environments.
func TestOpenKeyringRefusesAMismatchedSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	ring := keys.NewKeyring()
	if err := ring.Generate("test-key"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("a passphrase keyring with a service provider", func(t *testing.T) {
		path := filepath.Join(dir, "passphrase.json")
		data, err := ring.Marshal([]byte("a passphrase"), keys.DefaultKDFParams)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg := config.Keys{Provider: "vault", Vault: config.VaultKeys{
			Address: "http://127.0.0.1:1", Token: "t", KeyName: "k",
		}}
		_, err = openKeyring(context.Background(), path, cfg, &passphraseFlags{})
		if err == nil {
			t.Fatal("a Vault-configured gateway opened a passphrase keyring")
		}
		if !strings.Contains(err.Error(), "passphrase") || !strings.Contains(err.Error(), "vault") {
			t.Errorf("the error does not say what disagrees: %v", err)
		}
	})

	t.Run("a service keyring with no provider", func(t *testing.T) {
		path := filepath.Join(dir, "vault.json")
		root, err := keys.NewRootKey()
		if err != nil {
			t.Fatalf("NewRootKey: %v", err)
		}
		data, err := ring.MarshalWithRootKey(root, keys.RootKeyRef{
			Source: keys.SourceVaultTransit, Ciphertext: "vault:v1:x", KeyName: "k",
		})
		if err != nil {
			t.Fatalf("MarshalWithRootKey: %v", err)
		}
		clear(root)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg := config.Keys{Provider: "file"}
		_, err = openKeyring(context.Background(), path, cfg, &passphraseFlags{})
		if err == nil {
			t.Fatal("a passphrase-configured gateway opened a Vault keyring")
		}
		if !strings.Contains(err.Error(), keys.SourceVaultTransit) {
			t.Errorf("the error does not name the source that sealed it: %v", err)
		}
	})
}

// TestUnsealFixNamesTheSettings pins the settings named when a root-key
// service will not unseal: the service's own error says what it refused, and
// this says where that is configured.
func TestUnsealFixNamesTheSettings(t *testing.T) {
	for provider, want := range map[string][]string{
		"vault":  {"keys.vault.address", "keys.vault.token", "keys.vault.mount", `"blindbucket"`},
		"awskms": {"keys.awskms.region", "kms:Decrypt", "alias/bb"},
	} {
		fix := unsealFix(config.Keys{
			Provider: provider,
			Vault:    config.VaultKeys{KeyName: "blindbucket"},
			AWSKMS:   config.AWSKMSKeys{KeyID: "alias/bb"},
		})
		for _, w := range want {
			if !strings.Contains(fix, w) {
				t.Errorf("%s: %q does not name %q", provider, fix, w)
			}
		}
	}
}
