package rootkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// These run against the real services from docker-compose.yml, not against
// mocks: the whole value of this package is that it speaks two HTTP APIs
// correctly, and a mock would only assert what the code already believes.
//
//	docker compose --profile keys up -d
//	BLINDBUCKET_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
//	BLINDBUCKET_TEST_VAULT_TOKEN=blindbucket-dev-token \
//	BLINDBUCKET_TEST_KMS_ENDPOINT=http://127.0.0.1:4599 \
//	  go test ./internal/rootkey
const (
	vaultAddrEnv   = "BLINDBUCKET_TEST_VAULT_ADDR"
	vaultTokenEnv  = "BLINDBUCKET_TEST_VAULT_TOKEN"
	kmsEndpointEnv = "BLINDBUCKET_TEST_KMS_ENDPOINT"
	// kmsKeyEnv points the KMS tests at an existing key in real AWS instead of
	// the emulator. The credentials are the standard AWS_* variables, which is
	// what aws-actions/configure-aws-credentials exports; the gateway itself
	// never reads them (ADR-013), only this test does.
	kmsKeyEnv = "BLINDBUCKET_TEST_KMS_KEY_ID"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	addr := os.Getenv(vaultAddrEnv)
	if addr == "" {
		t.Skipf("set %s to run these (docker compose --profile keys up -d)", vaultAddrEnv)
	}
	v, err := NewVault(VaultConfig{
		Address: addr, Token: os.Getenv(vaultTokenEnv), KeyName: "blindbucket",
	})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	return v
}

// newTestKMS returns a KMS source pointed at the emulator, with a key created for
// this test.
func newTestKMS(t *testing.T) *KMS {
	t.Helper()
	if key := os.Getenv(kmsKeyEnv); key != "" {
		return newAWSKMS(t, key)
	}
	endpoint := os.Getenv(kmsEndpointEnv)
	if endpoint == "" {
		t.Skipf("set %s to run these (docker compose --profile keys up -d), "+
			"or %s for a key in real AWS", kmsEndpointEnv, kmsKeyEnv)
	}
	// The emulator accepts any credentials; these are not secrets.
	cfg := KMSConfig{
		Region: "us-east-1", KeyID: "placeholder",
		AccessKeyID: "test", SecretAccessKey: "test", Endpoint: endpoint,
	}
	k, err := NewKMS(cfg)
	if err != nil {
		t.Fatalf("NewKMS: %v", err)
	}

	var created struct {
		KeyMetadata struct {
			KeyID string `json:"KeyId"`
		} `json:"KeyMetadata"`
	}
	if err := k.call(t.Context(), "CreateKey", map[string]string{}, &created); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created.KeyMetadata.KeyID == "" {
		t.Fatal("the KMS emulator created no key")
	}

	cfg.KeyID = created.KeyMetadata.KeyID
	k, err = NewKMS(cfg)
	if err != nil {
		t.Fatalf("NewKMS: %v", err)
	}
	return k
}

// newAWSKMS returns a KMS source for an existing key in AWS. It creates
// nothing: the key belongs to deploy/aws-test, and the role the tests run under
// may only encrypt and decrypt with it.
func newAWSKMS(t *testing.T, keyID string) *KMS {
	t.Helper()
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Fatalf("%s is set, but AWS_REGION and the AWS_* credentials are not", kmsKeyEnv)
	}
	k, err := NewKMS(KMSConfig{
		Region: region, KeyID: keyID,
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	})
	if err != nil {
		t.Fatalf("NewKMS: %v", err)
	}
	return k
}

// roundTrip is the claim both sources have to satisfy: what goes in comes back.
func roundTrip(t *testing.T, src Source, source string, keyName string) {
	t.Helper()
	ctx := context.Background()

	root, err := keys.NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	ref, err := src.Encrypt(ctx, root)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if strings.Contains(ref.Ciphertext, string(root)) {
		t.Fatal("the ciphertext contains the plaintext key")
	}
	// The reference is what lands in the keyring file, so the source has to
	// describe itself correctly or the file cannot be opened again.
	if ref.Source != source {
		t.Errorf("the reference names source %q, want %q", ref.Source, source)
	}
	if ref.KeyName != keyName {
		t.Errorf("the reference names key %q, want %q", ref.KeyName, keyName)
	}

	back, err := src.RootKey(ctx, ref)
	if err != nil {
		t.Fatalf("RootKey: %v", err)
	}
	if !bytes.Equal(root, back) {
		t.Fatal("the key that came back is not the key that went in")
	}
}

func TestIntegrationVaultRoundTrip(t *testing.T) {
	roundTrip(t, newTestVault(t), keys.SourceVaultTransit, "blindbucket")
}

func TestIntegrationKMSRoundTrip(t *testing.T) {
	k := newTestKMS(t)
	roundTrip(t, k, keys.SourceAWSKMS, k.cfg.KeyID)
}

// A keyring sealed by a service has to open again through the whole path the
// gateway takes: read the reference off the file, ask the service, unwrap.
func TestIntegrationVaultSealsAKeyring(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()

	ring := keys.NewKeyring()
	if err := ring.Generate("test-key"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	root, err := keys.NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	ref, err := v.Encrypt(ctx, root)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	data, err := ring.MarshalWithRootKey(root, ref)
	if err != nil {
		t.Fatalf("MarshalWithRootKey: %v", err)
	}
	clear(root)

	// The file must not contain the root key, and must say what opens it.
	if bytes.Contains(data, []byte(`"kdf"`)) && bytes.Contains(data, []byte("argon2id")) {
		t.Error("a service-sealed keyring carries KDF parameters it cannot use")
	}
	stored, err := keys.ReadRootKeyRef(data)
	if err != nil {
		t.Fatalf("ReadRootKeyRef: %v", err)
	}
	if stored.Source != keys.SourceVaultTransit {
		t.Fatalf("the keyring names source %q, want %q", stored.Source, keys.SourceVaultTransit)
	}

	back, err := v.RootKey(ctx, stored)
	if err != nil {
		t.Fatalf("RootKey: %v", err)
	}
	defer clear(back)

	reopened, err := keys.LoadKeyringWithRootKey(data, back)
	if err != nil {
		t.Fatalf("LoadKeyringWithRootKey: %v", err)
	}
	if reopened.ActiveKID() != "test-key" {
		t.Errorf("active key is %q, want %q", reopened.ActiveKID(), "test-key")
	}

	// And a passphrase must not open it -- including an empty one, which is
	// what a caller that ignored the reference would end up with.
	if _, err := keys.LoadKeyring(data, []byte("any passphrase")); err == nil {
		t.Fatal("a passphrase opened a Vault-sealed keyring")
	}
}

// The misconfiguration that actually happens: a keyring from another
// environment, sealed under a Transit key this Vault does not have configured.
func TestIntegrationVaultRefusesAnotherKey(t *testing.T) {
	v := newTestVault(t)

	_, err := v.RootKey(context.Background(), keys.RootKeyRef{
		Source: keys.SourceVaultTransit, Ciphertext: "vault:v1:whatever", KeyName: "some-other-key",
	})
	if err == nil {
		t.Fatal("a keyring sealed under a different transit key was accepted")
	}
	if !strings.Contains(err.Error(), "some-other-key") {
		t.Errorf("the error does not name the key that sealed it: %v", err)
	}
}

// A ciphertext the service cannot open is an error, not an empty key.
func TestIntegrationSourcesRefuseGarbage(t *testing.T) {
	t.Run("vault", func(t *testing.T) {
		v := newTestVault(t)
		_, err := v.RootKey(context.Background(), keys.RootKeyRef{
			Source: keys.SourceVaultTransit, Ciphertext: "vault:v1:bm90LWEtY2lwaGVydGV4dA==",
			KeyName: "blindbucket",
		})
		if err == nil {
			t.Fatal("Vault accepted a forged ciphertext")
		}
	})

	t.Run("kms", func(t *testing.T) {
		k := newTestKMS(t)
		_, err := k.RootKey(context.Background(), keys.RootKeyRef{
			Source: keys.SourceAWSKMS, Ciphertext: "bm90LWEtY2lwaGVydGV4dA==", KeyName: k.cfg.KeyID,
		})
		if err == nil {
			t.Fatal("KMS accepted a forged ciphertext")
		}
	})
}

// A source is only asked for the kind of keyring it seals.
func TestSourceRefusesTheWrongReference(t *testing.T) {
	t.Parallel()

	v, err := NewVault(VaultConfig{Address: "http://127.0.0.1:1", Token: "t", KeyName: "k"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if _, err := v.RootKey(context.Background(), keys.RootKeyRef{
		Source: keys.SourceAWSKMS, Ciphertext: "x",
	}); err == nil {
		t.Error("the Vault source accepted a KMS keyring")
	}

	k, err := NewKMS(KMSConfig{
		Region: "us-east-1", KeyID: "k", AccessKeyID: "a", SecretAccessKey: "s",
	})
	if err != nil {
		t.Fatalf("NewKMS: %v", err)
	}
	if _, err := k.RootKey(context.Background(), keys.RootKeyRef{
		Source: keys.SourceVaultTransit, Ciphertext: "x",
	}); err == nil {
		t.Error("the KMS source accepted a Vault keyring")
	}
}

// Configuration that cannot work is refused before anything is attempted, so a
// gateway fails at startup rather than at the first request.
func TestSourcesValidateTheirConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewVault(VaultConfig{Token: "t", KeyName: "k"}); err == nil {
		t.Error("a Vault source without an address was accepted")
	}
	if _, err := NewVault(VaultConfig{Address: "http://v", KeyName: "k"}); err == nil {
		t.Error("a Vault source without a token was accepted")
	}
	if _, err := NewKMS(KMSConfig{Region: "r", AccessKeyID: "a", SecretAccessKey: "s"}); err == nil {
		t.Error("a KMS source without a key id was accepted")
	}
	if _, err := NewKMS(KMSConfig{Region: "r", KeyID: "k"}); err == nil {
		t.Error("a KMS source without credentials was accepted")
	}
}

// TestIntegrationKMSBindsTheEncryptionContext is the point of sending one at
// all: the ciphertext is bound to it, so a keyring whose recorded context has
// been edited fails to open rather than opening under someone else's terms.
//
// The same call also has to keep working for a keyring written before contexts
// existed, which carries none.
func TestIntegrationKMSBindsTheEncryptionContext(t *testing.T) {
	k := newTestKMS(t)
	ctx := context.Background()

	root, err := keys.NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	ref, err := k.Encrypt(ctx, root)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ref.Context[contextKey] == "" {
		t.Fatalf("the reference records no %q entry: %v", contextKey, ref.Context)
	}

	tampered := ref
	tampered.Context = map[string]string{contextKey: "something-else"}
	if _, err := k.RootKey(ctx, tampered); err == nil {
		t.Error("KMS opened the blob under a context it was not sealed with")
	}
	dropped := ref
	dropped.Context = nil
	if _, err := k.RootKey(ctx, dropped); err == nil {
		t.Error("KMS opened the blob with no context at all")
	}

	// A keyring from an earlier build: sealed without a context, and it must
	// still open.
	var out struct {
		CiphertextBlob string `json:"CiphertextBlob"`
	}
	in := map[string]any{
		"KeyId":     k.cfg.KeyID,
		"Plaintext": base64.StdEncoding.EncodeToString(root),
	}
	if err := k.call(ctx, "Encrypt", in, &out); err != nil {
		t.Fatalf("Encrypt without a context: %v", err)
	}
	back, err := k.RootKey(ctx, keys.RootKeyRef{
		Source: keys.SourceAWSKMS, Ciphertext: out.CiphertextBlob, KeyName: k.cfg.KeyID,
	})
	if err != nil {
		t.Fatalf("a keyring sealed before encryption contexts existed no longer opens: %v", err)
	}
	if !bytes.Equal(root, back) {
		t.Error("the key that came back is not the key that went in")
	}
}
