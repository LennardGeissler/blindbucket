package rootkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// KMSConfig addresses an AWS KMS key.
type KMSConfig struct {
	// Region the key lives in.
	Region string
	// KeyID is the key, alias or ARN that encrypts the root key.
	KeyID string

	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// Credentials supplies the credentials instead of the three fields above
	// (ADR-024). Set it or the fields, not both.
	Credentials aws.CredentialsProvider

	// Endpoint overrides the derived kms.<region>.amazonaws.com. It exists for
	// LocalStack and for the AWS-compatible endpoints some environments front
	// KMS with; leave it empty for AWS.
	Endpoint string

	// Context is the encryption context new root keys are sealed under, on top
	// of the fixed pair every blindbucket keyring carries. Operators add
	// something that identifies the deployment, and then a key policy can
	// require it. See defaultContext.
	Context map[string]string

	HTTPClient *http.Client
	// now is injectable so the signature of a test is deterministic.
	now func() time.Time
}

// KMS obtains a root key from AWS KMS.
//
// Like the upstream S3 client (ADR-003) this speaks the service's HTTP API
// directly rather than through the AWS SDK's KMS client. Two calls of a JSON
// protocol need less code than the dependency would add, the SigV4 signer is
// already in the module for the S3 side, and the alternative would have made
// the largest dependency in a deliberately small module larger still.
type KMS struct {
	cfg      KMSConfig
	client   *http.Client
	signer   *v4.Signer
	creds    aws.CredentialsProvider
	endpoint string
}

// contextKey is the fixed encryption-context entry every keyring sealed by this
// build carries.
//
// Fixed rather than derived from the deployment, so that a key policy can
// require it with a single kms:EncryptionContext:blindbucket condition and no
// per-environment editing. Anything identifying the environment is the
// operator's to add through KMSConfig.Context.
const contextKey = "blindbucket"

// defaultContext returns the encryption context for a fresh root key: the fixed
// entry, plus whatever the operator configured.
//
// The fixed entry wins a collision. It is what a key policy keys off, and a
// configuration file must not be able to turn that condition off by overwriting
// it with something else.
func (k *KMS) defaultContext() map[string]string {
	out := make(map[string]string, len(k.cfg.Context)+1)
	for name, value := range k.cfg.Context {
		out[name] = value
	}
	out[contextKey] = "root-key"
	return out
}

// NewKMS validates the configuration and returns a source.
func NewKMS(cfg KMSConfig) (*KMS, error) {
	switch {
	case strings.TrimSpace(cfg.Region) == "":
		return nil, fmt.Errorf("rootkey: kms needs a region")
	case strings.TrimSpace(cfg.KeyID) == "":
		return nil, fmt.Errorf("rootkey: kms needs a key id")
	case cfg.Credentials != nil && (cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" || cfg.SessionToken != ""):
		return nil, fmt.Errorf("rootkey: kms credentials are configured twice, as keys and as a provider")
	case cfg.Credentials == nil && strings.TrimSpace(cfg.AccessKeyID) == "":
		return nil, fmt.Errorf("rootkey: kms needs an access key id")
	case cfg.Credentials == nil && strings.TrimSpace(cfg.SecretAccessKey) == "":
		return nil, fmt.Errorf("rootkey: kms needs a secret access key")
	}
	creds := cfg.Credentials
	if creds == nil {
		static := aws.Credentials{
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
			SessionToken:    cfg.SessionToken,
		}
		creds = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return static, nil
		})
	}

	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://kms.%s.amazonaws.com", cfg.Region)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &KMS{
		cfg:      cfg,
		client:   client,
		signer:   v4.NewSigner(),
		creds:    creds,
		endpoint: endpoint,
	}, nil
}

// Encrypt hands a fresh root key to KMS and returns what a keyring must record
// to get it back.
//
// Used by `blindbucket keygen`, never by the gateway. The reference is built
// here rather than by the caller because the encryption context is part of it,
// and only this side knows what was sent.
func (k *KMS) Encrypt(ctx context.Context, rootKey []byte) (keys.RootKeyRef, error) {
	var out struct {
		CiphertextBlob string `json:"CiphertextBlob"`
	}
	encContext := k.defaultContext()
	in := map[string]any{
		"KeyId":             k.cfg.KeyID,
		"Plaintext":         base64.StdEncoding.EncodeToString(rootKey),
		"EncryptionContext": encContext,
	}
	if err := k.call(ctx, "Encrypt", in, &out); err != nil {
		return keys.RootKeyRef{}, err
	}
	if out.CiphertextBlob == "" {
		return keys.RootKeyRef{}, fmt.Errorf("rootkey: kms returned no ciphertext")
	}
	return keys.RootKeyRef{
		Source:     keys.SourceAWSKMS,
		Ciphertext: out.CiphertextBlob,
		KeyName:    k.cfg.KeyID,
		Context:    encContext,
	}, nil
}

// RootKey asks KMS to decrypt the stored root key.
func (k *KMS) RootKey(ctx context.Context, ref keys.RootKeyRef) ([]byte, error) {
	if ref.Source != keys.SourceAWSKMS {
		return nil, fmt.Errorf("rootkey: keyring names source %q, not %q",
			ref.Source, keys.SourceAWSKMS)
	}
	if _, err := ref.DecodeKMSCiphertext(); err != nil {
		return nil, err
	}

	var out struct {
		Plaintext string `json:"Plaintext"`
	}
	// KeyId is sent even though a symmetric decrypt does not need it: it makes
	// KMS refuse a blob produced under a different key rather than opening it,
	// so a keyring from another environment fails loudly here.
	in := map[string]any{"CiphertextBlob": ref.Ciphertext, "KeyId": k.cfg.KeyID}
	// The context that encrypted, not the one configured now. They are usually
	// the same, but a keyring written before encryption contexts existed has
	// none, and it must keep opening: KMS requires an exact match, so guessing
	// the current one would lock out every keyring made by an earlier build.
	if len(ref.Context) > 0 {
		in["EncryptionContext"] = ref.Context
	}
	if err := k.call(ctx, "Decrypt", in, &out); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("rootkey: kms returned a plaintext that is not base64: %w", err)
	}
	if len(key) != keys.KeySize {
		clear(key)
		return nil, fmt.Errorf("rootkey: kms returned a %d byte key, want %d", len(key), keys.KeySize)
	}
	return key, nil
}

// call performs one signed KMS API call.
//
// KMS is AWS JSON 1.1: one POST to the service root, the operation in
// X-Amz-Target, and a signature over the real payload hash rather than the
// UNSIGNED-PAYLOAD the S3 client uses for streams.
func (k *KMS) call(ctx context.Context, op string, in any, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.endpoint+"/", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	req.ContentLength = int64(len(payload))

	sum := sha256.Sum256(payload)
	creds, err := k.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("rootkey: kms credentials: %w", err)
	}
	if err := k.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]),
		"kms", k.cfg.Region, k.cfg.now().UTC()); err != nil {
		return fmt.Errorf("rootkey: signing the kms request: %w", err)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("rootkey: kms %s: %w", op, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("rootkey: reading the kms answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &failure) == nil && (failure.Type != "" || failure.Message != "") {
			return fmt.Errorf("rootkey: kms %s: %s %s (%d)",
				op, failure.Type, failure.Message, resp.StatusCode)
		}
		return fmt.Errorf("rootkey: kms %s returned %d", op, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("rootkey: the kms answer is not the expected JSON: %w", err)
	}
	return nil
}
