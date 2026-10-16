package proxytest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Bucket is the bucket every test writes to. It must exist already.
var Bucket = testprovider.Bucket()

// The credentials of the gateway's one client, which Client signs with.
const (
	ClientAccessKey = "BBTESTACCESSKEY"
	ClientSecretKey = "bb-test-secret-key-not-a-real-one"
)

// SigningTransport signs every request the way a real S3 client does.
//
// It uses the AWS SDK's signer rather than this project's own code: the proxy
// must accept what real clients produce, and a test that signed with the
// verifier's own helpers would only prove the two agree with each other.
type SigningTransport struct{ Base http.RoundTripper }

// RoundTrip signs req and sends it.
func (s *SigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		read, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = read
		if len(body) == 0 {
			// A non-nil Body with ContentLength 0 makes net/http switch to
			// chunked encoding, which is a different request entirely.
			req.Body = http.NoBody
		} else {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		req.ContentLength = int64(len(body))
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)

	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	creds := aws.Credentials{AccessKeyID: ClientAccessKey, SecretAccessKey: ClientSecretKey}
	if err := signer.SignHTTP(req.Context(), creds, req, hash, "s3", "us-east-1", time.Now().UTC()); err != nil {
		return nil, err
	}
	return s.Base.RoundTrip(req)
}

// Harness is a gateway in front of the provider under test, with a client for
// each side: Client and Unsigned speak S3 to the gateway, Upstream to the
// provider directly.
type Harness struct {
	Server   *httptest.Server
	Upstream *upstream.Client
	Keyring  *keys.Keyring
	// Gateway is the Proxy behind the server, so that a test can install the
	// coordination hooks of hooks.go and replay a model counterexample.
	Gateway *proxy.Proxy
	// config is what the gateway was built from, for helpers that need the
	// same settings -- a scrub, say -- without reading the gateway's fields.
	config proxy.Config
	Client *http.Client
	// Unsigned sends requests without a signature, to check that the gateway
	// refuses them. It has to be captured before the signing transport is
	// installed: httptest.Server.Client returns the same client every time, so
	// asking for it later would hand back the signing one.
	Unsigned *http.Client
}

// UpstreamConfig describes the provider under test to an upstream client, so
// that a test building a client of its own -- one that counts requests, say --
// talks to the same provider as the harness.
func UpstreamConfig(t *testing.T) upstream.Config {
	t.Helper()
	p := testprovider.Require(t)
	return upstream.Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey, SessionToken: p.SessionToken,
	}
}

// New builds a gateway against a real provider.
//
// An option adjusts either the proxy configuration or the verifier's, for tests
// that need something other than the defaults -- a short stall timeout, say,
// where waiting out the real one would take a minute, or presigned URLs, which
// are configured on the verifier and not on the proxy. Anything else is a
// mistake rather than a no-op, so the default case fails the test instead of
// ignoring it.
func New(t *testing.T, options ...any) *Harness {
	t.Helper()
	client, err := upstream.New(UpstreamConfig(t))
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	ring := keys.NewKeyring()
	if err := ring.Generate("test-key"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	authCfg := auth.Config{Clients: []auth.Client{{
		Name: "integration", AccessKeyID: ClientAccessKey,
		SecretAccessKey: ClientSecretKey, Buckets: []string{Bucket},
	}}}
	for _, option := range options {
		if adjust, ok := option.(func(*auth.Config)); ok {
			adjust(&authCfg)
		}
	}
	verifier, err := auth.NewVerifier(authCfg)
	if err != nil {
		t.Fatalf("auth.NewVerifier: %v", err)
	}

	cfg := proxy.Config{
		Upstream: client, Keys: ring, Verifier: verifier,
		Log2ChunkSize: stream.MinLog2ChunkSize,
		// Discard: these tests deliberately provoke errors, and the log noise
		// would drown the failures that matter.
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, option := range options {
		switch adjust := option.(type) {
		case func(*proxy.Config):
			adjust(&cfg)
		case func(*auth.Config):
			// Applied above, before the verifier was built.
		case func(net.Listener) net.Listener:
			// Applied below, once the server exists.
		default:
			t.Fatalf("newHarness: %T is not a harness option", adjust)
		}
	}
	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	srv := httptest.NewUnstartedServer(p)
	for _, option := range options {
		if wrap, ok := option.(func(net.Listener) net.Listener); ok {
			srv.Listener = wrap(srv.Listener)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	signing := srv.Client()
	plain := &http.Client{Transport: signing.Transport}
	signing.Transport = &SigningTransport{Base: plain.Transport}
	return &Harness{
		Server: srv, Upstream: client, Keyring: ring, Gateway: p, config: cfg,
		Client: signing, Unsigned: plain,
	}
}

// URL is the gateway's address of key in Bucket.
func (h *Harness) URL(key string) string {
	return h.Server.URL + "/" + Bucket + "/" + key
}

// Put uploads body to key through the gateway, with headers, and returns the
// response for the test to judge.
func (h *Harness) Put(t *testing.T, key string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.URL(key), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	return resp
}

// Do sends a bodiless request for key through the gateway.
func (h *Harness) Do(t *testing.T, method, key string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.URL(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return resp
}

// Store uploads through the proxy and registers cleanup.
func (h *Harness) Store(t *testing.T, key string, body []byte) {
	t.Helper()
	resp := h.Put(t, key, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", resp.StatusCode, ReadBody(t, resp))
	}
	t.Cleanup(func() {
		_ = h.Upstream.DeleteObject(context.Background(), Bucket, key)
	})
}

// RewriteUpstream replaces an object's stored bytes while keeping its metadata,
// which is how an actively hostile provider would behave.
func (h *Harness) RewriteUpstream(t *testing.T, key string, mutate func([]byte) []byte) {
	t.Helper()
	ctx := context.Background()

	get, err := h.Upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: Bucket, Key: key})
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}
	stored, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}

	modified := mutate(stored)
	if _, err := h.Upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: Bucket, Key: key,
		Body: bytes.NewReader(modified), ContentLength: int64(len(modified)),
		Metadata: get.Metadata,
	}); err != nil {
		t.Fatalf("writing the modified object: %v", err)
	}
}

// ReadBody returns up to 4 KiB of a response body, for failure messages.
func ReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b)
}

// CleanupStored removes a stored object when the test ends, together with any
// manifest it has. A test that stores under an encrypted name needs it: the
// stored key is not under the run's prefix, so the sweep in TestMain cannot
// find the object, and a manifest lives under a hash of the key, so deleting
// the object alone would orphan it.
func (h *Harness) CleanupStored(t *testing.T, stored string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_ = h.Upstream.DeleteObject(ctx, Bucket, stored)
		page, err := h.Upstream.ListObjects(ctx, Bucket,
			url.Values{"list-type": {"2"}, "prefix": {manifest.PrefixFor(stored)}})
		if err != nil {
			return
		}
		for _, entry := range page.Contents {
			_ = h.Upstream.DeleteObject(ctx, Bucket, entry.Key)
		}
	})
}

// TestKey is a key under the run's prefix that no other test uses, so that
// tests can share the bucket and the sweep finds what they leave.
func TestKey(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("%sproxy-test/%s/%d/%s", testprovider.RunPrefix(),
		strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano(), suffix)
}
