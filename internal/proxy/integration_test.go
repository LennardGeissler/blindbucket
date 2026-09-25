package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// These tests need a real S3-compatible provider, because the interesting
// failures are the ones a fake would paper over: what a provider stores, what it
// returns, and what happens when the stored bytes are changed behind the
// proxy's back.
//
//	docker compose up -d
//	BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/proxy
//
// Any other provider works the same way; internal/testprovider lists the
// variables that describe it.
var testBucket = testprovider.Bucket()

const (
	clientAccessKey = "BBTESTACCESSKEY"
	clientSecretKey = "bb-test-secret-key-not-a-real-one"
)

// signingTransport signs every request the way a real S3 client does.
//
// It uses the AWS SDK's signer rather than this project's own code: the proxy
// must accept what real clients produce, and a test that signed with the
// verifier's own helpers would only prove the two agree with each other.
type signingTransport struct{ base http.RoundTripper }

func (s *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
	creds := aws.Credentials{AccessKeyID: clientAccessKey, SecretAccessKey: clientSecretKey}
	if err := signer.SignHTTP(req.Context(), creds, req, hash, "s3", "us-east-1", time.Now().UTC()); err != nil {
		return nil, err
	}
	return s.base.RoundTrip(req)
}

type harness struct {
	proxy    *httptest.Server
	upstream *upstream.Client
	keyring  *keys.Keyring
	// gateway is the Proxy behind the server, so that a test can install the
	// coordination hooks of hooks.go and replay a model counterexample.
	gateway *Proxy
	client  *http.Client
	// unsigned sends requests without a signature, to check that the gateway
	// refuses them. It has to be captured before the signing transport is
	// installed: httptest.Server.Client returns the same client every time, so
	// asking for it later would hand back the signing one.
	unsigned *http.Client
}

// upstreamConfig describes the provider under test to an upstream client, so
// that a test building a client of its own -- one that counts requests, say --
// talks to the same provider as the harness.
func upstreamConfig(t *testing.T) upstream.Config {
	t.Helper()
	p := testprovider.Require(t)
	return upstream.Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey,
	}
}

// newHarness builds a gateway against a real provider.
//
// An option adjusts either the proxy configuration or the verifier's, for tests
// that need something other than the defaults -- a short stall timeout, say,
// where waiting out the real one would take a minute, or presigned URLs, which
// are configured on the verifier and not on the proxy. Anything else is a
// mistake rather than a no-op, so the default case fails the test instead of
// ignoring it.
func newHarness(t *testing.T, options ...any) *harness {
	t.Helper()
	client, err := upstream.New(upstreamConfig(t))
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	ring := keys.NewKeyring()
	if err := ring.Generate("test-key"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	authCfg := auth.Config{Clients: []auth.Client{{
		Name: "integration", AccessKeyID: clientAccessKey,
		SecretAccessKey: clientSecretKey, Buckets: []string{testBucket},
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

	cfg := Config{
		Upstream: client, Keys: ring, Verifier: verifier,
		Log2ChunkSize: stream.MinLog2ChunkSize,
		// Discard: these tests deliberately provoke errors, and the log noise
		// would drown the failures that matter.
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, option := range options {
		switch adjust := option.(type) {
		case func(*Config):
			adjust(&cfg)
		case func(*auth.Config):
			// Applied above, before the verifier was built.
		default:
			t.Fatalf("newHarness: %T is not a harness option", adjust)
		}
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	signing := srv.Client()
	plain := &http.Client{Transport: signing.Transport}
	signing.Transport = &signingTransport{base: plain.Transport}
	return &harness{
		proxy: srv, upstream: client, keyring: ring, gateway: p,
		client: signing, unsigned: plain,
	}
}

func (h *harness) url(key string) string {
	return h.proxy.URL + "/" + testBucket + "/" + key
}

func (h *harness) put(t *testing.T, key string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.url(key), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	return resp
}

func (h *harness) do(t *testing.T, method, key string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return resp
}

// store uploads through the proxy and registers cleanup.
func (h *harness) store(t *testing.T, key string, body []byte) {
	t.Helper()
	resp := h.put(t, key, body, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	t.Cleanup(func() {
		_ = h.upstream.DeleteObject(context.Background(), testBucket, key)
	})
}

// rewriteUpstream replaces an object's stored bytes while keeping its metadata,
// which is how an actively hostile provider would behave.
func (h *harness) rewriteUpstream(t *testing.T, key string, mutate func([]byte) []byte) {
	t.Helper()
	ctx := context.Background()

	get, err := h.upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: testBucket, Key: key})
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}
	stored, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}

	modified := mutate(stored)
	if _, err := h.upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: testBucket, Key: key,
		Body: bytes.NewReader(modified), ContentLength: int64(len(modified)),
		Metadata: get.Metadata,
	}); err != nil {
		t.Fatalf("writing the modified object: %v", err)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b)
}

// cleanupStored removes a stored object when the test ends, together with any
// manifest it has. A test that stores under an encrypted name needs it: the
// stored key is not under the run's prefix, so the sweep in TestMain cannot
// find the object, and a manifest lives under a hash of the key, so deleting
// the object alone would orphan it.
func (h *harness) cleanupStored(t *testing.T, stored string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		_ = h.upstream.DeleteObject(ctx, testBucket, stored)
		page, err := h.upstream.ListObjects(ctx, testBucket,
			url.Values{"list-type": {"2"}, "prefix": {manifest.PrefixFor(stored)}})
		if err != nil {
			return
		}
		for _, entry := range page.Contents {
			_ = h.upstream.DeleteObject(ctx, testBucket, entry.Key)
		}
	})
}

func testKey(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("%sproxy-test/%s/%d/%s", testprovider.RunPrefix(),
		strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano(), suffix)
}

func TestIntegrationRoundTrip(t *testing.T) {
	h := newHarness(t)

	for _, size := range []int{0, 1, 4095, 4096, 4097, 100_000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			key := testKey(t, "object.bin")
			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}
			h.store(t, key, payload)

			// What the provider holds must be the blindbucket format, at the
			// size the arithmetic predicts -- never the plaintext.
			info, err := h.upstream.HeadObject(context.Background(), testBucket, key)
			if err != nil {
				t.Fatalf("HeadObject upstream: %v", err)
			}
			wantSealed, err := stream.SealedSize(int64(size), stream.MinLog2ChunkSize)
			if err != nil {
				t.Fatalf("SealedSize: %v", err)
			}
			if info.ContentLength != wantSealed {
				t.Errorf("provider stores %d bytes, the format says %d", info.ContentLength, wantSealed)
			}

			// HEAD through the proxy reports the plaintext size.
			head := h.do(t, http.MethodHead, key)
			_ = head.Body.Close()
			if head.ContentLength != int64(size) {
				t.Errorf("HEAD reports %d bytes, want %d", head.ContentLength, size)
			}
			if head.Header.Get("X-Amz-Meta-Bb-Dek") != "" {
				t.Error("the wrapped key leaked into a response to the client")
			}

			// GET returns the original bytes.
			get := h.do(t, http.MethodGet, key)
			defer func() { _ = get.Body.Close() }()
			if get.ContentLength != int64(size) {
				t.Errorf("GET declares %d bytes, want %d", get.ContentLength, size)
			}
			body, err := io.ReadAll(get.Body)
			if err != nil {
				t.Fatalf("reading the response: %v", err)
			}
			if sha256.Sum256(body) != sha256.Sum256(payload) {
				t.Error("the object came back different from what was sent")
			}
		})
	}
}

func TestIntegrationCiphertextIsOpaque(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "secret.txt")
	secret := bytes.Repeat([]byte("TOP SECRET PAYLOAD "), 500)
	h.store(t, key, secret)

	get, err := h.upstream.GetObject(context.Background(), upstream.GetObjectInput{
		Bucket: testBucket, Key: key,
	})
	if err != nil {
		t.Fatalf("GetObject upstream: %v", err)
	}
	stored, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	if bytes.Contains(stored, []byte("TOP SECRET")) {
		t.Fatal("plaintext reached the storage provider")
	}
	if !bytes.HasPrefix(stored, []byte("BLBK")) {
		t.Errorf("stored object does not start with the segment magic: %x", stored[:8])
	}
	if stored[4] != stream.Version {
		t.Errorf("stored format version is %d, want %d", stored[4], stream.Version)
	}
	if stored[5] != stream.MinLog2ChunkSize {
		t.Errorf("stored chunk size is 2^%d, want 2^%d", stored[5], stream.MinLog2ChunkSize)
	}
}

func TestIntegrationMetadataHandling(t *testing.T) {
	h := newHarness(t)

	t.Run("client metadata survives, gateway metadata is hidden", func(t *testing.T) {
		key := testKey(t, "meta.bin")
		resp := h.put(t, key, []byte("payload"), map[string]string{
			"Content-Type":      "text/plain",
			"X-Amz-Meta-Origin": "integration-test",
			"Cache-Control":     "max-age=60",
		})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT returned %d", resp.StatusCode)
		}
		t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, key) })

		head := h.do(t, http.MethodHead, key)
		_ = head.Body.Close()
		if got := head.Header.Get("X-Amz-Meta-Origin"); got != "integration-test" {
			t.Errorf("client metadata = %q, want it preserved", got)
		}
		if got := head.Header.Get("Content-Type"); got != "text/plain" {
			t.Errorf("Content-Type = %q, want it preserved", got)
		}
		if got := head.Header.Get("Cache-Control"); got != "max-age=60" {
			t.Errorf("Cache-Control = %q, want it preserved", got)
		}
		for _, name := range []string{"X-Amz-Meta-Bb-V", "X-Amz-Meta-Bb-Kid", "X-Amz-Meta-Bb-Dek", "X-Amz-Meta-Bb-C"} {
			if head.Header.Get(name) != "" {
				t.Errorf("%s leaked to the client", name)
			}
		}
	})

	t.Run("clients may not write the reserved prefix", func(t *testing.T) {
		key := testKey(t, "forged.bin")
		resp := h.put(t, key, []byte("payload"), map[string]string{
			"X-Amz-Meta-Bb-Dek": "forged",
		})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status %d, want 400: a client must not be able to set its own wrapped key", resp.StatusCode)
		}
	})
}

// TestIntegrationTamperedObject is the heart of it: an actively hostile
// provider must never produce plaintext.
func TestIntegrationTamperedObject(t *testing.T) {
	h := newHarness(t)
	const chunk = 1 << stream.MinLog2ChunkSize

	t.Run("tampering in a later chunk aborts the response", func(t *testing.T) {
		key := testKey(t, "late.bin")
		payload := bytes.Repeat([]byte{0xAB}, 5*chunk)
		h.store(t, key, payload)

		// Corrupt the third chunk, which the client only reaches after the
		// status line is already on the wire.
		h.rewriteUpstream(t, key, func(b []byte) []byte {
			b[stream.HeaderSize+2*(chunk+stream.TagSize)+9] ^= 0x01
			return b
		})

		get := h.do(t, http.MethodGet, key)
		defer func() { _ = get.Body.Close() }()
		if get.StatusCode != http.StatusOK {
			t.Fatalf("status %d: the failure is expected mid-body, not before it", get.StatusCode)
		}

		body, err := io.ReadAll(get.Body)
		if err == nil {
			t.Fatal("the response completed despite corrupted data")
		}
		if int64(len(body)) >= get.ContentLength {
			t.Errorf("delivered %d of %d declared bytes; a client could mistake this for success",
				len(body), get.ContentLength)
		}
		// Whatever did arrive must be authentic: only verified chunks are released.
		if !bytes.Equal(body, payload[:len(body)]) {
			t.Error("the bytes delivered before the abort were not authentic plaintext")
		}
	})

	t.Run("tampering in the first chunk yields a clean error", func(t *testing.T) {
		key := testKey(t, "early.bin")
		h.store(t, key, bytes.Repeat([]byte{0xCD}, 3*chunk))

		h.rewriteUpstream(t, key, func(b []byte) []byte {
			b[stream.HeaderSize+5] ^= 0x01
			return b
		})

		get := h.do(t, http.MethodGet, key)
		defer func() { _ = get.Body.Close() }()
		if get.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502 with an S3 error document", get.StatusCode)
		}
		if body := readBody(t, get); !strings.Contains(body, "IntegrityCheckFailed") {
			t.Errorf("body = %q, want an IntegrityCheckFailed error", body)
		}
	})

	t.Run("truncation is detected", func(t *testing.T) {
		key := testKey(t, "truncated.bin")
		h.store(t, key, bytes.Repeat([]byte{0xEF}, 3*chunk))

		h.rewriteUpstream(t, key, func(b []byte) []byte {
			return b[:stream.HeaderSize+2*(chunk+stream.TagSize)]
		})

		get := h.do(t, http.MethodGet, key)
		defer func() { _ = get.Body.Close() }()
		// A truncated object has an impossible ciphertext length, so this is
		// caught before any byte is served.
		if get.StatusCode == http.StatusOK {
			if _, err := io.ReadAll(get.Body); err == nil {
				t.Error("a truncated object was served as if complete")
			}
			return
		}
		if get.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502", get.StatusCode)
		}
	})

	t.Run("swapping two objects' bodies is detected", func(t *testing.T) {
		keyA, keyB := testKey(t, "a.bin"), testKey(t, "b.bin")
		h.store(t, keyA, bytes.Repeat([]byte{1}, 2*chunk))
		h.store(t, keyB, bytes.Repeat([]byte{2}, 2*chunk))

		ctx := context.Background()
		get, err := h.upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: testBucket, Key: keyB})
		if err != nil {
			t.Fatalf("reading B: %v", err)
		}
		bodyB, err := io.ReadAll(get.Body)
		_ = get.Body.Close()
		if err != nil {
			t.Fatalf("reading B: %v", err)
		}

		// B's body under A's key and metadata: the data key is bound to the key
		// name, so A's key cannot open B's segment.
		h.rewriteUpstream(t, keyA, func([]byte) []byte { return bodyB })

		resp := h.do(t, http.MethodGet, keyA)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				t.Errorf("a swapped body was served as plaintext (%d bytes)", len(body))
			}
			return
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502", resp.StatusCode)
		}
	})

	t.Run("a forged wrapped key is rejected", func(t *testing.T) {
		key := testKey(t, "forged-dek.bin")
		h.store(t, key, bytes.Repeat([]byte{3}, chunk))

		ctx := context.Background()
		get, err := h.upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: testBucket, Key: key})
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		stored, err := io.ReadAll(get.Body)
		_ = get.Body.Close()
		if err != nil {
			t.Fatalf("reading: %v", err)
		}

		metadata := get.Metadata
		forged := keys.EncodeWrapped(bytes.Repeat([]byte{0}, keys.WrappedDEKSize))
		for name := range metadata {
			if strings.EqualFold(name, "bb-dek") {
				metadata[name] = forged
			}
		}
		if _, err := h.upstream.PutObject(ctx, upstream.PutObjectInput{
			Bucket: testBucket, Key: key,
			Body: bytes.NewReader(stored), ContentLength: int64(len(stored)),
			Metadata: metadata,
		}); err != nil {
			t.Fatalf("writing the forged object: %v", err)
		}

		resp := h.do(t, http.MethodGet, key)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502", resp.StatusCode)
		}
	})
}

// TestIntegrationForeignObject covers a bucket that also holds objects this
// gateway did not write.
func TestIntegrationForeignObject(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "foreign.txt")

	if _, err := h.upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: testBucket, Key: key,
		Body: strings.NewReader("written without the gateway"), ContentLength: 27,
	}); err != nil {
		t.Fatalf("PutObject upstream: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, key) })

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		resp := h.do(t, method, key)
		body := readBody(t, resp)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("%s returned %d, want 502 -- an unencrypted object must not be served silently",
				method, resp.StatusCode)
		}
		if method == http.MethodGet && !strings.Contains(body, "ObjectNotEncrypted") {
			t.Errorf("GET body = %q, want an ObjectNotEncrypted error", body)
		}
	}
}

func TestIntegrationDeleteAndMissing(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "transient.bin")

	resp := h.put(t, key, []byte("payload"), nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	del := h.do(t, http.MethodDelete, key)
	_ = del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE returned %d, want 204", del.StatusCode)
	}

	get := h.do(t, http.MethodGet, key)
	body := readBody(t, get)
	_ = get.Body.Close()
	if get.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE returned %d, want 404", get.StatusCode)
	}
	if !strings.Contains(body, "NoSuchKey") {
		t.Errorf("body = %q, want NoSuchKey", body)
	}
}

// TestIntegrationRefusesUnsupported checks that nothing this build cannot do is
// quietly accepted.
func TestIntegrationRefusesUnsupported(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "unsupported.bin")
	h.store(t, key, bytes.Repeat([]byte{7}, 1000))

	t.Run("object sub-resources", func(t *testing.T) {
		for _, suffix := range []string{"?acl", "?attributes", "?versionId=null"} {
			resp, err := h.client.Get(h.url(key) + suffix)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("%s returned %d, want 501", suffix, resp.StatusCode)
			}
		}
	})

	// Tagging is the asymmetric one. Reading is forwarded, because the AWS CLI
	// asks for an object's tags before a server-side copy and a refusal there
	// breaks every large copy. Writing is refused: the provider would store the
	// tag in plaintext (ADR-012).
	t.Run("tagging is readable and not writable", func(t *testing.T) {
		resp, err := h.client.Get(h.url(key) + "?tagging")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET ?tagging returned %d, want 200", resp.StatusCode)
		}

		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			req, err := http.NewRequestWithContext(t.Context(), method, h.url(key)+"?tagging", nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", method, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("%s ?tagging returned %d, want 501", method, resp.StatusCode)
			}
		}

		// And the header form on an ordinary upload.
		put := h.put(t, testKey(t, "tagged.bin"), []byte("tagged"),
			map[string]string{"X-Amz-Tagging": "team=platform"})
		_ = put.Body.Close()
		if put.StatusCode != http.StatusNotImplemented {
			t.Errorf("PUT with x-amz-tagging returned %d, want 501", put.StatusCode)
		}
	})

	// The multipart sub-resources are implemented since M4, so a malformed one
	// is a client error rather than an unimplemented feature. Both must still be
	// refused: ?partNumber without an upload id used to fall through to the
	// plain-object path, which would have stored one part as the whole object.
	t.Run("malformed multipart requests", func(t *testing.T) {
		for _, suffix := range []string{"?partNumber=1", "?uploadId="} {
			resp, err := h.client.Get(h.url(key) + suffix)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s returned %d, want 400", suffix, resp.StatusCode)
			}
		}
	})

	t.Run("bucket sub-resources", func(t *testing.T) {
		for _, suffix := range []string{"?versioning", "?policy", "?lifecycle"} {
			resp, err := h.client.Get(h.proxy.URL + "/" + testBucket + suffix)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("%s returned %d, want 501", suffix, resp.StatusCode)
			}
		}
	})

	t.Run("the reserved prefix", func(t *testing.T) {
		resp, err := h.client.Get(h.proxy.URL + "/" + testBucket + "/.blindbucket/m/anything")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})

	t.Run("server-side encryption headers", func(t *testing.T) {
		resp := h.put(t, testKey(t, "sse.bin"), []byte("payload"),
			map[string]string{"X-Amz-Server-Side-Encryption": "AES256"})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("status %d, want 501", resp.StatusCode)
		}
	})
}

// TestIntegrationAbortedUploadStoresNothing checks that a client which stops
// mid-body leaves no object: the final chunk is only written on a clean close.
func TestIntegrationAbortedUploadStoresNothing(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "aborted.bin")

	// Declare more bytes than the body will produce.
	body := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{9}, 1000)), errReader{})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.url(key), body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = 100000

	resp, err := h.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}

	if _, err := h.upstream.HeadObject(context.Background(), testBucket, key); !upstream.NotFound(err) {
		t.Errorf("an aborted upload left an object behind (err = %v)", err)
	}
}

// errReader fails partway through a body, standing in for a client that goes
// away mid-upload.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("client went away") }

// TestIntegrationAuthentication checks that the gateway is closed to anyone
// without a credential, and scoped for those who have one.
func TestIntegrationAuthentication(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "auth.bin")
	h.store(t, key, []byte("payload"))

	unsigned := h.unsigned

	t.Run("unsigned requests are refused", func(t *testing.T) {
		resp, err := unsigned.Get(h.url(key))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})

	t.Run("a bucket outside the credential's scope is refused", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			h.proxy.URL+"/some-other-bucket/key", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})

	t.Run("a forged signature is refused", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Authorization",
			"AWS4-HMAC-SHA256 Credential="+clientAccessKey+"/"+time.Now().UTC().Format("20060102")+
				"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, "+
				"Signature="+strings.Repeat("0", 64))
		req.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
		req.Header.Set("X-Amz-Content-Sha256", strings.Repeat("e", 64))

		resp, err := unsigned.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
		if body := readBody(t, resp); !strings.Contains(body, "SignatureDoesNotMatch") {
			t.Errorf("body = %q, want SignatureDoesNotMatch", body)
		}
	})
}

// TestIntegrationRangeRequests covers the mapping from plaintext ranges onto
// ciphertext chunks, end to end through a real provider.
func TestIntegrationRangeRequests(t *testing.T) {
	h := newHarness(t)
	const chunk = 1 << stream.MinLog2ChunkSize

	key := testKey(t, "ranged.bin")
	payload := make([]byte, 5*chunk+123)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	h.store(t, key, payload)
	size := int64(len(payload))

	tests := []struct {
		spec       string
		start, end int64
	}{
		{"bytes=0-0", 0, 0},
		{"bytes=0-99", 0, 99},
		{"bytes=100-199", 100, 199},
		{"bytes=4095-4096", chunk - 1, chunk},   // across a chunk boundary
		{"bytes=4096-8191", chunk, 2*chunk - 1}, // exactly one chunk
		{"bytes=8192-", 2 * chunk, size - 1},    // open ended
		{"bytes=-100", size - 100, size - 1},    // suffix
		{fmt.Sprintf("bytes=0-%d", size-1), 0, size - 1},
		{fmt.Sprintf("bytes=%d-%d", size-1, size-1), size - 1, size - 1},
		{fmt.Sprintf("bytes=1000-%d", size+10_000), 1000, size - 1}, // clamped
	}

	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Header.Set("Range", tc.spec)

			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusPartialContent {
				t.Fatalf("status %d, want 206: %s", resp.StatusCode, readBody(t, resp))
			}
			want := fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, size)
			if got := resp.Header.Get("Content-Range"); got != want {
				t.Errorf("Content-Range = %q, want %q", got, want)
			}

			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading: %v", err)
			}
			if !bytes.Equal(got, payload[tc.start:tc.end+1]) {
				t.Errorf("got %d bytes, want %d", len(got), tc.end-tc.start+1)
			}
		})
	}

	t.Run("unsatisfiable ranges", func(t *testing.T) {
		for _, spec := range []string{
			fmt.Sprintf("bytes=%d-", size), "bytes=abc-def", "bytes=5-2", "items=0-10",
		} {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Header.Set("Range", spec)
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusPartialContent || resp.StatusCode == http.StatusOK {
				t.Errorf("range %q was served with %d", spec, resp.StatusCode)
			}
		}
	})

	t.Run("a tampered chunk inside a range is detected", func(t *testing.T) {
		tampered := testKey(t, "range-tampered.bin")
		h.store(t, tampered, payload)
		h.rewriteUpstream(t, tampered, func(b []byte) []byte {
			b[stream.HeaderSize+2*(chunk+stream.TagSize)+11] ^= 0x01
			return b
		})

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(tampered), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", 2*chunk, 2*chunk+50))
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusPartialContent {
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Error("a tampered range was served as plaintext")
			}
			return
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502", resp.StatusCode)
		}
	})
}

// TestIntegrationListing checks that listings report plaintext sizes and hide
// the gateway's own objects.
func TestIntegrationListing(t *testing.T) {
	h := newHarness(t)
	prefix := fmt.Sprintf("listing-test/%d/", time.Now().UnixNano())

	sizes := map[string]int{"a.bin": 100, "b.bin": 4096, "c.bin": 10000}
	for name, size := range sizes {
		h.store(t, prefix+name, bytes.Repeat([]byte{1}, size))
	}

	// An object under the reserved prefix, written directly, must not appear.
	hidden := ".blindbucket/m/deadbeef/manifest"
	if _, err := h.upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: testBucket, Key: hidden,
		Body: strings.NewReader("manifest"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("writing the hidden object: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, hidden) })

	for _, listType := range []string{"2", ""} {
		name, query := "ListObjectsV2", "?list-type=2&prefix="+url.QueryEscape(prefix)
		if listType == "" {
			name, query = "ListObjects", "?prefix="+url.QueryEscape(prefix)
		}

		t.Run(name, func(t *testing.T) {
			resp, err := h.client.Get(h.proxy.URL + "/" + testBucket + query)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, readBody(t, resp))
			}

			var result upstream.ListBucketResult
			if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("the listing is not valid XML: %v", err)
			}
			if len(result.Contents) != len(sizes) {
				t.Fatalf("listed %d objects, want %d", len(result.Contents), len(sizes))
			}
			for _, entry := range result.Contents {
				base := strings.TrimPrefix(entry.Key, prefix)
				want, ok := sizes[base]
				if !ok {
					t.Errorf("unexpected key %q", entry.Key)
					continue
				}
				if entry.Size != int64(want) {
					t.Errorf("%s: listed size %d, want the plaintext size %d", base, entry.Size, want)
				}
			}
		})
	}

	t.Run("the reserved prefix is hidden", func(t *testing.T) {
		resp, err := h.client.Get(h.proxy.URL + "/" + testBucket + "?list-type=2&prefix=.blindbucket/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var result upstream.ListBucketResult
		if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("the listing is not valid XML: %v", err)
		}
		if len(result.Contents) != 0 {
			t.Errorf("the gateway's own objects appeared in a listing: %d entries", len(result.Contents))
		}
	})
}

// TestIntegrationDeleteObjects covers the bulk delete `aws s3 rm --recursive`
// uses.
func TestIntegrationDeleteObjects(t *testing.T) {
	h := newHarness(t)
	prefix := fmt.Sprintf("bulk-delete/%d/", time.Now().UnixNano())

	keys := []string{prefix + "one", prefix + "two", prefix + "three"}
	for _, key := range keys {
		h.store(t, key, []byte("payload"))
	}

	var body strings.Builder
	body.WriteString("<Delete>")
	for _, key := range keys {
		body.WriteString("<Object><Key>" + key + "</Key></Object>")
	}
	body.WriteString("</Delete>")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		h.proxy.URL+"/"+testBucket+"?delete", strings.NewReader(body.String()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, readBody(t, resp))
	}

	for _, key := range keys {
		if _, err := h.upstream.HeadObject(context.Background(), testBucket, key); !upstream.NotFound(err) {
			t.Errorf("%s survived the bulk delete", key)
		}
	}

	t.Run("the reserved prefix is refused", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			h.proxy.URL+"/"+testBucket+"?delete",
			strings.NewReader("<Delete><Object><Key>.blindbucket/m/x</Key></Object></Delete>"))
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})
}

func TestIntegrationBucketOperations(t *testing.T) {
	h := newHarness(t)

	t.Run("HeadBucket", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodHead,
			h.proxy.URL+"/"+testBucket, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("HEAD: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("GetBucketLocation", func(t *testing.T) {
		resp, err := h.client.Get(h.proxy.URL + "/" + testBucket + "?location")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d, want 200", resp.StatusCode)
		}
		if body := readBody(t, resp); !strings.Contains(body, "LocationConstraint") {
			t.Errorf("body = %q, want a LocationConstraint document", body)
		}
	})
}
