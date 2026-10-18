package encrypt_test

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/encrypt"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The integration tests of `blindbucket encrypt-existing` (ADR-034): plaintext
// stored before the gateway becomes readable through it with the same content
// and headers, in both cases -- names in clear and encrypted -- a client's write
// during the run survives, a second run changes nothing, and a provider that
// ignores the condition is refused.

// putPlain stores an object at the provider directly, past the gateway, as an
// application did before the gateway was put in front of the bucket.
func putPlain(t *testing.T, h *proxytest.Harness, key string, body []byte, contentType string,
	metadata map[string]string,
) {
	t.Helper()
	if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key, Body: bytes.NewReader(body), ContentLength: int64(len(body)),
		ContentType: contentType, ContentDisposition: `attachment; filename="report.pdf"`,
		ContentLanguage: "de", Metadata: metadata,
	}); err != nil {
		t.Fatalf("PUT %q at the provider: %v", key, err)
	}
}

// config is a run guarded where the provider enforces the condition the case
// needs, and unconditional where it does not, for the tests about something
// other than the guard.
func config(t *testing.T, h *proxytest.Harness, prefix string, guarded bool) encrypt.Config {
	t.Helper()
	return encrypt.Config{
		Upstream: h.Upstream, Keys: h.Keyring, Bucket: proxytest.Bucket, Prefix: prefix,
		Log2ChunkSize: stream.MinLog2ChunkSize, PartSize: proxytest.TestPart,
		Concurrency: 4, Log: proxytest.DiscardLogger(), AllowUnconditional: !guarded,
	}
}

func overwriteGuarded(t *testing.T) bool {
	t.Helper()
	return testprovider.Require(t).CompleteIfMatch == "enforced"
}

func run(t *testing.T, cfg encrypt.Config) *encrypt.Result {
	t.Helper()
	result, err := encrypt.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("encrypt-existing: %v", err)
	}
	return result
}

func status(t *testing.T, h *proxytest.Harness, key string) int {
	t.Helper()
	resp := h.Do(t, http.MethodGet, key)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestIntegrationEncryptMakesPlaintextReadable is the command's purpose with
// names in clear: an object stored before the gateway is refused through it,
// and once encrypted reads back the same, with its headers and metadata --
// a small one, an empty one, and one large enough to be written in parts.
func TestIntegrationEncryptMakesPlaintextReadable(t *testing.T) {
	h := proxytest.New(t)
	prefix := proxytest.TestKey(t, "plain") + "/"
	objects := map[string][]byte{
		prefix + "small.txt": proxytest.RandomBytes(t, 5000),
		prefix + "empty":     {},
		prefix + "large.bin": proxytest.RandomBytes(t, 2*proxytest.TestPart+1234),
	}
	for key, body := range objects {
		putPlain(t, h, key, body, "application/x-test", map[string]string{"owner": "lennard"})
	}
	if got := status(t, h, prefix+"small.txt"); got != http.StatusBadGateway {
		t.Fatalf("before the run the gateway answers %d for plaintext, want 502 ObjectNotEncrypted", got)
	}

	cfg := config(t, h, prefix, overwriteGuarded(t))
	cfg.DryRun = true
	if dry := run(t, cfg); dry.Encrypted != 3 || dry.Incomplete() {
		t.Fatalf("dry run: %+v, want three to encrypt", *dry)
	}
	if got := status(t, h, prefix+"small.txt"); got != http.StatusBadGateway {
		t.Fatalf("the dry run changed an object: the gateway now answers %d", got)
	}

	cfg.DryRun = false
	result := run(t, cfg)
	if result.Encrypted != 3 || result.Incomplete() {
		t.Fatalf("got %+v, want three encrypted", *result)
	}
	if want := int64(5000 + 2*proxytest.TestPart + 1234); result.BytesEncrypted != want {
		t.Errorf("BytesEncrypted = %d, want %d", result.BytesEncrypted, want)
	}
	for key, body := range objects {
		if got := h.MustRead(t, key, "after the run"); !bytes.Equal(got, body) {
			t.Errorf("%s reads back %d bytes, not the %d stored in clear", key, len(got), len(body))
		}
	}

	resp := h.Do(t, http.MethodHead, prefix+"small.txt")
	_ = resp.Body.Close()
	for header, want := range map[string]string{
		"Content-Type":        "application/x-test",
		"Content-Disposition": `attachment; filename="report.pdf"`,
		"Content-Language":    "de",
		"x-amz-meta-owner":    "lennard",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s is %q after the run, want %q", header, got, want)
		}
	}
	if !strings.Contains(h.ObjectKID(t, prefix+"large.bin"), h.Keyring.ActiveKID()) {
		t.Error("the large object is not wrapped under the active key")
	}
	// Up to the part size, one segment and no manifest; beyond it, parts.
	for key, wantParts := range map[string]bool{prefix + "small.txt": false, prefix + "large.bin": true} {
		info, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, key)
		if err != nil {
			t.Fatalf("HEAD %q: %v", key, err)
		}
		meta, err := objectmeta.Parse(info.Metadata, stream.MinLog2ChunkSize)
		if err != nil {
			t.Fatalf("%s carries no gateway metadata: %v", key, err)
		}
		if meta.Multipart != wantParts {
			t.Errorf("%s: multipart = %v, want %v", key, meta.Multipart, wantParts)
		}
	}

	// Idempotent: a second run finds only objects the gateway wrote.
	if again := run(t, cfg); again.Skipped != 3 || again.Encrypted != 0 || again.Incomplete() {
		t.Errorf("a second run: %+v, want three skipped", *again)
	}
}

// TestIntegrationEncryptUnderEncryptedNames: with names.encrypt the object goes
// to its encrypted key, and nothing is left in clear at the provider.
func TestIntegrationEncryptUnderEncryptedNames(t *testing.T) {
	option, enc := proxytest.WithEncryptedNames(t)
	h := proxytest.New(t, option)
	key := proxytest.TestKey(t, "names.bin")
	body := proxytest.RandomBytes(t, 70000)
	putPlain(t, h, key, body, "application/octet-stream", nil)
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	h.CleanupStored(t, stored)

	cfg := config(t, h, key, testprovider.Require(t).MigrationGuarded())
	cfg.Names = enc
	if result := run(t, cfg); result.Encrypted != 1 || result.Incomplete() {
		t.Fatalf("got %+v, want one encrypted", *result)
	}
	if got := h.MustRead(t, key, "after the run"); !bytes.Equal(got, body) {
		t.Errorf("the object reads back %d bytes, not the %d stored in clear", len(got), len(body))
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, key); !upstream.NotFound(err) {
		t.Errorf("the plaintext is still stored in clear (HEAD: %v)", err)
	}
	if again := run(t, cfg); again.Scanned != 0 || again.Incomplete() {
		t.Errorf("a second run: %+v, want nothing left to look at", *again)
	}
}

// TestIntegrationEncryptKeepsAClientWrite is MCEncrypt's point: a client
// writing the key through the gateway while the run has it in flight wins, and
// the run reports the object rather than overwriting the client's version.
func TestIntegrationEncryptKeepsAClientWrite(t *testing.T) {
	if !overwriteGuarded(t) {
		t.Skip("the provider does not enforce If-Match on the completion, so a guarded run is refused")
	}
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "contested.bin")
	original, clientWrote := proxytest.RandomBytes(t, 4096), proxytest.RandomBytes(t, 8192)
	putPlain(t, h, key, original, "", nil)

	held := proxytest.NewGate()
	cfg := config(t, h, key, true)
	var once sync.Once
	cfg.Hook = func(point, _ string) {
		if point == encrypt.HookRotManifest {
			once.Do(held.Wait)
		}
	}
	done := make(chan *encrypt.Result, 1)
	errs := make(chan error, 1)
	go func() {
		result, err := encrypt.Run(t.Context(), cfg)
		done <- result
		errs <- err
	}()
	held.Await(t, "the run to have the object in flight")

	resp := h.Put(t, key, clientWrote, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the client's PUT returned %d", resp.StatusCode)
	}

	held.Open()
	if err := <-errs; err != nil {
		t.Fatalf("encrypt-existing: %v", err)
	}
	result := <-done
	if got := h.MustRead(t, key, "after the run raced a client write"); !bytes.Equal(got, clientWrote) {
		t.Fatalf("the client's write did not survive: %d bytes read, I2 violated", len(got))
	}
	if result.Conflicted != 1 || result.Encrypted != 0 {
		t.Errorf("got %+v, want the object reported as conflicted", *result)
	}
}

// TestIntegrationEncryptKeepsAClientWriteUnderEncryptedNames: with names
// encrypted, a client's write to the encrypted key during the run stands, and
// the plaintext is deleted as obsolete.
func TestIntegrationEncryptKeepsAClientWriteUnderEncryptedNames(t *testing.T) {
	if !testprovider.Require(t).MigrationGuarded() {
		t.Skip("the provider does not enforce If-None-Match on the completion, so a guarded run is refused")
	}
	option, enc := proxytest.WithEncryptedNames(t)
	h := proxytest.New(t, option)
	key := proxytest.TestKey(t, "contested-names.bin")
	original, clientWrote := proxytest.RandomBytes(t, 4096), proxytest.RandomBytes(t, 8192)
	putPlain(t, h, key, original, "", nil)
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	h.CleanupStored(t, stored)
	// The client's write must be newer by the provider's clock, which counts
	// seconds.
	time.Sleep(1100 * time.Millisecond)

	held := proxytest.NewGate()
	cfg := config(t, h, key, true)
	cfg.Names = enc
	var once sync.Once
	cfg.Hook = func(point, _ string) {
		if point == encrypt.HookMigHeadEnc {
			once.Do(held.Wait)
		}
	}
	done := make(chan *encrypt.Result, 1)
	errs := make(chan error, 1)
	go func() {
		result, err := encrypt.Run(t.Context(), cfg)
		done <- result
		errs <- err
	}()
	held.Await(t, "the run to find nothing at the encrypted key")

	resp := h.Put(t, key, clientWrote, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the client's PUT returned %d", resp.StatusCode)
	}

	held.Open()
	if err := <-errs; err != nil {
		t.Fatalf("encrypt-existing: %v", err)
	}
	result := <-done
	if got := h.MustRead(t, key, "after the run raced a client write"); !bytes.Equal(got, clientWrote) {
		t.Fatalf("the client's write did not survive: %d bytes read", len(got))
	}
	if result.Obsolete != 1 || result.Incomplete() {
		t.Errorf("got %+v, want the plaintext obsolete", *result)
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, key); !upstream.NotFound(err) {
		t.Errorf("the plaintext is still stored in clear (HEAD: %v)", err)
	}
}

// TestIntegrationEncryptRefusedWithoutTheGuard: on a provider that ignores
// If-Match on the completion, a guarded run is refused before it touches an
// object, and says what was measured and the way out.
func TestIntegrationEncryptRefusedWithoutTheGuard(t *testing.T) {
	if overwriteGuarded(t) {
		t.Skip("the provider enforces If-Match on the completion; nothing to refuse")
	}
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "unguarded.bin")
	body := proxytest.RandomBytes(t, 100)
	putPlain(t, h, key, body, "", nil)

	_, err := encrypt.Run(t.Context(), config(t, h, key, true))
	var refusal *encrypt.UnguardedError
	if !errors.As(err, &refusal) {
		t.Fatalf("Run returned %v, want an UnguardedError", err)
	}
	for _, want := range []string{"If-Match on CompleteMultipartUpload", "--allow-unconditional"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if got := status(t, h, key); got != http.StatusBadGateway {
		t.Errorf("the refused run changed the object: the gateway answers %d", got)
	}
}

// TestIntegrationEncryptLeavesGatewayObjects: what the gateway wrote is never
// rewritten, and a plaintext object next to it is.
func TestIntegrationEncryptLeavesGatewayObjects(t *testing.T) {
	h := proxytest.New(t)
	prefix := proxytest.TestKey(t, "mixed") + "/"
	h.Store(t, prefix+"gateway.bin", []byte("written through the gateway"))
	kid := h.ObjectKID(t, prefix+"gateway.bin")
	before, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, prefix+"gateway.bin")
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	putPlain(t, h, prefix+"plain.bin", []byte("written before the gateway"), "", nil)

	result := run(t, config(t, h, prefix, overwriteGuarded(t)))
	if result.Encrypted != 1 || result.Skipped != 1 || result.Incomplete() {
		t.Fatalf("got %+v, want one encrypted and one skipped", *result)
	}
	after, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, prefix+"gateway.bin")
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	if after.ETag != before.ETag || h.ObjectKID(t, prefix+"gateway.bin") != kid {
		t.Error("the run rewrote an object the gateway wrote")
	}
}
