package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

// withEncryptedNames turns object-name encryption on for a harness, and hands
// back the encrypter so a test can check what the provider was addressed with.
func withEncryptedNames(t *testing.T) (func(*Config), *names.Encrypter) {
	t.Helper()
	key := make([]byte, names.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	enc, err := names.New(key)
	if err != nil {
		t.Fatalf("names.New: %v", err)
	}
	return func(cfg *Config) { cfg.Names = enc }, enc
}

// TestEncryptedNamesRoundTripThroughTheGateway is the whole point of the slice:
// a client uses ordinary keys, and the provider never sees one.
func TestEncryptedNamesRoundTripThroughTheGateway(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	const key = "photos/2026/03/holiday.jpg"
	body := bytes.Repeat([]byte("blindbucket"), 4096)

	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })

	resp := h.put(t, key, body, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	// The provider holds it under the encrypted name, and under nothing else.
	if _, err := h.upstream.HeadObject(ctx, testBucket, stored); err != nil {
		t.Fatalf("the object is not at its encrypted key upstream: %v", err)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, key); err == nil {
		t.Error("the object is also stored under its plaintext key")
	}
	for _, segment := range strings.Split(key, "/") {
		if strings.Contains(stored, segment) {
			t.Errorf("the stored key %q leaks the plaintext segment %q", stored, segment)
		}
	}

	// GET, HEAD and DELETE all reach it by the plaintext key.
	get := h.do(t, http.MethodGet, key)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, body) {
		t.Errorf("GET returned %d bytes, want %d", len(got), len(body))
	}

	head := h.do(t, http.MethodHead, key)
	_ = head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", head.StatusCode)
	}

	del := h.do(t, http.MethodDelete, key)
	_ = del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", del.StatusCode)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, stored); err == nil {
		t.Error("DELETE left the object at its encrypted key")
	}
}

// TestEncryptedNamesServeRanges: a range read makes a HEAD and one or two GETs,
// and every one of them has to address the same encrypted key.
func TestEncryptedNamesServeRanges(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)

	const key = "logs/2026/app.log"
	body := make([]byte, 200_000)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, stored) })

	resp := h.put(t, key, body, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	// Deliberately far enough in that the header is not adjacent to the range,
	// which is the two-request path.
	const start, end = 150_000, 150_999
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Range", "bytes=150000-150999")
	get, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusPartialContent {
		t.Fatalf("ranged GET returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, body[start:end+1]) {
		t.Errorf("the ranged read returned the wrong %d bytes", len(got))
	}
}

// TestEncryptedNamesRefuseUnwiredOperations: the gate has to be reachable
// through the real handler, not only as a unit.
func TestEncryptedNamesRefuseUnwiredOperations(t *testing.T) {
	option, _ := withEncryptedNames(t)
	h := newHarness(t, option)

	resp := h.do(t, http.MethodGet, "?list-type=2")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("a listing returned %d, want 501: %s", resp.StatusCode, readBody(t, resp))
	}
	if body := readBody(t, resp); !strings.Contains(body, "object-name encryption") {
		t.Errorf("the refusal does not explain itself: %s", body)
	}
}

// TestPlaintextNamesAreUnchanged guards the default. With the feature off the
// provider must see exactly the key the client used, or every existing
// deployment would lose its objects on upgrade.
func TestPlaintextNamesAreUnchanged(t *testing.T) {
	h := newHarness(t)
	const key = "photos/2026/03/holiday.jpg"
	h.store(t, key, []byte("hello"))

	if _, err := h.upstream.HeadObject(context.Background(), testBucket, key); err != nil {
		t.Fatalf("with names off the object is not at its plaintext key: %v", err)
	}
}

func readBodyBytes(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return buf.Bytes()
}
