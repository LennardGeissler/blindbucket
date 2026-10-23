package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/prometheus/client_golang/prometheus"
)

func TestIntegrationRoundTrip(t *testing.T) {
	h := proxytest.New(t)

	for _, size := range []int{0, 1, 4095, 4096, 4097, 100_000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			key := proxytest.TestKey(t, "object.bin")
			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}
			h.Store(t, key, payload)

			// What the provider holds must be the blindbucket format, at the
			// size the arithmetic predicts -- never the plaintext.
			info, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, key)
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
			head := h.Do(t, http.MethodHead, key)
			_ = head.Body.Close()
			if head.ContentLength != int64(size) {
				t.Errorf("HEAD reports %d bytes, want %d", head.ContentLength, size)
			}
			if head.Header.Get("X-Amz-Meta-Bb-Dek") != "" {
				t.Error("the wrapped key leaked into a response to the client")
			}

			// GET returns the original bytes.
			get := h.Do(t, http.MethodGet, key)
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "secret.txt")
	secret := bytes.Repeat([]byte("TOP SECRET PAYLOAD "), 500)
	h.Store(t, key, secret)

	get, err := h.Upstream.GetObject(context.Background(), upstream.GetObjectInput{
		Bucket: proxytest.Bucket, Key: key,
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
	h := proxytest.New(t)

	t.Run("client metadata survives, gateway metadata is hidden", func(t *testing.T) {
		key := proxytest.TestKey(t, "meta.bin")
		resp := h.Put(t, key, []byte("payload"), map[string]string{
			"Content-Type":      "text/plain",
			"X-Amz-Meta-Origin": "integration-test",
			"Cache-Control":     "max-age=60",
		})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT returned %d", resp.StatusCode)
		}
		t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key) })

		head := h.Do(t, http.MethodHead, key)
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
		key := proxytest.TestKey(t, "forged.bin")
		resp := h.Put(t, key, []byte("payload"), map[string]string{
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
	h := proxytest.New(t)
	const chunk = 1 << stream.MinLog2ChunkSize

	t.Run("tampering in a later chunk aborts the response", func(t *testing.T) {
		key := proxytest.TestKey(t, "late.bin")
		payload := bytes.Repeat([]byte{0xAB}, 5*chunk)
		h.Store(t, key, payload)

		// Corrupt the third chunk, which the client only reaches after the
		// status line is already on the wire.
		h.RewriteUpstream(t, key, func(b []byte) []byte {
			b[stream.HeaderSize+2*(chunk+stream.TagSize)+9] ^= 0x01
			return b
		})

		get := h.Do(t, http.MethodGet, key)
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
		key := proxytest.TestKey(t, "early.bin")
		h.Store(t, key, bytes.Repeat([]byte{0xCD}, 3*chunk))

		h.RewriteUpstream(t, key, func(b []byte) []byte {
			b[stream.HeaderSize+5] ^= 0x01
			return b
		})

		get := h.Do(t, http.MethodGet, key)
		defer func() { _ = get.Body.Close() }()
		if get.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502 with an S3 error document", get.StatusCode)
		}
		if body := proxytest.ReadBody(t, get); !strings.Contains(body, "IntegrityCheckFailed") {
			t.Errorf("body = %q, want an IntegrityCheckFailed error", body)
		}
	})

	t.Run("truncation is detected", func(t *testing.T) {
		key := proxytest.TestKey(t, "truncated.bin")
		h.Store(t, key, bytes.Repeat([]byte{0xEF}, 3*chunk))

		h.RewriteUpstream(t, key, func(b []byte) []byte {
			return b[:stream.HeaderSize+2*(chunk+stream.TagSize)]
		})

		get := h.Do(t, http.MethodGet, key)
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
		keyA, keyB := proxytest.TestKey(t, "a.bin"), proxytest.TestKey(t, "b.bin")
		h.Store(t, keyA, bytes.Repeat([]byte{1}, 2*chunk))
		h.Store(t, keyB, bytes.Repeat([]byte{2}, 2*chunk))

		ctx := context.Background()
		get, err := h.Upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: keyB})
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
		h.RewriteUpstream(t, keyA, func([]byte) []byte { return bodyB })

		resp := h.Do(t, http.MethodGet, keyA)
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
		key := proxytest.TestKey(t, "forged-dek.bin")
		h.Store(t, key, bytes.Repeat([]byte{3}, chunk))

		ctx := context.Background()
		get, err := h.Upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: key})
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
		if _, err := h.Upstream.PutObject(ctx, upstream.PutObjectInput{
			Bucket: proxytest.Bucket, Key: key,
			Body: bytes.NewReader(stored), ContentLength: int64(len(stored)),
			Metadata: metadata,
		}); err != nil {
			t.Fatalf("writing the forged object: %v", err)
		}

		resp := h.Do(t, http.MethodGet, key)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502", resp.StatusCode)
		}
	})
}

// TestIntegrationForeignObject covers a bucket that also holds objects this
// gateway did not write.
func TestIntegrationForeignObject(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "foreign.txt")

	if _, err := h.Upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key,
		Body: strings.NewReader("written without the gateway"), ContentLength: 27,
	}); err != nil {
		t.Fatalf("PutObject upstream: %v", err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key) })

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		resp := h.Do(t, method, key)
		body := proxytest.ReadBody(t, resp)
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "transient.bin")

	resp := h.Put(t, key, []byte("payload"), nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	del := h.Do(t, http.MethodDelete, key)
	_ = del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE returned %d, want 204", del.StatusCode)
	}

	get := h.Do(t, http.MethodGet, key)
	body := proxytest.ReadBody(t, get)
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "unsupported.bin")
	h.Store(t, key, bytes.Repeat([]byte{7}, 1000))

	t.Run("object sub-resources", func(t *testing.T) {
		for _, suffix := range []string{"?acl", "?attributes", "?versionId=null"} {
			resp, err := h.Client.Get(h.URL(key) + suffix)
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
	t.Run("tagging is readable", func(t *testing.T) {
		resp, err := h.Client.Get(h.URL(key) + "?tagging")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET ?tagging returned %d, want 200", resp.StatusCode)
		}
		// Writing tags is served since ADR-037; tags_test.go has it.
	})

	// The multipart sub-resources are implemented since M4, so a malformed one
	// is a client error rather than an unimplemented feature. Both must still be
	// refused: ?partNumber without an upload id used to fall through to the
	// plain-object path, which would have stored one part as the whole object.
	t.Run("malformed multipart requests", func(t *testing.T) {
		for _, suffix := range []string{"?partNumber=1", "?uploadId="} {
			resp, err := h.Client.Get(h.URL(key) + suffix)
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
			resp, err := h.Client.Get(h.Server.URL + "/" + proxytest.Bucket + suffix)
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
		resp, err := h.Client.Get(h.Server.URL + "/" + proxytest.Bucket + "/.blindbucket/m/anything")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})

	t.Run("server-side encryption headers", func(t *testing.T) {
		resp := h.Put(t, proxytest.TestKey(t, "sse.bin"), []byte("payload"),
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "aborted.bin")

	// Declare more bytes than the body will produce.
	body := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{9}, 1000)), errReader{})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.URL(key), body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = 100000

	resp, err := h.Client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}

	if _, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, key); !upstream.NotFound(err) {
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
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "auth.bin")
	h.Store(t, key, []byte("payload"))

	unsigned := h.Unsigned

	t.Run("unsigned requests are refused", func(t *testing.T) {
		resp, err := unsigned.Get(h.URL(key))
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
			h.Server.URL+"/some-other-bucket/key", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})

	t.Run("a forged signature is refused", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Authorization",
			"AWS4-HMAC-SHA256 Credential="+proxytest.ClientAccessKey+"/"+time.Now().UTC().Format("20060102")+
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
		if body := proxytest.ReadBody(t, resp); !strings.Contains(body, "SignatureDoesNotMatch") {
			t.Errorf("body = %q, want SignatureDoesNotMatch", body)
		}
	})
}

// TestIntegrationRangeRequests covers the mapping from plaintext ranges onto
// ciphertext chunks, end to end through a real provider.
func TestIntegrationRangeRequests(t *testing.T) {
	h := proxytest.New(t)
	const chunk = 1 << stream.MinLog2ChunkSize

	key := proxytest.TestKey(t, "ranged.bin")
	payload := make([]byte, 5*chunk+123)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	h.Store(t, key, payload)
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
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Header.Set("Range", tc.spec)

			resp, err := h.Client.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusPartialContent {
				t.Fatalf("status %d, want 206: %s", resp.StatusCode, proxytest.ReadBody(t, resp))
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
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Header.Set("Range", spec)
			resp, err := h.Client.Do(req)
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
		tampered := proxytest.TestKey(t, "range-tampered.bin")
		h.Store(t, tampered, payload)
		h.RewriteUpstream(t, tampered, func(b []byte) []byte {
			b[stream.HeaderSize+2*(chunk+stream.TagSize)+11] ^= 0x01
			return b
		})

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(tampered), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", 2*chunk, 2*chunk+50))
		resp, err := h.Client.Do(req)
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

// TestIntegrationGzipEncodedObjectReadsBack: an object a client stores with
// Content-Encoding: gzip -- a pre-compressed web asset, say -- reads back whole
// through the gateway, with its header, and verifies under scrub. The provider
// returns the stored Content-Encoding on every GET, and a transport that took it
// for its own would gunzip the ciphertext; every read of such an object failed
// with 502 IntegrityCheckFailed and counted as an integrity failure (#110).
// Content-Encoding: br, which the rotation tests store, never showed it: Go
// decompresses only the gzip it asked for itself.
func TestIntegrationGzipEncodedObjectReadsBack(t *testing.T) {
	reg := prometheus.NewRegistry()
	h := proxytest.New(t, func(cfg *proxy.Config) { cfg.Metrics = obs.NewMetrics(reg, obs.MetricsConfig{}) })
	prefix := proxytest.ScrubPrefix(t)
	key := prefix + "page.html.gz"

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(bytes.Repeat([]byte("<p>blindbucket</p>\n"), 2000)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	plaintext := compressed.Bytes()

	resp := h.Put(t, key, plaintext, map[string]string{
		"Content-Type": "text/html", "Content-Encoding": "gzip",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}
	h.CleanupStored(t, key)

	// The client's own transport would gunzip the response just as the
	// gateway's did; asking for identity keeps the bytes as stored.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	got, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = got.Body.Close() }()
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if got.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", got.StatusCode, body)
	}
	if !bytes.Equal(body, plaintext) {
		t.Errorf("GET returned %d bytes that differ from the %d stored", len(body), len(plaintext))
	}
	if enc := got.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", enc)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	// Every kind is registered at zero, so it is the counts that must stay zero.
	for _, family := range families {
		if family.GetName() != "blindbucket_integrity_failures_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			if m.GetCounter().GetValue() != 0 {
				t.Errorf("an intact object counted as an integrity failure: %v", m)
			}
		}
	}

	result := h.Scrub(t, h.ScrubConfig(prefix))
	if result.Scanned != 1 || result.Verified != 1 || result.Incomplete() {
		t.Errorf("scrub: scanned %d, verified %d, failed %d, unreadable %d; want 1 verified (findings: %+v)",
			result.Scanned, result.Verified, result.Failed, result.Errors, result.Findings)
	}
}

// TestIntegrationTaggingOnAProviderWithout: the AWS CLI asks for an object's
// tags before every multipart server-side copy. Garage does not implement
// tagging, and a 502 there failed the copy; its true answer is no tags.
func TestIntegrationTaggingOnAProviderWithout(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))
	key := proxytest.TestKey(t, "tags.bin")
	// Written at the provider directly, as before the gateway: an object the
	// gateway wrote has its tags in a sidecar, and only one it did not write
	// has them asked of the provider (ADR-037).
	if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key, Body: strings.NewReader("tagged, or not"), ContentLength: 14,
	}); err != nil {
		t.Fatalf("writing the object at the provider: %v", err)
	}
	h.CleanupStored(t, key)

	// Against MinIO the request is forwarded and answered by it.
	if status, body := gatewayDo(t, h, http.MethodGet, key, "tagging"); status != http.StatusOK ||
		!strings.Contains(body, "Tagging") {
		t.Fatalf("GET ?tagging returned %d: %s", status, body)
	}

	rule := f.fail(&fault{match: objectRequest(http.MethodGet, key, "tagging"), times: 1,
		status: http.StatusNotImplemented, code: "NotImplemented"})
	status, body := gatewayDo(t, h, http.MethodGet, key, "tagging")
	if f.hits(rule) == 0 {
		t.Fatal("the fault was never reached")
	}
	if status != http.StatusOK || !strings.Contains(body, "<TagSet></TagSet>") {
		t.Errorf("a provider without tagging gave %d: %s", status, body)
	}

	// Any other failure is not dressed up as an empty tag set.
	f.fail(&fault{match: objectRequest(http.MethodGet, key, "tagging"), status: http.StatusInternalServerError})
	if status, _ := gatewayDo(t, h, http.MethodGet, key, "tagging"); status < 500 {
		t.Errorf("a failed tagging request answered %d", status)
	}
}

// TestIntegrationVersionIDIsPassedOn: on a versioned bucket the provider names
// the version it stored, and a client that asked for it must get it back.
// MinIO's test bucket is unversioned, so the header is added on its way back.
func TestIntegrationVersionIDIsPassedOn(t *testing.T) {
	f := newFaultyProvider(t)
	h := proxytest.New(t, f.option(t))

	put := proxytest.TestKey(t, "versioned.bin")
	f.fail(&fault{match: plainPut(put), setHeader: map[string]string{"x-amz-version-id": "v-put"}})
	resp := h.Put(t, put, []byte("versioned"), nil)
	_ = resp.Body.Close()
	if got := resp.Header.Get("x-amz-version-id"); got != "v-put" {
		t.Errorf("PutObject returned version %q, want v-put", got)
	}

	mpu := proxytest.TestKey(t, "versioned-mpu.bin")
	f.fail(&fault{match: objectRequest(http.MethodPost, mpu, "uploadId"),
		setHeader: map[string]string{"x-amz-version-id": "v-mpu"}})
	token := h.MpuStart(t, mpu, nil)
	etag, resp := h.MpuPart(t, mpu, token, 1, proxytest.RandomBytes(t, 1000))
	_ = resp.Body.Close()
	resp = h.MpuComplete(t, mpu, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
	_ = resp.Body.Close()
	if got := resp.Header.Get("x-amz-version-id"); got != "v-mpu" {
		t.Errorf("CompleteMultipartUpload returned version %q, want v-mpu", got)
	}
}
