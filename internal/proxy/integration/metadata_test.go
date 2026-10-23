package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// forgedDEK is a reserved key a client must not be able to set: the gateway
// reads bb-dek back to unwrap an object's data key (docs/FORMAT.md section 6.3),
// so a client that could write it could point an object it may write at the
// wrapped key of one it may not.
const forgedDEK = "X-Amz-Meta-Bb-Dek"

// TestIntegrationReservedMetadataIsRefusedOnEveryWritePath walks every path that
// takes client metadata and requires each to refuse a bb-* key through the
// gateway: PutObject, CopyObject with x-amz-metadata-directive: REPLACE, and
// CreateMultipartUpload. All three call clientMetadata; until #91 only the
// first was covered, and mergeMetadata writing the gateway's fields last is not
// the guarantee -- it overwrites a bb- field the gateway sets on that object,
// and not one it does not.
//
// Every case has a positive control: the same request with an ordinary
// x-amz-meta-origin must succeed. Without it a 400 could come from the request
// being malformed in some other way and the test would still pass.
func TestIntegrationReservedMetadataIsRefusedOnEveryWritePath(t *testing.T) {
	h := proxytest.New(t)

	t.Run("PutObject", func(t *testing.T) {
		t.Run("the control is accepted", func(t *testing.T) {
			key := proxytest.TestKey(t, "put-ok.bin")
			h.CleanupStored(t, key)
			resp := h.Put(t, key, []byte("payload"), map[string]string{
				"X-Amz-Meta-Origin": "alice",
			})
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("PUT with ordinary metadata returned %d, want 200", resp.StatusCode)
			}
		})

		t.Run("a forged bb- key is refused and nothing is stored", func(t *testing.T) {
			key := proxytest.TestKey(t, "put-forged.bin")
			resp := h.Put(t, key, []byte("payload"), map[string]string{
				forgedDEK: "forged",
			})
			requireReserved(t, resp, "PutObject")
			wantAbsent(t, h, key)
		})
	})

	// A REPLACE copy takes its metadata from the request rather than the
	// source, which is the whole reason it reaches clientMetadata at all.
	t.Run("CopyObject with REPLACE", func(t *testing.T) {
		src := proxytest.TestKey(t, "copy-src.bin")
		body := []byte("the source")
		put := h.Put(t, src, body, map[string]string{"X-Amz-Meta-Origin": "the-source"})
		_ = put.Body.Close()
		if put.StatusCode != http.StatusOK {
			t.Fatalf("storing the source returned %d", put.StatusCode)
		}
		t.Cleanup(func() {
			_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, src)
		})

		t.Run("the control is accepted", func(t *testing.T) {
			dst := proxytest.TestKey(t, "copy-ok.bin")
			resp := copyTo(t, h, src, dst, map[string]string{
				"X-Amz-Metadata-Directive": "REPLACE",
				"X-Amz-Meta-Origin":        "the-request",
			})
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("a REPLACE copy with ordinary metadata returned %d, want 200: %s",
					resp.StatusCode, proxytest.ReadBody(t, resp))
			}
		})

		t.Run("a forged bb- key is refused and the destination is not written", func(t *testing.T) {
			dst := proxytest.TestKey(t, "copy-forged.bin")
			resp := copyTo(t, h, src, dst, map[string]string{
				"X-Amz-Metadata-Directive": "REPLACE",
				forgedDEK:                  "forged",
			})
			requireReserved(t, resp, "CopyObject with REPLACE")
			wantAbsent(t, h, dst)
		})

		t.Run("the source is untouched by the refused copy", func(t *testing.T) {
			if got := getOK(t, h, src); got != string(body) {
				t.Errorf("the source reads back %q, want %q", got, body)
			}
		})
	})

	// CreateMultipartUpload fixes an object's metadata for good: S3 records a
	// multipart object's metadata from this call and there is no way to change
	// it later, so a forged key accepted here could not be corrected.
	t.Run("CreateMultipartUpload", func(t *testing.T) {
		t.Run("the control is accepted", func(t *testing.T) {
			key := proxytest.TestKey(t, "mpu-ok.bin")
			resp := startUpload(t, h, key, map[string]string{"X-Amz-Meta-Origin": "alice"})
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("CreateMultipartUpload with ordinary metadata returned %d, want 200: %s",
					resp.StatusCode, proxytest.ReadBody(t, resp))
			}
			// Opened for real, so it has to be closed again on the provider.
			t.Cleanup(func() { abandonUploads(t, h, key) })
		})

		t.Run("a forged bb- key is refused and no upload is opened", func(t *testing.T) {
			key := proxytest.TestKey(t, "mpu-forged.bin")
			resp := startUpload(t, h, key, map[string]string{forgedDEK: "forged"})
			requireReserved(t, resp, "CreateMultipartUpload")

			// The refusal happens before the provider is asked, so there must be
			// nothing open under the key. This is what says the request was
			// stopped rather than merely answered with a 400.
			open, err := h.Upstream.ListMultipartUploads(t.Context(), proxytest.Bucket, key)
			if err != nil {
				t.Fatalf("listing the uploads open on the provider: %v", err)
			}
			if len(open) != 0 {
				t.Errorf("%d upload(s) open under %s, want none: a refused create opened one",
					len(open), key)
			}
			wantAbsent(t, h, key)
		})
	})
}

// requireReserved requires a 400 whose body says the prefix is reserved.
//
// The status alone is not enough: a client that gets a bare 400 cannot tell a
// reserved key from any other bad request, and the message is the only thing
// that tells it which header to drop.
func requireReserved(t *testing.T, resp *http.Response, path string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body := proxytest.ReadBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s returned %d, want 400: a client must not be able to set its own wrapped key (%s)",
			path, resp.StatusCode, body)
	}
	if !strings.Contains(body, "reserved") {
		t.Errorf("%s was refused with %q, want a message naming the reserved prefix", path, body)
	}
}

// startUpload issues a CreateMultipartUpload and hands back the response
// whatever it says.
//
// proxytest.MpuStart fails the test on anything but a 200, which is right for
// the happy path and no use for a refusal.
func startUpload(
	t *testing.T, h *proxytest.Harness, key string, headers map[string]string,
) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL(key)+"?uploads", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	return resp
}

// abandonUploads aborts whatever is open under key, so an accepted create does
// not leave the provider holding parts after the test.
func abandonUploads(t *testing.T, h *proxytest.Harness, key string) {
	t.Helper()
	open, err := h.Upstream.ListMultipartUploads(context.Background(), proxytest.Bucket, key)
	if err != nil {
		t.Logf("listing uploads to clean up %s: %v", key, err)
		return
	}
	for _, upload := range open {
		if err := h.Upstream.AbortMultipartUpload(
			context.Background(), proxytest.Bucket, upload.Key, upload.UploadID,
		); err != nil {
			t.Logf("aborting upload %s: %v", upload.UploadID, err)
		}
	}
}
