package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// partCopy issues an UploadPartCopy with any headers, for the cases mpuPartCopy
// cannot express: a source other than a key in the test bucket, or conditions.
func partCopy(
	t *testing.T, h *proxytest.Harness, key, token, source string, headers map[string]string,
) *http.Response {
	t.Helper()
	target := fmt.Sprintf("%s?partNumber=1&uploadId=%s", h.URL(key), proxytest.URLQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = 0
	req.Header.Set("X-Amz-Copy-Source", source)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("UploadPartCopy: %v", err)
	}
	return resp
}

// TestIntegrationUploadPartCopyRefusals is TestIntegrationCopyRefusals for the
// multipart copy path, which checks the same things through code of its own. A
// part copy that skipped the bucket check would let a credential read any
// bucket the gateway's upstream credentials can, by copying it into one it may.
func TestIntegrationUploadPartCopyRefusals(t *testing.T) {
	h := proxytest.New(t)
	src := proxytest.TestKey(t, "src.bin")
	h.Store(t, src, proxytest.RandomBytes(t, 3000))
	info, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, src)
	if err != nil {
		t.Fatalf("HEAD upstream: %v", err)
	}
	etag := strings.Trim(info.ETag, `"`)
	source := "/" + proxytest.Bucket + "/" + src

	foreign := proxytest.TestKey(t, "foreign.bin")
	if _, err := h.Upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: foreign, Body: strings.NewReader("not ours"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("writing the foreign object: %v", err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, foreign) })

	cases := []struct {
		name    string
		source  string
		headers map[string]string
		want    int
		code    string
	}{
		{"a bucket the credential does not have", "/other-bucket/some-key", nil,
			http.StatusForbidden, "AccessDenied"},
		{"the reserved prefix", "/" + proxytest.Bucket + "/.blindbucket/anything", nil,
			http.StatusBadRequest, "InvalidRequest"},
		{"a malformed source", "not-a-path", nil, http.StatusBadRequest, ""},
		{"a missing source", "/" + proxytest.Bucket + "/does-not-exist", nil, http.StatusNotFound, ""},
		{"an object this gateway did not write", "/" + proxytest.Bucket + "/" + foreign, nil,
			0, "ObjectNotEncrypted"},
		{"a failed if-match", source,
			map[string]string{"X-Amz-Copy-Source-If-Match": strings.Repeat("0", 32)},
			http.StatusPreconditionFailed, "PreconditionFailed"},
		{"a matching if-none-match", source,
			map[string]string{"X-Amz-Copy-Source-If-None-Match": etag},
			http.StatusPreconditionFailed, "PreconditionFailed"},
		{"a range past the end", source,
			map[string]string{"X-Amz-Copy-Source-Range": "bytes=5000-5999"},
			http.StatusRequestedRangeNotSatisfiable, "InvalidRange"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := proxytest.TestKey(t, "dst.bin")
			token := h.MpuStart(t, dst, nil)
			resp := partCopy(t, h, dst, token, tc.source, tc.headers)
			defer func() { _ = resp.Body.Close() }()
			body := proxytest.ReadBody(t, resp)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("the part copy was accepted: %s", body)
			}
			if tc.want != 0 && resp.StatusCode != tc.want {
				t.Errorf("returned %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
			if tc.code != "" && !strings.Contains(body, "<Code>"+tc.code+"</Code>") {
				t.Errorf("the error is not %s: %s", tc.code, body)
			}
		})
	}
}

// TestIntegrationUploadPartCopyIntoAnEndedUpload covers the two ways the
// destination upload can be gone: an upload id the gateway never issued, and
// one it issued for an upload that has since been aborted.
func TestIntegrationUploadPartCopyIntoAnEndedUpload(t *testing.T) {
	h := proxytest.New(t)
	src := proxytest.TestKey(t, "src.bin")
	h.Store(t, src, proxytest.RandomBytes(t, 3000))
	source := "/" + proxytest.Bucket + "/" + src

	t.Run("an upload id the gateway never issued", func(t *testing.T) {
		dst := proxytest.TestKey(t, "dst.bin")
		resp := partCopy(t, h, dst, "not-a-sealed-token", source, nil)
		defer func() { _ = resp.Body.Close() }()
		if body := proxytest.ReadBody(t, resp); resp.StatusCode != http.StatusNotFound ||
			!strings.Contains(body, "NoSuchUpload") {
			t.Errorf("returned %d: %s", resp.StatusCode, body)
		}
	})

	t.Run("an aborted upload", func(t *testing.T) {
		dst := proxytest.TestKey(t, "dst.bin")
		token := h.MpuStart(t, dst, nil)
		abort, err := http.NewRequestWithContext(t.Context(), http.MethodDelete,
			h.URL(dst)+"?uploadId="+proxytest.URLQueryEscape(token), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.Client.Do(abort)
		if err != nil {
			t.Fatalf("abort: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("abort returned %d", resp.StatusCode)
		}

		// The token still opens -- it is sealed, not looked up -- so this is
		// the provider saying the upload is gone, passed on as what it means.
		resp = partCopy(t, h, dst, token, source, nil)
		defer func() { _ = resp.Body.Close() }()
		if body := proxytest.ReadBody(t, resp); resp.StatusCode != http.StatusNotFound ||
			!strings.Contains(body, "NoSuchUpload") {
			t.Errorf("returned %d: %s", resp.StatusCode, body)
		}
	})
}

// TestIntegrationUploadPartCopySourceEdges covers the source shapes the happy
// paths do not: a multipart source that fails authentication or is asked for a
// range past its end, a single-part source whose range starts mid-object so its
// header is fetched on its own -- and checked on its own -- and an empty one.
func TestIntegrationUploadPartCopySourceEdges(t *testing.T) {
	h := proxytest.New(t)
	flipAt := func(offset int) func([]byte) []byte {
		return func(stored []byte) []byte {
			modified := append([]byte(nil), stored...)
			modified[offset] ^= 0x01
			return modified
		}
	}

	t.Run("a tampered multipart source", func(t *testing.T) {
		src := proxytest.TestKey(t, "mpu-src.bin")
		h.MpuStore(t, src, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 50_000)})
		h.RewriteUpstream(t, src, flipAt(10)) // inside the first part's header

		dst := proxytest.TestKey(t, "dst.bin")
		resp := mpuPartCopy(t, h, dst, h.MpuStart(t, dst, nil), 1, src, "")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("a multipart source that failed authentication was copied")
		}
	})

	t.Run("a tampered header under a mid-object range", func(t *testing.T) {
		src := proxytest.TestKey(t, "src.bin")
		h.Store(t, src, proxytest.RandomBytes(t, 300_000))
		h.RewriteUpstream(t, src, flipAt(10))

		dst := proxytest.TestKey(t, "dst.bin")
		resp := mpuPartCopy(t, h, dst, h.MpuStart(t, dst, nil), 1, src, "bytes=200000-299999")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("a range was copied from a source whose header failed authentication")
		}
	})

	t.Run("a range past the end of a multipart source", func(t *testing.T) {
		src := proxytest.TestKey(t, "mpu-src.bin")
		h.MpuStore(t, src, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1000)})

		dst := proxytest.TestKey(t, "dst.bin")
		resp := mpuPartCopy(t, h, dst, h.MpuStart(t, dst, nil), 1, src,
			fmt.Sprintf("bytes=%d-%d", proxytest.TestPart*3, proxytest.TestPart*3+10))
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
			t.Errorf("returned %d, want 416: %s", resp.StatusCode, proxytest.ReadBody(t, resp))
		}
	})

	// No position permits an empty part (ADR-008), so refuse it on arrival
	// without storing a part or replacing a previous, usable attempt.
	t.Run("an empty source", func(t *testing.T) {
		src := proxytest.TestKey(t, "empty.bin")
		h.Store(t, src, nil)

		dst := proxytest.TestKey(t, "dst.bin")
		token := h.MpuStart(t, dst, nil)
		resp := mpuPartCopy(t, h, dst, token, 1, src, "")
		defer func() { _ = resp.Body.Close() }()
		requireEmptyPartRefused(t, h, dst, token, resp, nil)

		small := proxytest.TestKey(t, "small.bin")
		h.Store(t, small, []byte("x"))
		etag := copyPartETag(t, h, dst, token, 1, small, "")
		before := storedParts(t, h, dst, token)
		retry := mpuPartCopy(t, h, dst, token, 1, src, "")
		defer func() { _ = retry.Body.Close() }()
		requireEmptyPartRefused(t, h, dst, token, retry, before)

		done := h.MpuComplete(t, dst, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
		defer func() { _ = done.Body.Close() }()
		if done.StatusCode != http.StatusOK {
			t.Fatalf("completion returned %d: %s", done.StatusCode, proxytest.ReadBody(t, done))
		}
		if got := getOK(t, h, dst); got != "x" {
			t.Errorf("the retained last part reads back as %q, want x", got)
		}
	})
}
