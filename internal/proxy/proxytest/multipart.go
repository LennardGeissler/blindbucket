package proxytest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The harness runs at a 4 KiB chunk size (stream.MinLog2ChunkSize).
//
// Non-final parts are still 5 MiB, because that floor is the provider's and is
// checked on the ciphertext: MinIO and S3 both answer EntityTooSmall below it,
// whatever the gateway thinks. 5 MiB is a multiple of every permitted chunk
// size, so it satisfies the alignment rule at the same time.
const (
	TestChunk = 1 << stream.MinLog2ChunkSize
	TestPart  = 5 << 20
)

// MpuStart opens a multipart upload and returns the token the gateway issued.
func (h *Harness) MpuStart(t *testing.T, key string, headers map[string]string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL(key)+"?uploads", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateMultipartUpload returned %d: %s", resp.StatusCode, ReadBody(t, resp))
	}

	var out struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := xml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing the initiate result: %v (%s)", err, raw)
	}
	if out.UploadID == "" {
		t.Fatalf("the gateway issued no upload id: %s", raw)
	}
	t.Cleanup(func() {
		_ = h.Upstream.DeleteObject(context.Background(), Bucket, key)
	})
	return out.UploadID
}

// MpuPart uploads one part and returns its ETag.
func (h *Harness) MpuPart(t *testing.T, key, token string, number int, body []byte) (string, *http.Response) {
	t.Helper()
	target := fmt.Sprintf("%s?partNumber=%d&uploadId=%s", h.URL(key), number, URLQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}
	return resp.Header.Get("ETag"), resp
}

// MpuComplete assembles the parts.
func (h *Harness) MpuComplete(t *testing.T, key, token string, parts []CompletedPart) *http.Response {
	t.Helper()
	body, err := xml.Marshal(CompleteRequest{Parts: parts})
	if err != nil {
		t.Fatalf("marshalling the completion: %v", err)
	}
	target := fmt.Sprintf("%s?uploadId=%s", h.URL(key), URLQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	return resp
}

// MpuStore performs a whole multipart upload and fails the test if any step does.
func (h *Harness) MpuStore(t *testing.T, key string, parts [][]byte) []byte {
	t.Helper()
	token := h.MpuStart(t, key, nil)

	completed := make([]CompletedPart, 0, len(parts))
	var whole []byte
	for i, part := range parts {
		etag, resp := h.MpuPart(t, key, token, i+1, part)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("part %d returned %d: %s", i+1, resp.StatusCode, ReadBody(t, resp))
		}
		_ = resp.Body.Close()
		completed = append(completed, CompletedPart{PartNumber: i + 1, ETag: etag})
		whole = append(whole, part...)
	}

	resp := h.MpuComplete(t, key, token, completed)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", resp.StatusCode, ReadBody(t, resp))
	}
	return whole
}

// URLQueryEscape escapes the two characters of an upload token that a query
// string would otherwise misread.
func URLQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "+", "%2B"), "=", "%3D")
}

// RandomBytes returns n random bytes.
func RandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// List returns the size a listing reports for one key.
func (h *Harness) List(t *testing.T, key string) int64 {
	t.Helper()
	target := h.Server.URL + "/" + Bucket + "?list-type=2&prefix=" + key
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out upstream.ListBucketResult
	raw, _ := io.ReadAll(resp.Body)
	if err := xml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing the listing: %v (%s)", err, raw)
	}
	for _, entry := range out.Contents {
		if entry.Key == key {
			return entry.Size
		}
	}
	t.Fatalf("key %q not in the listing: %s", key, raw)
	return 0
}
