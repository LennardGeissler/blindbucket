package proxy

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// lookupMeta reads one metadata value, whatever case the provider returned the
// name in.
func lookupMeta(md map[string]string, want string) string {
	for name, value := range md {
		if strings.EqualFold(name, want) {
			return value
		}
	}
	return ""
}

// copyTo issues a CopyObject from src to dst through the gateway.
func (h *harness) copyTo(t *testing.T, src, dst string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.url(dst), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = 0
	req.Header.Set("X-Amz-Copy-Source", "/"+testBucket+"/"+src)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	// Only a destination this call created: a self-copy's destination is the
	// source, and deleting it here would pull the object out from under the
	// test that stored it.
	if dst != src {
		t.Cleanup(func() {
			_ = h.upstream.DeleteObject(context.Background(), testBucket, dst)
		})
	}
	return resp
}

// copyOK copies and fails the test unless the gateway accepted it.
func (h *harness) copyOK(t *testing.T, src, dst string, headers map[string]string) copyObjectResult {
	t.Helper()
	resp := h.copyTo(t, src, dst, headers)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("copy returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	var out copyObjectResult
	if err := xml.Unmarshal([]byte(readBody(t, resp)), &out); err != nil {
		t.Fatalf("parsing the copy result: %v", err)
	}
	if out.ETag == "" {
		t.Error("the copy result carries no ETag")
	}
	return out
}

// getOK reads an object back through the gateway and requires 200.
//
// It reads the whole body rather than using readBody, which caps at 4 KiB
// because it exists for error documents.
func (h *harness) getOK(t *testing.T, key string) string {
	t.Helper()
	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d: %s", key, resp.StatusCode, readBody(t, resp))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", key, err)
	}
	return string(body)
}

// storedMeta reads blindbucket's own metadata straight off the provider.
func (h *harness) storedMeta(t *testing.T, key string) objectmeta.Meta {
	t.Helper()
	info, err := h.upstream.HeadObject(context.Background(), testBucket, key)
	if err != nil {
		t.Fatalf("HEAD %s upstream: %v", key, err)
	}
	meta, err := objectmeta.Parse(info.Metadata, 12)
	if err != nil {
		t.Fatalf("parsing the metadata of %s: %v", key, err)
	}
	return meta
}

// TestIntegrationCopySinglePart is the operation's core claim: the copy reads
// back as the original, and the original is untouched.
func TestIntegrationCopySinglePart(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	body := strings.Repeat("copy me, the provider never sees this. ", 500)
	h.store(t, src, []byte(body))

	h.copyOK(t, src, dst, nil)

	if got := h.getOK(t, dst); got != body {
		t.Errorf("the copy differs from the source (%d vs %d bytes)", len(got), len(body))
	}
	if got := h.getOK(t, src); got != body {
		t.Errorf("the source changed during the copy")
	}
}

// TestIntegrationCopyRewrapsTheDataKey is the security claim, and the reason a
// copy cannot be a plain server-side copy.
//
// The wrapped key is associated data-bound to the object's bucket and key
// (FORMAT §6.1). A copy that moved the metadata verbatim would produce an
// object whose key cannot be unwrapped where it now lives -- and would only
// fail at the next read. Two checks: the destination's wrapped key is not the
// source's, and pasting the source's back over it makes the object unreadable.
func TestIntegrationCopyRewrapsTheDataKey(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	body := strings.Repeat("rewrap me. ", 400)
	h.store(t, src, []byte(body))
	h.copyOK(t, src, dst, nil)

	srcMeta, dstMeta := h.storedMeta(t, src), h.storedMeta(t, dst)
	if string(srcMeta.WrappedDEK) == string(dstMeta.WrappedDEK) {
		t.Fatal("the copy carries the source's wrapped key verbatim; it was not re-wrapped")
	}

	// The provider now swaps the destination's wrapped key for the source's.
	// Both are genuine keys this gateway wrote, and they unwrap to the same data
	// key -- but each only under its own object's identity.
	ctx := context.Background()
	info, err := h.upstream.HeadObject(ctx, testBucket, dst)
	if err != nil {
		t.Fatalf("HEAD upstream: %v", err)
	}
	get, err := h.upstream.GetObject(ctx, upstream.GetObjectInput{Bucket: testBucket, Key: dst})
	if err != nil {
		t.Fatalf("GET upstream: %v", err)
	}
	stored, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatalf("reading the stored object: %v", err)
	}

	srcInfo, err := h.upstream.HeadObject(ctx, testBucket, src)
	if err != nil {
		t.Fatalf("HEAD source upstream: %v", err)
	}
	swapped := map[string]string{}
	for name, value := range info.Metadata {
		if strings.EqualFold(name, "bb-dek") {
			value = lookupMeta(srcInfo.Metadata, "bb-dek")
		}
		swapped[name] = value
	}
	if _, err := h.upstream.PutObject(ctx, upstream.PutObjectInput{
		Bucket: testBucket, Key: dst,
		Body: strings.NewReader(string(stored)), ContentLength: int64(len(stored)),
		Metadata: swapped,
	}); err != nil {
		t.Fatalf("writing the swapped object: %v", err)
	}

	resp := h.do(t, http.MethodGet, dst)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the gateway served an object whose wrapped key belongs to a different key; " +
			"the associated-data binding is not doing anything")
	}
}

// TestIntegrationCopyMultipart copies an object made of several parts.
//
// The part boundaries have to survive: the destination gets its own manifest
// under a new id (rule R1), and the size arithmetic reads the part count off the
// ETag suffix, so a copy flattened into one part would report the wrong size.
func TestIntegrationCopyMultipart(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	parts := [][]byte{
		randomBytes(t, testPart),
		randomBytes(t, testPart),
		randomBytes(t, 4321), // the last part need not be aligned
	}
	whole := h.mpuStore(t, src, parts)
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, src) })

	h.copyOK(t, src, dst, nil)

	srcMeta, dstMeta := h.storedMeta(t, src), h.storedMeta(t, dst)
	if !dstMeta.Multipart {
		t.Fatal("the copy of a multipart object is not multipart")
	}
	if srcMeta.ManifestID == dstMeta.ManifestID {
		t.Error("the copy reuses the source's manifest id; rule R1 says it mints a new one")
	}

	if got := h.getOK(t, dst); got != string(whole) {
		t.Errorf("the copy differs from the source (%d vs %d bytes)", len(got), len(whole))
	}
	// The listing reports plaintext sizes, which for a multipart object is
	// recovered from the ETag suffix and the part count.
	if size := h.list(t, dst); size != int64(len(whole)) {
		t.Errorf("the listing reports %d bytes for the copy, want %d", size, len(whole))
	}
}

// TestIntegrationCopyMovesNoData is the reason to do this inside the provider
// at all: the bytes never travel through the gateway.
func TestIntegrationCopyMovesNoData(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	const size = 600_000
	h.store(t, src, randomBytes(t, size))

	counter := &countingTransport{base: http.DefaultTransport}
	meteredCfg := upstreamConfig(t)
	meteredCfg.HTTPClient = &http.Client{Transport: counter}
	metered, err := upstream.New(meteredCfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	h.gateway.upstream = metered

	h.copyOK(t, src, dst, nil)

	moved := counter.bytes.Load()
	// Generous on purpose: the point is the order of magnitude. A copy that read
	// and rewrote the body would move at least `size` bytes twice.
	if moved > size/50 {
		t.Errorf("the copy moved %d bytes for a %d byte object; it is copying data",
			moved, size)
	}
	t.Logf("copied a %d byte object while moving %d bytes over the wire", size, moved)
}

// TestIntegrationCopyMetadataDirective covers both directives, including the
// self-copy that S3 clients use to rewrite metadata in place.
func TestIntegrationCopyMetadataDirective(t *testing.T) {
	h := newHarness(t)
	src := testKey(t, "src.bin")
	body := []byte("metadata directives")

	resp := h.put(t, src, body, map[string]string{
		"X-Amz-Meta-Origin": "the-source",
		"Content-Type":      "text/plain",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, src) })

	t.Run("COPY keeps the source's metadata", func(t *testing.T) {
		dst := testKey(t, "copied.bin")
		h.copyOK(t, src, dst, nil)

		head := h.do(t, http.MethodHead, dst)
		defer func() { _ = head.Body.Close() }()
		if got := head.Header.Get("x-amz-meta-origin"); got != "the-source" {
			t.Errorf("user metadata is %q after a COPY, want %q", got, "the-source")
		}
		if got := head.Header.Get("Content-Type"); got != "text/plain" {
			t.Errorf("content type is %q after a COPY, want text/plain", got)
		}
	})

	t.Run("REPLACE takes the request's metadata", func(t *testing.T) {
		dst := testKey(t, "replaced.bin")
		h.copyOK(t, src, dst, map[string]string{
			"X-Amz-Metadata-Directive": "REPLACE",
			"X-Amz-Meta-Origin":        "the-request",
			"Content-Type":             "application/octet-stream",
		})

		head := h.do(t, http.MethodHead, dst)
		defer func() { _ = head.Body.Close() }()
		if got := head.Header.Get("x-amz-meta-origin"); got != "the-request" {
			t.Errorf("user metadata is %q after a REPLACE, want %q", got, "the-request")
		}
		if got := h.getOK(t, dst); got != string(body) {
			t.Error("REPLACE changed the object's content")
		}
	})

	t.Run("a self-copy needs REPLACE", func(t *testing.T) {
		resp := h.copyTo(t, src, src, nil)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("a self-copy without REPLACE returned %d, want 400", resp.StatusCode)
		}
	})

	t.Run("a self-copy with REPLACE rewrites metadata in place", func(t *testing.T) {
		resp := h.copyTo(t, src, src, map[string]string{
			"X-Amz-Metadata-Directive": "REPLACE",
			"X-Amz-Meta-Origin":        "rewritten",
		})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a self-copy with REPLACE returned %d: %s", resp.StatusCode, readBody(t, resp))
		}

		head := h.do(t, http.MethodHead, src)
		defer func() { _ = head.Body.Close() }()
		if got := head.Header.Get("x-amz-meta-origin"); got != "rewritten" {
			t.Errorf("user metadata is %q after an in-place REPLACE, want %q", got, "rewritten")
		}
		// The object has to survive its own metadata being rewritten: the wrap
		// is bound to bucket and key, neither of which a self-copy changes.
		if got := h.getOK(t, src); got != string(body) {
			t.Error("an in-place metadata rewrite damaged the object")
		}
	})
}

// TestIntegrationCopyConditions covers the x-amz-copy-source-if-* preconditions.
func TestIntegrationCopyConditions(t *testing.T) {
	h := newHarness(t)
	src := testKey(t, "src.bin")
	h.store(t, src, []byte("conditional"))

	info, err := h.upstream.HeadObject(context.Background(), testBucket, src)
	if err != nil {
		t.Fatalf("HEAD upstream: %v", err)
	}
	etag := strings.Trim(info.ETag, `"`)

	cases := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"matching if-match", map[string]string{"X-Amz-Copy-Source-If-Match": etag}, http.StatusOK},
		{"wrong if-match", map[string]string{
			"X-Amz-Copy-Source-If-Match": "00000000000000000000000000000000",
		}, http.StatusPreconditionFailed},
		{"matching if-none-match", map[string]string{
			"X-Amz-Copy-Source-If-None-Match": etag,
		}, http.StatusPreconditionFailed},
		{"unmodified since the epoch", map[string]string{
			"X-Amz-Copy-Source-If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT",
		}, http.StatusPreconditionFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.copyTo(t, src, testKey(t, "dst.bin"), tc.header)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("returned %d, want %d: %s", resp.StatusCode, tc.want, readBody(t, resp))
			}
		})
	}
}

// TestIntegrationCopyRefusals covers the sources a copy must not accept.
func TestIntegrationCopyRefusals(t *testing.T) {
	h := newHarness(t)
	src := testKey(t, "src.bin")
	h.store(t, src, []byte("refusals"))

	cases := []struct {
		name   string
		source string
		want   int
	}{
		{"a bucket the credential does not have", "/other-bucket/some-key", http.StatusForbidden},
		{"the reserved prefix", "/" + testBucket + "/.blindbucket/anything", http.StatusBadRequest},
		{"a malformed source", "not-a-path", http.StatusBadRequest},
		{"a versioned source", "/" + testBucket + "/" + src + "?versionId=abc", http.StatusNotImplemented},
		{"a missing source", "/" + testBucket + "/does-not-exist", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
				h.url(testKey(t, "dst.bin")), nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.ContentLength = 0
			req.Header.Set("X-Amz-Copy-Source", tc.source)
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatalf("copy: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("returned %d, want %d: %s", resp.StatusCode, tc.want, readBody(t, resp))
			}
		})
	}
}

// TestIntegrationCopyRefusesForeignSource: an object this gateway did not write
// has no wrapped key, so a copy of it would produce something unreadable.
func TestIntegrationCopyRefusesForeignSource(t *testing.T) {
	h := newHarness(t)
	src := testKey(t, "foreign.bin")

	if _, err := h.upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: testBucket, Key: src,
		Body: strings.NewReader("not ours"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("writing the foreign object: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, src) })

	resp := h.copyTo(t, src, testKey(t, "dst.bin"), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the gateway copied an object it did not write")
	}
}

// mpuPartCopy fills one part of an open upload from a range of another object.
func (h *harness) mpuPartCopy(
	t *testing.T, key, token string, number int, srcKey, rangeSpec string,
) *http.Response {
	t.Helper()
	target := fmt.Sprintf("%s?partNumber=%d&uploadId=%s", h.url(key), number, urlQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = 0
	req.Header.Set("X-Amz-Copy-Source", "/"+testBucket+"/"+srcKey)
	if rangeSpec != "" {
		req.Header.Set("X-Amz-Copy-Source-Range", rangeSpec)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("UploadPartCopy: %v", err)
	}
	return resp
}

// copyPartETag issues an UploadPartCopy and returns the ETag from its body.
func (h *harness) copyPartETag(
	t *testing.T, key, token string, number int, srcKey, rangeSpec string,
) string {
	t.Helper()
	resp := h.mpuPartCopy(t, key, token, number, srcKey, rangeSpec)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UploadPartCopy part %d returned %d: %s", number, resp.StatusCode, readBody(t, resp))
	}
	var out copyPartResult
	if err := xml.Unmarshal([]byte(readBody(t, resp)), &out); err != nil {
		t.Fatalf("parsing the copy part result: %v", err)
	}
	if out.ETag == "" {
		t.Fatalf("part %d came back with no ETag", number)
	}
	return out.ETag
}

// TestIntegrationUploadPartCopy is what `aws s3 cp s3://a s3://b` does above the
// CLI's 8 MiB threshold: a multipart upload whose parts are ranges of another
// object.
//
// Unlike CopyObject the bytes do travel through the gateway, because a part is
// a segment with its own salt and its own chunk counters -- the destination's
// ciphertext cannot be the source's. What must hold is that the plaintext comes
// back identical.
func TestIntegrationUploadPartCopy(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	// Two aligned parts and a short remainder, which is the shape the part-size
	// rules allow (FORMAT §7.3).
	body := randomBytes(t, testPart*2+4321)
	h.store(t, src, body)

	token := h.mpuStart(t, dst, nil)
	parts := []struct{ first, last int }{
		{0, testPart - 1},
		{testPart, testPart*2 - 1},
		{testPart * 2, len(body) - 1},
	}
	completed := make([]completeReqPart, 0, len(parts))
	for i, part := range parts {
		etag := h.copyPartETag(t, dst, token, i+1, src,
			fmt.Sprintf("bytes=%d-%d", part.first, part.last))
		completed = append(completed, completeReqPart{PartNumber: i + 1, ETag: etag})
	}

	resp := h.mpuComplete(t, dst, token, completed)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", resp.StatusCode, readBody(t, resp))
	}

	if got := h.getOK(t, dst); got != string(body) {
		t.Errorf("the copied object differs from the source (%d vs %d bytes)", len(got), len(body))
	}
	if size := h.list(t, dst); size != int64(len(body)) {
		t.Errorf("the listing reports %d bytes, want %d", size, len(body))
	}

	// The destination is its own object under its own data key, which is the
	// point of re-encrypting rather than copying bytes.
	srcMeta, dstMeta := h.storedMeta(t, src), h.storedMeta(t, dst)
	if string(srcMeta.WrappedDEK) == string(dstMeta.WrappedDEK) {
		t.Error("the copied object shares the source's wrapped key")
	}
}

// TestIntegrationUploadPartCopyFromMultipart copies out of an object that is
// itself multipart, so the source range crosses segment boundaries the manifest
// describes.
func TestIntegrationUploadPartCopyFromMultipart(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	whole := h.mpuStore(t, src, [][]byte{
		randomBytes(t, testPart),
		randomBytes(t, testPart),
		randomBytes(t, 2048),
	})
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, src) })

	// One part covering a range that starts inside the source's first segment
	// and ends inside its second.
	const first, last = 1000, testPart + 5000
	token := h.mpuStart(t, dst, nil)
	etag := h.copyPartETag(t, dst, token, 1, src, fmt.Sprintf("bytes=%d-%d", first, last))

	resp := h.mpuComplete(t, dst, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", resp.StatusCode, readBody(t, resp))
	}

	want := string(whole[first : last+1])
	if got := h.getOK(t, dst); got != want {
		t.Errorf("the copied range differs (%d bytes vs %d)", len(got), len(want))
	}
}

// TestIntegrationUploadPartCopyWholeObject: without a range, the part is the
// whole source object.
func TestIntegrationUploadPartCopyWholeObject(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	body := randomBytes(t, 40_000)
	h.store(t, src, body)

	token := h.mpuStart(t, dst, nil)
	etag := h.copyPartETag(t, dst, token, 1, src, "")

	resp := h.mpuComplete(t, dst, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	if got := h.getOK(t, dst); got != string(body) {
		t.Errorf("the copied object differs from the source (%d vs %d bytes)", len(got), len(body))
	}
}

// TestIntegrationUploadPartCopyRefusesTamperedSource: the source is stored data,
// and copying it means reading it. A provider that changed it must not get its
// bytes laundered into a new object under a valid key.
func TestIntegrationUploadPartCopyRefusesTamperedSource(t *testing.T) {
	h := newHarness(t)
	src, dst := testKey(t, "src.bin"), testKey(t, "dst.bin")

	h.store(t, src, randomBytes(t, 20_000))
	h.rewriteUpstream(t, src, func(stored []byte) []byte {
		modified := append([]byte(nil), stored...)
		modified[len(modified)/2] ^= 0x01
		return modified
	})

	token := h.mpuStart(t, dst, nil)
	resp := h.mpuPartCopy(t, dst, token, 1, src, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the gateway copied a source that failed authentication")
	}
}
