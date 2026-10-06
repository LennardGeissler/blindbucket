package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/upload"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The harness runs at a 4 KiB chunk size (stream.MinLog2ChunkSize).
//
// Non-final parts are still 5 MiB, because that floor is the provider's and is
// checked on the ciphertext: MinIO and S3 both answer EntityTooSmall below it,
// whatever the gateway thinks. 5 MiB is a multiple of every permitted chunk
// size, so it satisfies the alignment rule at the same time.
const (
	testChunk = 1 << stream.MinLog2ChunkSize
	testPart  = 5 << 20
)

// mpuStart opens a multipart upload and returns the token the gateway issued.
func (h *harness) mpuStart(t *testing.T, key string, headers map[string]string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.url(key)+"?uploads", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateMultipartUpload returned %d: %s", resp.StatusCode, readBody(t, resp))
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
		_ = h.upstream.DeleteObject(context.Background(), testBucket, key)
	})
	return out.UploadID
}

// mpuPart uploads one part and returns its ETag.
func (h *harness) mpuPart(t *testing.T, key, token string, number int, body []byte) (string, *http.Response) {
	t.Helper()
	target := fmt.Sprintf("%s?partNumber=%d&uploadId=%s", h.url(key), number, urlQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}
	return resp.Header.Get("ETag"), resp
}

// mpuComplete assembles the parts.
func (h *harness) mpuComplete(t *testing.T, key, token string, parts []completeReqPart) *http.Response {
	t.Helper()
	body, err := xml.Marshal(completeRequest{Parts: parts})
	if err != nil {
		t.Fatalf("marshalling the completion: %v", err)
	}
	target := fmt.Sprintf("%s?uploadId=%s", h.url(key), urlQueryEscape(token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	return resp
}

// mpuStore performs a whole multipart upload and fails the test if any step does.
func (h *harness) mpuStore(t *testing.T, key string, parts [][]byte) []byte {
	t.Helper()
	token := h.mpuStart(t, key, nil)

	completed := make([]completeReqPart, 0, len(parts))
	var whole []byte
	for i, part := range parts {
		etag, resp := h.mpuPart(t, key, token, i+1, part)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("part %d returned %d: %s", i+1, resp.StatusCode, readBody(t, resp))
		}
		_ = resp.Body.Close()
		completed = append(completed, completeReqPart{PartNumber: i + 1, ETag: etag})
		whole = append(whole, part...)
	}

	resp := h.mpuComplete(t, key, token, completed)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	return whole
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "+", "%2B"), "=", "%3D")
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestIntegrationMultipartRoundTrip is the milestone's core claim: a multipart
// upload through standard calls comes back byte-identical.
func TestIntegrationMultipartRoundTrip(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "object.bin")

	parts := [][]byte{
		randomBytes(t, testPart),
		randomBytes(t, testPart),
		randomBytes(t, 1234), // the last part need not be aligned
	}
	whole := h.mpuStore(t, key, parts)

	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(whole) {
		t.Fatalf("round trip changed the object: got %d bytes, want %d", len(got), len(whole))
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(whole)) {
		t.Errorf("Content-Length = %s, want %d", got, len(whole))
	}
}

// A single-part multipart upload is the shape `aws s3 cp` produces at the
// threshold, and the shape rotation reuses for every object it rewrites.
func TestIntegrationMultipartSinglePart(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "one-part.bin")

	whole := h.mpuStore(t, key, [][]byte{randomBytes(t, 5000)})

	resp := h.do(t, http.MethodGet, key)
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, whole) {
		t.Fatalf("round trip changed the object")
	}
}

// The size a HEAD and a listing report must be the plaintext size, recovered
// from the ciphertext size and the part count in the ETag suffix alone.
func TestIntegrationMultipartSizeArithmetic(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "sized.bin")

	parts := [][]byte{
		randomBytes(t, testPart), randomBytes(t, testPart), randomBytes(t, 77),
	}
	whole := h.mpuStore(t, key, parts)
	want := strconv.Itoa(len(whole))

	head := h.do(t, http.MethodHead, key)
	_ = head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", head.StatusCode)
	}
	if got := head.Header.Get("Content-Length"); got != want {
		t.Errorf("HEAD Content-Length = %s, want %s", got, want)
	}

	// The stored object really is larger, so this is a conversion and not a
	// forwarded number.
	stored, err := h.upstream.HeadObject(t.Context(), testBucket, key)
	if err != nil {
		t.Fatalf("upstream HEAD: %v", err)
	}
	if stored.ContentLength <= int64(len(whole)) {
		t.Errorf("ciphertext is %d bytes, not larger than the %d bytes of plaintext",
			stored.ContentLength, len(whole))
	}
	if !strings.Contains(stored.ETag, "-") {
		t.Errorf("upstream ETag %q carries no part count", stored.ETag)
	}

	listed := h.list(t, key)
	if listed != int64(len(whole)) {
		t.Errorf("listing reports %d bytes, want %d", listed, len(whole))
	}
}

// list returns the size a listing reports for one key.
func (h *harness) list(t *testing.T, key string) int64 {
	t.Helper()
	target := h.proxy.URL + "/" + testBucket + "?list-type=2&prefix=" + key
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.client.Do(req)
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

// Ranges on a multipart object have to cross part boundaries correctly: the
// prefix sums locate the part, and only the first part touched may start in the
// middle of a segment.
func TestIntegrationMultipartRanges(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "ranged.bin")

	parts := [][]byte{
		randomBytes(t, testPart), randomBytes(t, testPart), randomBytes(t, testPart),
		randomBytes(t, 999),
	}
	whole := h.mpuStore(t, key, parts)
	size := int64(len(whole))

	cases := []struct {
		name       string
		start, end int64
	}{
		{"the first byte", 0, 0},
		{"inside the first part", 10, 1000},
		{"the whole first part", 0, testPart - 1},
		{"across one boundary", testPart - 10, testPart + 10},
		{"starting mid-part, ending mid-part", testPart + 77, 2*testPart + 5},
		{"a whole middle part", testPart, 2*testPart - 1},
		{"exactly one chunk, mid-part", testPart + testChunk, testPart + 2*testChunk - 1},
		{"spanning every part", 1, size - 2},
		{"the whole object", 0, size - 1},
		{"the final part only", 3 * testPart, size - 1},
		{"the last byte", size - 1, size - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", tc.start, tc.end))
			resp, err := h.client.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusPartialContent {
				t.Fatalf("status = %d, want 206: %s", resp.StatusCode, readBody(t, resp))
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading the body: %v", err)
			}
			want := whole[tc.start : tc.end+1]
			if !bytes.Equal(got, want) {
				t.Fatalf("range %d-%d: got %d bytes, want %d (first difference at %d)",
					tc.start, tc.end, len(got), len(want), firstDiff(got, want))
			}
			wantRange := fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, size)
			if got := resp.Header.Get("Content-Range"); got != wantRange {
				t.Errorf("Content-Range = %q, want %q", got, wantRange)
			}
		})
	}

	// A suffix range is what `tail`-style clients send.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	req.Header.Set("Range", "bytes=-500")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, whole[size-500:]) {
		t.Errorf("suffix range returned %d wrong bytes", len(got))
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// The part size rules exist so that the plaintext size stays recoverable. A
// client that breaks them is refused at completion, with a message naming the
// fix, rather than storing an object that would list at the wrong size for ever.
func TestIntegrationMultipartRejectsUnalignedParts(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "unaligned.bin")
	token := h.mpuStart(t, key, nil)

	// A non-final part that is not a multiple of the chunk size. It is over the
	// provider's own 5 MiB floor, so the refusal comes from the gateway's rules
	// and not from the upstream.
	etag1, resp1 := h.mpuPart(t, key, token, 1, randomBytes(t, testPart+1))
	_ = resp1.Body.Close()
	etag2, resp2 := h.mpuPart(t, key, token, 2, randomBytes(t, 100))
	_ = resp2.Body.Close()

	resp := h.mpuComplete(t, key, token, []completeReqPart{
		{PartNumber: 1, ETag: etag1}, {PartNumber: 2, ETag: etag2},
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "InvalidRequest") {
		t.Errorf("error code missing from %s", body)
	}
	// The message has to say what to change, because a part size setting is the
	// only thing the client can do about it.
	if !strings.Contains(body, "multiple of the chunk size") {
		t.Errorf("the error does not name the fix: %s", body)
	}
	if _, err := h.upstream.HeadObject(t.Context(), testBucket, key); err == nil {
		t.Error("the object became visible despite the refused completion")
	}
}

func TestIntegrationMultipartRejectsEmptyLastPart(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "empty-last.bin")
	token := h.mpuStart(t, key, nil)

	_, resp := h.mpuPart(t, key, token, 1, nil)
	defer func() { _ = resp.Body.Close() }()
	h.requireEmptyPartRefused(t, key, token, resp, nil)

	// A refused attempt must neither poison the upload nor replace a valid
	// part: even one byte can be the last part (FORMAT §7.3).
	body := []byte("x")
	etag, part := h.mpuPart(t, key, token, 1, body)
	_ = part.Body.Close()
	if part.StatusCode != http.StatusOK {
		t.Fatalf("nonempty part returned %d", part.StatusCode)
	}
	before := h.storedParts(t, key, token)
	_, retry := h.mpuPart(t, key, token, 1, nil)
	defer func() { _ = retry.Body.Close() }()
	h.requireEmptyPartRefused(t, key, token, retry, before)

	done := h.mpuComplete(t, key, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	defer func() { _ = done.Body.Close() }()
	if done.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", done.StatusCode, readBody(t, done))
	}
	if got := h.getOK(t, key); got != string(body) {
		t.Errorf("the retained last part reads back as %q, want %q", got, body)
	}
}

// storedParts observes the provider directly so an early refusal cannot hide a
// part that was stored anyway, or an existing attempt that was overwritten.
func (h *harness) storedParts(t *testing.T, key, token string) []upstream.Part {
	t.Helper()
	opened, err := upload.Open(t.Context(), h.keyring, token, testBucket, key)
	if err != nil {
		t.Fatalf("opening upload token: %v", err)
	}
	parts, err := h.upstream.ListParts(t.Context(), testBucket, key, opened.UploadID)
	if err != nil {
		t.Fatalf("listing upstream parts: %v", err)
	}
	return parts
}

func (h *harness) requireEmptyPartRefused(
	t *testing.T, key, token string, resp *http.Response, before []upstream.Part,
) {
	t.Helper()
	var out struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty part returned %d, want 400: %s", resp.StatusCode, body)
	}
	if err := xml.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("parsing part refusal: %v: %s", err, body)
	}
	want := manifest.ErrPartRules.Error() + ": the last part is empty"
	if out.Code != "InvalidRequest" || out.Message != want {
		t.Fatalf("empty part returned %d: %s; want 400 InvalidRequest: %s", resp.StatusCode, body, want)
	}
	if after := h.storedParts(t, key, token); !slices.Equal(after, before) {
		t.Errorf("refused part changed upstream parts: before %v, after %v", before, after)
	}
	h.absentUpstream(t, key)
}

// Every operation is bound to the object its token was issued for. A token
// obtained for a key the client may write must not work against another one.
func TestIntegrationMultipartTokenIsBoundToTheObject(t *testing.T) {
	h := newHarness(t)
	mine := testKey(t, "mine.bin")
	other := testKey(t, "other.bin")
	token := h.mpuStart(t, mine, nil)

	_, resp := h.mpuPart(t, other, token, 1, randomBytes(t, 100))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a token was accepted for another key: status %d", resp.StatusCode)
	}
	if !strings.Contains(readBody(t, resp), "NoSuchUpload") {
		t.Error("expected NoSuchUpload for a token used against the wrong key")
	}
}

func TestIntegrationMultipartRejectsForgedTokens(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "forged.bin")
	genuine := h.mpuStart(t, key, nil)

	middle := len(genuine) / 2
	forged := []string{
		"not-a-token",
		"",
		strings.Repeat("A", 200),
		// A single flipped character inside a real token. The last character is
		// deliberately not the one flipped: base64 hides unused trailing bits, so
		// changing it can decode to the very same token.
		genuine[:middle] + flipChar(genuine[middle]) + genuine[middle+1:],
		// A real token truncated.
		genuine[:len(genuine)-4],
	}
	for _, token := range forged {
		t.Run(fmt.Sprintf("%.12q", token), func(t *testing.T) {
			_, resp := h.mpuPart(t, key, token, 1, randomBytes(t, 50))
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				t.Fatal("a forged token was accepted")
			}
		})
	}
}

func flipChar(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

// An upload whose parts were never uploaded cannot be completed by naming them.
func TestIntegrationMultipartRejectsUnknownParts(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "unknown-part.bin")
	token := h.mpuStart(t, key, nil)

	etag, resp := h.mpuPart(t, key, token, 1, randomBytes(t, testPart))
	_ = resp.Body.Close()

	done := h.mpuComplete(t, key, token, []completeReqPart{
		{PartNumber: 1, ETag: etag},
		{PartNumber: 7, ETag: `"deadbeefdeadbeefdeadbeefdeadbeef"`},
	})
	defer func() { _ = done.Body.Close() }()
	if done.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", done.StatusCode, readBody(t, done))
	}
	if !strings.Contains(readBody(t, done), "InvalidPart") {
		t.Error("expected InvalidPart")
	}
}

func TestIntegrationMultipartRejectsDescendingParts(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "descending.bin")
	token := h.mpuStart(t, key, nil)

	e1, r1 := h.mpuPart(t, key, token, 1, randomBytes(t, testPart))
	_ = r1.Body.Close()
	e2, r2 := h.mpuPart(t, key, token, 2, randomBytes(t, 10))
	_ = r2.Body.Close()

	done := h.mpuComplete(t, key, token, []completeReqPart{
		{PartNumber: 2, ETag: e2}, {PartNumber: 1, ETag: e1},
	})
	defer func() { _ = done.Body.Close() }()
	if done.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", done.StatusCode, readBody(t, done))
	}
}

// Aborting releases the upload, and the token stops working.
func TestIntegrationMultipartAbort(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "aborted.bin")
	token := h.mpuStart(t, key, nil)

	_, resp := h.mpuPart(t, key, token, 1, randomBytes(t, testPart))
	_ = resp.Body.Close()

	target := fmt.Sprintf("%s?uploadId=%s", h.url(key), urlQueryEscape(token))
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodDelete, target, nil)
	abort, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("abort: %v", err)
	}
	_ = abort.Body.Close()
	if abort.StatusCode != http.StatusNoContent {
		t.Fatalf("abort returned %d", abort.StatusCode)
	}

	// The token is still cryptographically valid -- aborting does not invalidate
	// it -- so what refuses the part is the upstream, and the client has to hear
	// why. Reporting the pipe error that follows from closing the body instead
	// would say IncompleteBody, which tells a client to retry something that can
	// never succeed.
	_, after := h.mpuPart(t, key, token, 2, randomBytes(t, 10))
	defer func() { _ = after.Body.Close() }()
	if after.StatusCode != http.StatusNotFound {
		t.Errorf("a part after the abort returned %d, want 404", after.StatusCode)
	}
	if body := readBody(t, after); !strings.Contains(body, "NoSuchUpload") {
		t.Errorf("expected NoSuchUpload, got %s", body)
	}
	if _, err := h.upstream.HeadObject(t.Context(), testBucket, key); err == nil {
		t.Error("an aborted upload produced a visible object")
	}
}

// ListParts reports plaintext sizes, not the stored ciphertext sizes.
func TestIntegrationMultipartListParts(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "list-parts.bin")
	token := h.mpuStart(t, key, nil)

	sizes := []int{testPart, testPart}
	for i, size := range sizes {
		_, resp := h.mpuPart(t, key, token, i+1, randomBytes(t, size))
		_ = resp.Body.Close()
	}

	target := fmt.Sprintf("%s?uploadId=%s", h.url(key), urlQueryEscape(token))
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListParts returned %d: %s", resp.StatusCode, readBody(t, resp))
	}

	var out listPartsResult
	raw, _ := io.ReadAll(resp.Body)
	if err := xml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing: %v (%s)", err, raw)
	}
	if len(out.Parts) != len(sizes) {
		t.Fatalf("got %d parts, want %d", len(out.Parts), len(sizes))
	}
	for i, part := range out.Parts {
		if part.Size != int64(sizes[i]) {
			t.Errorf("part %d: size %d, want %d (a ciphertext size leaked)",
				part.PartNumber, part.Size, sizes[i])
		}
	}
}

// The manifest lives under the reserved prefix, so a client must not be able to
// see it in a listing or delete it. Deleting one would make the object
// unreadable, which is the failure I1 exists to prevent.
func TestIntegrationManifestIsNotReachableByClients(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "protected.bin")
	h.mpuStore(t, key, [][]byte{randomBytes(t, testPart), randomBytes(t, 10)})

	stored, err := h.upstream.HeadObject(t.Context(), testBucket, key)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	var manifestKey string
	for name, value := range stored.Metadata {
		if strings.EqualFold(name, "bb-mid") {
			id, err := manifest.ParseID(value)
			if err != nil {
				t.Fatalf("bb-mid is unreadable: %v", err)
			}
			manifestKey = id.ObjectKey(key)
		}
	}
	if manifestKey == "" {
		t.Fatal("the object carries no bb-mid")
	}
	t.Cleanup(func() {
		_ = h.upstream.DeleteObject(context.Background(), testBucket, manifestKey)
	})

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodHead} {
		resp := h.do(t, method, manifestKey)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s on the manifest returned %d, want 403", method, resp.StatusCode)
		}
	}

	// And it must not show up in an ordinary listing.
	target := h.proxy.URL + "/" + testBucket + "?list-type=2&prefix=.blindbucket/"
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if body := readBody(t, resp); strings.Contains(body, ".blindbucket/m/") {
		t.Errorf("a manifest appeared in a listing: %s", body)
	}
}
