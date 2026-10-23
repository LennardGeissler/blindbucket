package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Presigned uploads (ADR-036): a backend hands a browser a URL to upload one
// file to. The holder of the URL is the adversary these tests play -- it is by
// design a browser nobody vouches for -- so each one sends with nothing but an
// HTTP client and tries to do more than the URL was signed for.

// uploadLimit is the max_size the tests serve uploads with.
const uploadLimit = 1 << 20

// withUploads serves presigned uploads up to limit bytes.
func withUploads(limit int64) func(*proxy.Config) {
	return func(c *proxy.Config) { c.PresignUploadMaxSize = limit }
}

// presignPut signs an upload URL. A positive length binds Content-Length, as
// boto3 and JavaScript v3 do when the backend passes ContentLength; headers are
// signed as headers, as boto3 signs everything; query rides in the URL, as
// JavaScript v3 carries x-amz-* values, and is signed with it.
func presignPut(
	t *testing.T, target string, expires time.Duration, signedAt time.Time,
	length int64, headers map[string]string, query url.Values,
) string {
	t.Helper()
	var body io.Reader
	if length > 0 {
		body = strings.NewReader(strings.Repeat("x", int(length)))
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = length
	req.Host = req.URL.Host
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	q := req.URL.Query()
	for name, values := range query {
		q[name] = values
	}
	q.Set(auth.QueryExpires, strconv.FormatInt(int64(expires.Seconds()), 10))
	req.URL.RawQuery = q.Encode()

	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	creds := aws.Credentials{AccessKeyID: proxytest.ClientAccessKey, SecretAccessKey: proxytest.ClientSecretKey}
	signed, _, err := signer.PresignHTTP(context.Background(), creds, req,
		auth.UnsignedPayload, "s3", "us-east-1", signedAt.UTC())
	if err != nil {
		t.Fatalf("PresignHTTP: %v", err)
	}
	return signed
}

// sendUpload sends body to a presigned URL, with the headers given and no signing.
func sendUpload(t *testing.T, h *proxytest.Harness, method, signed string, body []byte, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, signed, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	if len(body) == 0 {
		req.Body = http.NoBody
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := h.Unsigned.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, signed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, proxytest.ReadBody(t, resp)
}

// wantAbsent fails the test unless nothing is stored at key.
func wantAbsent(t *testing.T, h *proxytest.Harness, key string) {
	t.Helper()
	resp := h.Do(t, http.MethodHead, key)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("HEAD %s: %d, want 404 -- a refused upload stored something", key, resp.StatusCode)
	}
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// TestPresignedUploadStoresTheObjectEncrypted is the feature: a URL, a body,
// and at the provider ciphertext.
func TestPresignedUploadStoresTheObjectEncrypted(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key := proxytest.TestKey(t, "upload")
	h.CleanupStored(t, key)
	body := []byte("a file a browser uploaded, with no credential of its own")

	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), int64(len(body)), nil, nil)
	if code, msg := sendUpload(t, h, http.MethodPut, signed, body, nil); code != http.StatusOK {
		t.Fatalf("presigned PUT: %d %s", code, msg)
	}
	if got := getOK(t, h, key); got != string(body) {
		t.Fatalf("read back %q", got)
	}
	stored, err := h.Upstream.GetObject(context.Background(), upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: key})
	if err != nil {
		t.Fatalf("reading what the provider holds: %v", err)
	}
	raw, _ := io.ReadAll(stored.Body)
	_ = stored.Body.Close()
	if bytes.Contains(raw, body[:20]) {
		t.Fatal("the provider holds the plaintext")
	}
}

// TestPresignedUploadsAreRefusedUnlessASizeIsSet: no max_size, no uploads.
func TestPresignedUploadsAreRefusedUnlessASizeIsSet(t *testing.T) {
	h := proxytest.New(t, withPresign())
	key := proxytest.TestKey(t, "off")
	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 4, nil, nil)
	code, msg := sendUpload(t, h, http.MethodPut, signed, []byte("body"), nil)
	if code != http.StatusForbidden || !strings.Contains(msg, "max_size") {
		t.Fatalf("an upload with none configured: %d %s, want 403 naming max_size", code, msg)
	}
	wantAbsent(t, h, key)
}

// TestPresignedUploadOverTheLimitIsRefusedBeforeItsBody: the limit holds when
// the URL binds no length, and is judged on Content-Length.
func TestPresignedUploadOverTheLimitIsRefusedBeforeItsBody(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key := proxytest.TestKey(t, "big")
	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, nil, nil)
	code, msg := sendUpload(t, h, http.MethodPut, signed, make([]byte, uploadLimit+1), nil)
	if code != http.StatusBadRequest || !strings.Contains(msg, "EntityTooLarge") {
		t.Fatalf("an upload one byte over the limit: %d %s, want 400 EntityTooLarge", code, msg)
	}
	wantAbsent(t, h, key)

	// At the limit, it is served.
	h.CleanupStored(t, key)
	if code, msg := sendUpload(t, h, http.MethodPut, signed, make([]byte, uploadLimit), nil); code != http.StatusOK {
		t.Fatalf("an upload at the limit: %d %s", code, msg)
	}
}

// TestPresignedUploadExpiry: an upload URL has its own, shorter cap, and an
// expired one is refused like any other.
func TestPresignedUploadExpiry(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key := proxytest.TestKey(t, "expiry")
	body := []byte("late")

	expired := presignPut(t, h.URL(key), 15*time.Minute, time.Now().Add(-time.Hour), 0, nil, nil)
	if code, _ := sendUpload(t, h, http.MethodPut, expired, body, nil); code != http.StatusForbidden {
		t.Fatalf("an expired upload URL: %d, want 403", code)
	}
	// Two hours is fine for a download, under the seven-day cap, and too long
	// for an upload, under the one-hour default.
	long := presignPut(t, h.URL(key), 2*time.Hour, time.Now(), 0, nil, nil)
	// The reason is in the log only, as for every expired URL; the same URL
	// under a longer cap, below, is what shows it was the window.
	if code, msg := sendUpload(t, h, http.MethodPut, long, body, nil); code != http.StatusForbidden {
		t.Fatalf("an upload URL past the upload cap: %d %s, want 403", code, msg)
	}
	wantAbsent(t, h, key)

	h = proxytest.New(t, withPresign(func(c *auth.Config) { c.MaxPresignUploadExpiry = 3 * time.Hour }),
		withUploads(uploadLimit))
	h.CleanupStored(t, key)
	// Signed afresh: host is part of the signature, and this is another listener.
	long = presignPut(t, h.URL(key), 2*time.Hour, time.Now(), 0, nil, nil)
	if code, msg := sendUpload(t, h, http.MethodPut, long, body, nil); code != http.StatusOK {
		t.Fatalf("an upload URL within a configured cap: %d %s", code, msg)
	}
}

// TestPresignedUploadCannotBeAltered: everything the URL binds, the holder
// cannot change.
func TestPresignedUploadCannotBeAltered(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key, other := proxytest.TestKey(t, "bound"), proxytest.TestKey(t, "other")
	body := []byte("exactly this long")
	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), int64(len(body)), nil, nil)

	cases := map[string]struct {
		method, url string
		body        []byte
	}{
		"another key":           {http.MethodPut, strings.Replace(signed, "/bound?", "/other?", 1), body},
		"a longer body":         {http.MethodPut, signed, append(append([]byte{}, body...), '!')},
		"a longer window":       {http.MethodPut, strings.Replace(signed, "X-Amz-Expires=900", "X-Amz-Expires=1800", 1), body},
		"used to read":          {http.MethodGet, signed, nil},
		"used to delete":        {http.MethodDelete, signed, nil},
		"an added sub-resource": {http.MethodPut, signed + "&partNumber=1&uploadId=x", body},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.url == signed && tc.method == http.MethodPut && bytes.Equal(tc.body, body) {
				t.Fatal("the case alters nothing")
			}
			code, msg := sendUpload(t, h, tc.method, tc.url, tc.body, nil)
			if code < 400 {
				t.Fatalf("%s: %d %s, want a refusal", name, code, msg)
			}
		})
	}
	wantAbsent(t, h, key)
	wantAbsent(t, h, other)

	// And a GET URL cannot upload.
	get := presignURL(t, h, http.MethodGet, key, 15*time.Minute, time.Now())
	if code, _ := sendUpload(t, h, http.MethodPut, get, body, nil); code != http.StatusForbidden {
		t.Fatalf("a GET URL used to upload: %d, want 403", code)
	}
	wantAbsent(t, h, key)
}

// TestPresignedUploadHonoursABoundChecksum: with a checksum bound, the URL takes
// that one content, whether the checksum is signed as a header (boto3) or
// carried in the query (JavaScript v3).
func TestPresignedUploadHonoursABoundChecksum(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	want := []byte("the content the backend expected")
	wrong := []byte("something else of any length")

	for _, form := range []string{"header", "query"} {
		t.Run(form, func(t *testing.T) {
			key := proxytest.TestKey(t, "sum")
			var headers map[string]string
			var query url.Values
			if form == "header" {
				headers = map[string]string{"X-Amz-Checksum-Sha256": sha256Of(want)}
			} else {
				query = url.Values{"x-amz-checksum-sha256": {sha256Of(want)}}
			}
			signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, headers, query)

			code, msg := sendUpload(t, h, http.MethodPut, signed, wrong, headers)
			if code != http.StatusBadRequest || !strings.Contains(msg, "BadDigest") {
				t.Fatalf("another body: %d %s, want 400 BadDigest", code, msg)
			}
			wantAbsent(t, h, key)

			h.CleanupStored(t, key)
			if code, msg := sendUpload(t, h, http.MethodPut, signed, want, headers); code != http.StatusOK {
				t.Fatalf("the bound body: %d %s", code, msg)
			}
			if got := getOK(t, h, key); got != string(want) {
				t.Fatalf("read back %q", got)
			}
		})
	}
}

// TestPresignedUploadWithJavaScriptDefaults: the SDK binds the CRC32 of an
// empty body unless told otherwise, and the gateway honours it, so the URL
// takes an empty body and nothing else. Measured with v3.1152.0 (ADR-036).
func TestPresignedUploadWithJavaScriptDefaults(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key := proxytest.TestKey(t, "js")
	h.CleanupStored(t, key)
	defaults := url.Values{
		"x-amz-checksum-crc32":         {"AAAAAA=="},
		"x-amz-sdk-checksum-algorithm": {"CRC32"},
		"x-id":                         {"PutObject"},
	}
	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, nil, defaults)
	if code, msg := sendUpload(t, h, http.MethodPut, signed, []byte("a real file"), nil); code != http.StatusBadRequest ||
		!strings.Contains(msg, "BadDigest") {
		t.Fatalf("a real file under the SDK's defaults: %d %s, want 400 BadDigest", code, msg)
	}
	if code, msg := sendUpload(t, h, http.MethodPut, signed, nil, nil); code != http.StatusOK {
		t.Fatalf("an empty body under the SDK's defaults: %d %s", code, msg)
	}
}

// TestPresignedUploadCarriesQueryMetadata: x-amz-meta-* in the query is stored
// as the header would be.
func TestPresignedUploadCarriesQueryMetadata(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key := proxytest.TestKey(t, "meta")
	h.CleanupStored(t, key)
	signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, nil,
		url.Values{"x-amz-meta-owner": {"alice"}})
	if code, msg := sendUpload(t, h, http.MethodPut, signed, []byte("body"), nil); code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, msg)
	}
	head := h.Do(t, http.MethodHead, key)
	_ = head.Body.Close()
	if got := head.Header.Get("x-amz-meta-owner"); got != "alice" {
		t.Fatalf("x-amz-meta-owner reads back %q", got)
	}
}

// TestPresignedUploadRefusesWhatTheSignerDidNotChoose: an unsigned x-amz-*
// header, a value given both ways, tags, and an aws-chunked body.
func TestPresignedUploadRefusesWhatTheSignerDidNotChoose(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))
	key := proxytest.TestKey(t, "extra")

	cases := map[string]struct {
		signHeaders, sendHeaders map[string]string
		query                    url.Values
		want                     int
	}{
		"an unsigned metadata header": {
			sendHeaders: map[string]string{"X-Amz-Meta-Owner": "mallory"}, want: http.StatusForbidden,
		},
		"metadata both ways": {
			signHeaders: map[string]string{"X-Amz-Meta-Owner": "bob"},
			sendHeaders: map[string]string{"X-Amz-Meta-Owner": "bob"},
			query:       url.Values{"x-amz-meta-owner": {"alice"}}, want: http.StatusBadRequest,
		},
		"tags in the query": {
			query: url.Values{"x-amz-tagging": {"a=b"}}, want: http.StatusNotImplemented,
		},
		// A reserved key hoisted out of the query (#91). The signature covers
		// it, so the signer did choose it -- and it is still refused, because
		// hoistUploadHeaders only turns it into a header and clientMetadata
		// runs afterwards. Signing a bb-* key is not a way to set one.
		"a reserved metadata key in the query": {
			query: url.Values{"x-amz-meta-bb-kid": {"forged"}}, want: http.StatusBadRequest,
		},
		"a reserved metadata key signed as a header": {
			signHeaders: map[string]string{"X-Amz-Meta-Bb-Dek": "forged"},
			sendHeaders: map[string]string{"X-Amz-Meta-Bb-Dek": "forged"},
			want:        http.StatusBadRequest,
		},
		"an aws-chunked body": {
			sendHeaders: map[string]string{"Content-Encoding": "aws-chunked"}, want: http.StatusBadRequest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			signed := presignPut(t, h.URL(key), 15*time.Minute, time.Now(), 0, tc.signHeaders, tc.query)
			if code, msg := sendUpload(t, h, http.MethodPut, signed, []byte("body"), tc.sendHeaders); code != tc.want {
				t.Fatalf("%d %s, want %d", code, msg, tc.want)
			}
			wantAbsent(t, h, key)
		})
	}
}

// TestPresignedUploadCanBeUsedOnce: without a condition an upload URL writes as
// often as it is used, and with a signed If-None-Match: * once -- where the
// provider enforces it (#168).
func TestPresignedUploadCanBeUsedOnce(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))

	again := proxytest.TestKey(t, "again")
	h.CleanupStored(t, again)
	signed := presignPut(t, h.URL(again), 15*time.Minute, time.Now(), 0, nil, nil)
	for _, body := range []string{"first", "second"} {
		if code, msg := sendUpload(t, h, http.MethodPut, signed, []byte(body), nil); code != http.StatusOK {
			t.Fatalf("use %q: %d %s", body, code, msg)
		}
	}
	if got := getOK(t, h, again); got != "second" {
		t.Fatalf("read back %q", got)
	}

	once := proxytest.TestKey(t, "once")
	h.CleanupStored(t, once)
	only := map[string]string{"If-None-Match": "*"}
	signed = presignPut(t, h.URL(once), 15*time.Minute, time.Now(), 0, only, nil)
	if code, msg := sendUpload(t, h, http.MethodPut, signed, []byte("first"), only); code != http.StatusOK {
		t.Fatalf("the first use: %d %s", code, msg)
	}
	code, _ := sendUpload(t, h, http.MethodPut, signed, []byte("second"), only)
	wantRefused(t, h, testprovider.Require(t).PutIfNoneMatch, code, once, "first", "second")

	// Dropping the header the URL signed does not get around it.
	if code, _ := sendUpload(t, h, http.MethodPut, signed, []byte("third"), nil); code != http.StatusForbidden {
		t.Fatalf("the URL without the header it signed: %d, want 403", code)
	}
}

// TestPresignedUploadPart: the browser's multipart upload. The backend opens
// and completes it with its own credential; the browser uploads the parts by
// URL, each one under the limit, and hands the ETags back.
func TestPresignedUploadPart(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(proxytest.TestPart+proxytest.TestChunk))
	key := proxytest.TestKey(t, "parts")
	h.CleanupStored(t, key)
	token := h.MpuStart(t, key, nil)

	partURL := func(number int) string {
		return h.URL(key) + "?partNumber=" + strconv.Itoa(number) + "&uploadId=" + proxytest.URLQueryEscape(token)
	}
	upPart := func(number int, body []byte) (int, string, string) {
		t.Helper()
		signed := presignPut(t, partURL(number), 15*time.Minute, time.Now(), 0, nil, nil)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, signed, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.ContentLength = int64(len(body))
		resp, err := h.Unsigned.Do(req)
		if err != nil {
			t.Fatalf("UploadPart: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Header.Get("ETag"), proxytest.ReadBody(t, resp)
	}

	one, two := proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1000)
	code, etag1, msg := upPart(1, one)
	if code != http.StatusOK {
		t.Fatalf("part 1 by URL: %d %s", code, msg)
	}
	code, etag2, msg := upPart(2, two)
	if code != http.StatusOK {
		t.Fatalf("part 2 by URL: %d %s", code, msg)
	}
	if code, _, _ := upPart(3, make([]byte, proxytest.TestPart+proxytest.TestChunk+1)); code != http.StatusBadRequest {
		t.Fatalf("a part over the limit: %d, want 400", code)
	}

	// Completing by URL is the backend's to do, not the browser's.
	complete := presignURL(t, h, http.MethodPost, key, 15*time.Minute, time.Now())
	if code, _ := sendUpload(t, h, http.MethodPost, complete+"&uploadId="+proxytest.URLQueryEscape(token), nil, nil); code != http.StatusForbidden {
		t.Fatalf("a completion by URL: %d, want 403", code)
	}

	resp := h.MpuComplete(t, key, token, []proxytest.CompletedPart{
		{PartNumber: 1, ETag: etag1}, {PartNumber: 2, ETag: etag2},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion: %d %s", resp.StatusCode, proxytest.ReadBody(t, resp))
	}
	if got := getOK(t, h, key); got != string(one)+string(two) {
		t.Fatal("the object does not read back as its two parts")
	}
}
