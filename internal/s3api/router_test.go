package s3api

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/auth"
)

func request(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, target, nil)
}

func TestRouteObjectOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		target string
		want   Operation
		bucket string
		key    string
	}{
		{http.MethodPut, "/bucket/key", OpPutObject, "bucket", "key"},
		{http.MethodGet, "/bucket/key", OpGetObject, "bucket", "key"},
		{http.MethodHead, "/bucket/key", OpHeadObject, "bucket", "key"},
		{http.MethodDelete, "/bucket/key", OpDeleteObject, "bucket", "key"},
		{http.MethodGet, "/bucket/deep/nested/key.txt", OpGetObject, "bucket", "deep/nested/key.txt"},
		// A percent-encoded slash names the same object as a literal one, which
		// is what S3 itself does: a key is a flat string.
		{http.MethodGet, "/bucket/a%2Fb", OpGetObject, "bucket", "a/b"},
		{http.MethodGet, "/bucket/with%20space", OpGetObject, "bucket", "with space"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			t.Parallel()
			got, err := Route(request(t, tc.method, tc.target), "")
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Op != tc.want || got.Bucket != tc.bucket || got.Key != tc.key {
				t.Errorf("got %+v, want {%s %s %s}", got, tc.want, tc.bucket, tc.key)
			}
		})
	}
}

// TestRouteRefusesSubResources is the safety property: a sub-resource must never
// be mistaken for a plain object request. Answering ?uploads as a PUT would send
// plaintext to the provider.
func TestRouteRefusesSubResources(t *testing.T) {
	t.Parallel()

	targets := []string{
		"/bucket/key?acl",
		"/bucket/key?tagging",
		"/bucket/key?versionId=null",
		"/bucket/key?attributes",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			_, err := Route(request(t, http.MethodPut, target), "")
			if err == nil {
				t.Fatal("a sub-resource was routed as a plain object request")
			}
			if err.Code != "NotImplemented" {
				t.Errorf("code = %q, want NotImplemented", err.Code)
			}
		})
	}
}

// TestRoutePassesPresignedURLsThrough. The presigning parameters used to be
// refused here alongside ?acl and ?attributes, which was right while presigned
// URLs were unimplemented and is wrong now: the router runs before the verifier,
// so refusing them would reject every presigned URL before its signature was ever
// checked (ADR-019).
//
// What must not change is the rest of that refusal. A parameter this build does
// not implement is still refused, and a presigned URL naming one is refused too --
// carrying a signature does not make ?acl implemented.
func TestRoutePassesPresignedURLsThrough(t *testing.T) {
	t.Parallel()

	const presign = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=k%2F20260916%2F" +
		"us-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260916T000000Z&X-Amz-Expires=3600" +
		"&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef"

	t.Run("a presigned object read routes as one", func(t *testing.T) {
		t.Parallel()
		got, err := Route(request(t, http.MethodGet, "/bucket/key?"+presign), "")
		if err != nil {
			t.Fatalf("a presigned GET was refused by the router: %v", err)
		}
		if got.Op != OpGetObject || got.Bucket != "bucket" || got.Key != "key" {
			t.Errorf("got %+v, want a GetObject on bucket/key", got)
		}
	})

	t.Run("a presigned listing routes as one", func(t *testing.T) {
		t.Parallel()
		got, err := Route(request(t, http.MethodGet, "/bucket?list-type=2&"+presign), "")
		if err != nil {
			t.Fatalf("a presigned listing was refused by the router: %v", err)
		}
		if got.Op != OpListObjectsV2 {
			t.Errorf("got %+v, want ListObjectsV2", got)
		}
	})

	t.Run("a signature does not make an unimplemented sub-resource implemented", func(t *testing.T) {
		t.Parallel()
		_, err := Route(request(t, http.MethodGet, "/bucket/key?acl&"+presign), "")
		if err == nil {
			t.Fatal("?acl was routed because the URL was presigned")
		}
		if err.Code != "NotImplemented" {
			t.Errorf("code = %q, want NotImplemented", err.Code)
		}
	})
}

// TestSigV2PresignedURLSaysWhatIsWrong. botocore produces one by default against
// a custom endpoint, so this is the first thing a boto3 user meets. Before the
// message existed the answer named the first unknown query parameter, which is a
// symptom nobody can act on.
func TestSigV2PresignedURLSaysWhatIsWrong(t *testing.T) {
	t.Parallel()
	const v2 = "AWSAccessKeyId=KEY&Expires=1789600000&Signature=abc%3D"

	_, err := Route(request(t, http.MethodGet, "/bucket/key?"+v2), "")
	if err == nil {
		t.Fatal("a SigV2 presigned URL was routed")
	}
	if err.Code != "InvalidRequest" {
		t.Errorf("code = %q, want InvalidRequest", err.Code)
	}
	for _, want := range []string{"SigV2", "s3v4", "AWS4-HMAC-SHA256"} {
		if !strings.Contains(err.Message, want) {
			t.Errorf("the message does not mention %q: %s", want, err.Message)
		}
	}
}

func TestRouteRefusesReservedPrefix(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
		_, err := Route(request(t, method, "/bucket/.blindbucket/m/abc/def"), "")
		if err == nil || err.Code != "AccessDenied" {
			t.Errorf("%s on the reserved prefix returned %v, want AccessDenied", method, err)
		}
	}
	// A key that merely starts with a dot is fine.
	if _, err := Route(request(t, http.MethodGet, "/bucket/.hidden"), ""); err != nil {
		t.Errorf("a key starting with a dot was refused: %v", err)
	}
}

func TestRouteBucketAndServiceLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		target string
		want   Operation
		bucket string
	}{
		{http.MethodGet, "/", OpListBuckets, ""},
		{http.MethodGet, "/bucket", OpListObjects, "bucket"},
		{http.MethodGet, "/bucket/", OpListObjects, "bucket"},
		{http.MethodGet, "/bucket?list-type=2", OpListObjectsV2, "bucket"},
		{http.MethodGet, "/bucket?list-type=2&prefix=a/&delimiter=%2F", OpListObjectsV2, "bucket"},
		{http.MethodHead, "/bucket", OpHeadBucket, "bucket"},
		{http.MethodPut, "/bucket", OpCreateBucket, "bucket"},
		{http.MethodDelete, "/bucket", OpDeleteBucket, "bucket"},
		{http.MethodGet, "/bucket?location", OpGetBucketLocation, "bucket"},
		{http.MethodPost, "/bucket?delete", OpDeleteObjects, "bucket"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			t.Parallel()
			got, err := Route(request(t, tc.method, tc.target), "")
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Op != tc.want || got.Bucket != tc.bucket {
				t.Errorf("got {%s %s}, want {%s %s}", got.Op, got.Bucket, tc.want, tc.bucket)
			}
		})
	}
}

// TestRouteRefusesBucketSubResources keeps ?acl, ?policy and friends from being
// served as a listing, which would answer a question nobody asked.
func TestRouteRefusesBucketSubResources(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"/bucket?acl", "/bucket?policy", "/bucket?versioning",
		"/bucket?lifecycle", "/bucket?tagging",
	} {
		_, err := Route(request(t, http.MethodGet, target), "")
		if err == nil || err.Code != "NotImplemented" {
			t.Errorf("%q returned %v, want NotImplemented", target, err)
		}
	}
}

// TestRouteVirtualHostedStyle covers the addressing form AWS now prefers, where
// the bucket is a subdomain rather than the first path segment.
func TestRouteVirtualHostedStyle(t *testing.T) {
	t.Parallel()

	const base = "s3.internal.example"

	tests := []struct {
		host   string
		target string
		bucket string
		key    string
		op     Operation
	}{
		{"backups." + base, "/db.dump", "backups", "db.dump", OpGetObject},
		{"backups." + base + ":9000", "/db.dump", "backups", "db.dump", OpGetObject},
		{"BACKUPS." + base, "/db.dump", "backups", "db.dump", OpGetObject},
		{"backups." + base, "/deep/nested/key", "backups", "deep/nested/key", OpGetObject},
		{"backups." + base, "/", "backups", "", OpListObjects},
		// Not the base domain: falls back to path style.
		{"other.example", "/bucket/key", "bucket", "key", OpGetObject},
		// The base domain itself addresses the service, not a bucket.
		{base, "/bucket/key", "bucket", "key", OpGetObject},
	}

	for _, tc := range tests {
		t.Run(tc.host+tc.target, func(t *testing.T) {
			t.Parallel()
			r := request(t, http.MethodGet, tc.target)
			r.Host = tc.host

			got, err := Route(r, base)
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Bucket != tc.bucket || got.Key != tc.key || got.Op != tc.op {
				t.Errorf("got {%s %q %q}, want {%s %q %q}",
					got.Op, got.Bucket, got.Key, tc.op, tc.bucket, tc.key)
			}
		})
	}

	// Without base_domain configured, a virtual-hosted request is parsed as
	// path style -- the proxy has no way to know the authority carried a bucket.
	// Operators who serve vhost-style clients must configure base_domain, and
	// this test records what happens if they do not.
	t.Run("falls back to path style without a base domain", func(t *testing.T) {
		t.Parallel()
		r := request(t, http.MethodGet, "/key")
		r.Host = "backups." + base
		got, err := Route(r, "")
		if err != nil {
			t.Fatalf("Route returned %v", err)
		}
		if got.Bucket != "key" || got.Op != OpListObjects {
			t.Errorf("got {%s %q}, want the path-style reading {%s %q}",
				got.Op, got.Bucket, OpListObjects, "key")
		}
	})

	t.Run("a dotted prefix is not a bucket", func(t *testing.T) {
		t.Parallel()
		r := request(t, http.MethodGet, "/bucket/key")
		r.Host = "a.b." + base
		got, err := Route(r, base)
		if err != nil {
			t.Fatalf("Route returned %v", err)
		}
		if got.Bucket != "bucket" {
			t.Errorf("bucket = %q, want the path-style fallback", got.Bucket)
		}
	})
}

func TestRouteRejectsOverlongKey(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", MaxKeyLength+1)
	_, err := Route(request(t, http.MethodPut, "/bucket/"+long), "")
	if err == nil || err.Code != "InvalidArgument" {
		t.Errorf("an overlong key returned %v, want InvalidArgument", err)
	}

	ok := strings.Repeat("a", MaxKeyLength)
	if _, err := Route(request(t, http.MethodPut, "/bucket/"+ok), ""); err != nil {
		t.Errorf("a key at the limit was refused: %v", err)
	}
}

func TestRouteRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodOptions} {
		_, err := Route(request(t, method, "/bucket/key"), "")
		if err == nil || err.Code != "NotImplemented" {
			t.Errorf("%s returned %v, want NotImplemented", method, err)
		}
	}
}

func TestWriteErrorRendersS3XML(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	r := request(t, http.MethodGet, "/bucket/missing")
	WriteError(rec, r, ErrNoSuchKey, "req-123")

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	if id := resp.Header.Get("x-amz-request-id"); id != "req-123" {
		t.Errorf("x-amz-request-id = %q, want req-123", id)
	}

	var parsed struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource"`
		RequestID string   `xml:"RequestId"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("the error body is not valid XML: %v", err)
	}
	if parsed.Code != "NoSuchKey" {
		t.Errorf("Code = %q, want NoSuchKey", parsed.Code)
	}
	if parsed.Resource != "/bucket/missing" {
		t.Errorf("Resource = %q, want the request path", parsed.Resource)
	}
	if parsed.RequestID != "req-123" {
		t.Errorf("RequestId = %q, want req-123", parsed.RequestID)
	}
}

// TestWriteErrorOmitsBodyForHead keeps the response legal: a HEAD response must
// not carry a body, however useful the explanation would be.
func TestWriteErrorOmitsBodyForHead(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteError(rec, request(t, http.MethodHead, "/bucket/missing"), ErrNoSuchKey, "req-1")
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD error carried a %d-byte body", rec.Body.Len())
	}
}

func TestErrorWithMessageKeepsCodeAndStatus(t *testing.T) {
	t.Parallel()

	derived := ErrNotImplemented.WithMessage("the sub-resource %q is not implemented", "acl")
	switch {
	case derived.Code != ErrNotImplemented.Code:
		t.Errorf("code changed to %q", derived.Code)
	case derived.HTTPStatus != ErrNotImplemented.HTTPStatus:
		t.Errorf("status changed to %d", derived.HTTPStatus)
	case !strings.Contains(derived.Message, `"acl"`):
		t.Errorf("message = %q, want it to name the sub-resource", derived.Message)
	case ErrNotImplemented.Message == derived.Message:
		t.Error("WithMessage mutated the shared error value")
	}
}

// TestRouteMultipart covers the five object-level multipart operations, which S3
// tells apart by method and by which of ?uploads and ?uploadId is present. A
// CompleteMultipartUpload and a DeleteObjects are both POSTs; only the query
// separates them.
func TestRouteMultipart(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method, target string
		want           Operation
		uploadID       string
		part           int
	}{
		{http.MethodPost, "/bucket/key?uploads", OpCreateMultipartUpload, "", 0},
		{http.MethodPut, "/bucket/key?partNumber=1&uploadId=tok", OpUploadPart, "tok", 1},
		{http.MethodPut, "/bucket/key?partNumber=10000&uploadId=tok", OpUploadPart, "tok", 10000},
		{http.MethodPost, "/bucket/key?uploadId=tok", OpCompleteMultipartUpload, "tok", 0},
		{http.MethodDelete, "/bucket/key?uploadId=tok", OpAbortMultipartUpload, "tok", 0},
		{http.MethodGet, "/bucket/key?uploadId=tok", OpListParts, "tok", 0},
		{http.MethodGet, "/bucket/key?uploadId=tok&max-parts=100", OpListParts, "tok", 0},
		{http.MethodGet, "/bucket?uploads", OpListMultipartUploads, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			t.Parallel()
			got, err := Route(request(t, tc.method, tc.target), "")
			if err != nil {
				t.Fatalf("Route returned %v", err)
			}
			if got.Op != tc.want {
				t.Errorf("op = %s, want %s", got.Op, tc.want)
			}
			if got.UploadID != tc.uploadID {
				t.Errorf("upload id = %q, want %q", got.UploadID, tc.uploadID)
			}
			if got.PartNumber != tc.part {
				t.Errorf("part number = %d, want %d", got.PartNumber, tc.part)
			}
		})
	}
}

func TestRouteMultipartRefusesMalformedRequests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, method, target string
		code                 string
	}{
		{"no part number", http.MethodPut, "/bucket/key?uploadId=tok", "InvalidArgument"},
		{"part number zero", http.MethodPut, "/bucket/key?partNumber=0&uploadId=tok", "InvalidArgument"},
		{"part number too large", http.MethodPut,
			"/bucket/key?partNumber=10001&uploadId=tok", "InvalidArgument"},
		{"part number not a number", http.MethodPut,
			"/bucket/key?partNumber=abc&uploadId=tok", "InvalidArgument"},
		{"both uploads and uploadId", http.MethodPost,
			"/bucket/key?uploads&uploadId=tok", "InvalidRequest"},
		{"uploads with the wrong method", http.MethodPut, "/bucket/key?uploads", "NotImplemented"},
		{"reserved prefix", http.MethodPost, "/bucket/.blindbucket/m/x?uploads", "AccessDenied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Route(request(t, tc.method, tc.target), "")
			if err == nil {
				t.Fatal("a malformed multipart request was accepted")
			}
			if err.Code != tc.code {
				t.Errorf("code = %q, want %q", err.Code, tc.code)
			}
		})
	}
}

// UploadPartCopy is a part whose bytes come from another object. It is deferred
// along with CopyObject, and until then it must be refused rather than treated as
// an ordinary part upload with an empty body.
// A part upload and a part copy are the same method on the same path, and only
// the copy source tells them apart. Routing the copy as an ordinary UploadPart
// would store an empty body as that part.
func TestRouteUploadPartCopy(t *testing.T) {
	t.Parallel()

	r := request(t, http.MethodPut, "/bucket/key?partNumber=1&uploadId=tok")
	r.Header.Set("X-Amz-Copy-Source", "/other/source")
	req, err := Route(r, "")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if req.Op != OpUploadPartCopy {
		t.Errorf("Op = %s, want %s", req.Op, OpUploadPartCopy)
	}
	if req.PartNumber != 1 {
		t.Errorf("PartNumber = %d, want 1", req.PartNumber)
	}

	plain := request(t, http.MethodPut, "/bucket/key?partNumber=1&uploadId=tok")
	req, err = Route(plain, "")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if req.Op != OpUploadPart {
		t.Errorf("without a copy source, Op = %s, want %s", req.Op, OpUploadPart)
	}
}

// The same distinction one level up: a PUT of an object with a copy source is
// CopyObject, not PutObject.
func TestRouteCopyObject(t *testing.T) {
	t.Parallel()

	r := request(t, http.MethodPut, "/bucket/key")
	r.Header.Set("X-Amz-Copy-Source", "/other/source")
	req, err := Route(r, "")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if req.Op != OpCopyObject {
		t.Errorf("Op = %s, want %s", req.Op, OpCopyObject)
	}

	plain := request(t, http.MethodPut, "/bucket/key")
	req, err = Route(plain, "")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if req.Op != OpPutObject {
		t.Errorf("without a copy source, Op = %s, want %s", req.Op, OpPutObject)
	}
}

// TestPresignParamsMatchTheVerifier keeps the router's copy of the presigning
// parameter names in step with the verifier's.
//
// They are declared twice so that routing does not depend on authentication.
// Drift between them would be silent and would look like a client problem: a
// parameter the verifier signs over but the router does not know is a presigned
// URL refused as an unimplemented sub-resource, before anything gets as far as
// checking the signature.
func TestPresignParamsMatchTheVerifier(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		auth.QueryAlgorithm, auth.QueryCredential, auth.QueryDate,
		auth.QueryExpires, auth.QuerySignedHeaders, auth.QuerySignature,
	} {
		if !PresignQueryParam(name) {
			t.Errorf("the verifier signs over %q and the router does not know it", name)
		}
	}
	if got := len(presignParams); got != 6 {
		t.Errorf("the router knows %d presigning parameters, the verifier has 6", got)
	}
}
