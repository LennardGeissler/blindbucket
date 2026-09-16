package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	testAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testRegion    = "us-east-1"
)

func testVerifier(t *testing.T, buckets ...string) *Verifier {
	t.Helper()
	if len(buckets) == 0 {
		buckets = []string{AllBuckets}
	}
	v, err := NewVerifier(Config{Clients: []Client{{
		Name: "test", AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey, Buckets: buckets,
	}}})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// signWithSDK signs a request the way a real client does, using the AWS SDK's
// own signer.
//
// This is the point of keeping that dependency: the canonicalisation below is
// checked against a reference implementation rather than against itself. A test
// that signed with this package's own code would pass happily while both halves
// were wrong in the same way.
func signWithSDK(t *testing.T, method, rawURL string, body []byte, extra http.Header) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(body))
	for name, values := range extra {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	if err := signer.SignHTTP(context.Background(), creds, req, payloadHash, service, testRegion, time.Now().UTC()); err != nil {
		t.Fatalf("signing: %v", err)
	}

	// A server-side request carries the authority in Host; net/http moves it
	// there and removes the header.
	req.Host = req.URL.Host
	return req
}

// TestVerifyAcceptsSDKSignedRequests is the interoperability check that matters:
// whatever the AWS SDK signs, this package must accept.
func TestVerifyAcceptsSDKSignedRequests(t *testing.T) {
	t.Parallel()
	v := testVerifier(t)

	tests := []struct {
		name   string
		method string
		url    string
		body   string
		header http.Header
	}{
		{name: "simple get", method: "GET", url: "https://s3.example/bucket/key"},
		{name: "put with a body", method: "PUT", url: "https://s3.example/bucket/key", body: "payload"},
		{name: "empty body", method: "PUT", url: "https://s3.example/bucket/key"},
		{name: "delete", method: "DELETE", url: "https://s3.example/bucket/key"},
		{name: "head", method: "HEAD", url: "https://s3.example/bucket/key"},
		{name: "nested key", method: "GET", url: "https://s3.example/bucket/a/b/c/d.txt"},
		{name: "key with a space", method: "GET", url: "https://s3.example/bucket/with%20space.txt"},
		{name: "key with a plus", method: "GET", url: "https://s3.example/bucket/plus%2Bsign.txt"},
		{name: "key with unicode", method: "GET", url: "https://s3.example/bucket/umlaut-%C3%A4.txt"},
		{name: "single query parameter", method: "GET", url: "https://s3.example/bucket?list-type=2"},
		{
			name:   "several query parameters, unsorted",
			method: "GET",
			url:    "https://s3.example/bucket?prefix=a/b&max-keys=100&list-type=2&delimiter=%2F",
		},
		{
			name:   "empty query value",
			method: "GET",
			url:    "https://s3.example/bucket/key?acl=",
		},
		{
			name:   "user metadata and content type",
			method: "PUT",
			url:    "https://s3.example/bucket/key",
			body:   "payload",
			header: http.Header{
				"Content-Type":      {"application/json"},
				"X-Amz-Meta-Origin": {"test"},
				"Cache-Control":     {"max-age=60"},
			},
		},
		{
			name:   "header value with awkward whitespace",
			method: "PUT",
			url:    "https://s3.example/bucket/key",
			header: http.Header{"X-Amz-Meta-Spaced": {"  lots   of   space  "}},
		},
		{
			name:   "repeated header",
			method: "PUT",
			url:    "https://s3.example/bucket/key",
			header: http.Header{"X-Amz-Meta-Multi": {"one", "two"}},
		},
		{name: "port in the authority", method: "GET", url: "https://s3.example:9000/bucket/key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := signWithSDK(t, tc.method, tc.url, []byte(tc.body), tc.header)

			result, err := v.Verify(req, "bucket")
			if err != nil {
				t.Fatalf("a request signed by the AWS SDK was rejected: %v\ncanonical request built here:\n%s",
					err, CanonicalRequest(req, mustSignedHeaders(t, req), req.Header.Get("X-Amz-Content-Sha256")))
			}
			if result.Client.Name != "test" {
				t.Errorf("client = %q, want test", result.Client.Name)
			}
			if result.PayloadMode != PayloadHashed {
				t.Errorf("payload mode = %v, want PayloadHashed", result.PayloadMode)
			}
		})
	}
}

func mustSignedHeaders(t *testing.T, r *http.Request) []string {
	t.Helper()
	auth, err := ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	return auth.SignedHeaders
}

// TestVerifyRejectsTampering covers the point of signing at all: any change to a
// signed part of the request must invalidate it.
func TestVerifyRejectsTampering(t *testing.T) {
	t.Parallel()
	v := testVerifier(t)

	tests := map[string]func(r *http.Request){
		"method changed": func(r *http.Request) { r.Method = "DELETE" },
		"path changed":   func(r *http.Request) { r.URL.Path = "/bucket/other" },
		"query added":    func(r *http.Request) { r.URL.RawQuery = "acl" },
		"host changed":   func(r *http.Request) { r.Host = "evil.example" },
		"signed header changed": func(r *http.Request) {
			r.Header.Set("X-Amz-Meta-Origin", "tampered")
		},
		"payload hash changed": func(r *http.Request) {
			r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("a", 64))
		},
		"signature changed": func(r *http.Request) {
			auth := r.Header.Get("Authorization")
			idx := strings.Index(auth, "Signature=")
			r.Header.Set("Authorization", auth[:idx+len("Signature=")]+strings.Repeat("0", 64))
		},
		"timestamp changed": func(r *http.Request) {
			r.Header.Set("X-Amz-Date", time.Now().UTC().Add(-time.Minute).Format(amzDateFormat))
		},
	}

	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := signWithSDK(t, "PUT", "https://s3.example/bucket/key", []byte("payload"),
				http.Header{"X-Amz-Meta-Origin": {"original"}})
			tamper(req)

			if _, err := v.Verify(req, "bucket"); err == nil {
				t.Error("a tampered request was accepted")
			}
		})
	}
}

func TestVerifyRejectsBadCredentials(t *testing.T) {
	t.Parallel()

	t.Run("unknown access key", func(t *testing.T) {
		t.Parallel()
		v, err := NewVerifier(Config{Clients: []Client{{
			Name: "other", AccessKeyID: "AKIADIFFERENT", SecretAccessKey: "s", Buckets: []string{"*"},
		}}})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		req := signWithSDK(t, "GET", "https://s3.example/bucket/key", nil, nil)
		if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrUnknownAccessKey) {
			t.Errorf("got %v, want ErrUnknownAccessKey", err)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		t.Parallel()
		v, err := NewVerifier(Config{Clients: []Client{{
			Name: "test", AccessKeyID: testAccessKey, SecretAccessKey: "wrong", Buckets: []string{"*"},
		}}})
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		req := signWithSDK(t, "GET", "https://s3.example/bucket/key", nil, nil)
		if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrSignatureMismatch) {
			t.Errorf("got %v, want ErrSignatureMismatch", err)
		}
	})

	t.Run("bucket outside the credential's scope", func(t *testing.T) {
		t.Parallel()
		v := testVerifier(t, "allowed")
		req := signWithSDK(t, "GET", "https://s3.example/forbidden/key", nil, nil)
		if _, err := v.Verify(req, "forbidden"); !errors.Is(err, ErrBucketNotAllowed) {
			t.Errorf("got %v, want ErrBucketNotAllowed", err)
		}
		// And the allowed one still works.
		ok := signWithSDK(t, "GET", "https://s3.example/allowed/key", nil, nil)
		if _, err := v.Verify(ok, "allowed"); err != nil {
			t.Errorf("the allowed bucket was refused: %v", err)
		}
	})

	t.Run("unsigned request", func(t *testing.T) {
		t.Parallel()
		v := testVerifier(t)
		req, err := http.NewRequestWithContext(t.Context(), "GET", "https://s3.example/bucket/key", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Host = req.URL.Host
		if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrMissingAuth) {
			t.Errorf("got %v, want ErrMissingAuth", err)
		}
	})

	// A query-signed request against a listener that does not serve them. The
	// subject of this subtest changed with ADR-019: it used to assert that
	// presigned URLs were unimplemented, and now asserts that a listener with
	// them switched off says so rather than reporting a payload problem.
	t.Run("presigned URL against a listener that refuses them", func(t *testing.T) {
		t.Parallel()
		v := testVerifier(t)
		req, err := http.NewRequestWithContext(t.Context(), "GET",
			"https://s3.example/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Host = req.URL.Host
		if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrPresignDisabled) {
			t.Errorf("got %v, want ErrPresignDisabled", err)
		}
	})
}

// TestVerifyClockSkew bounds how long a captured signature stays usable.
func TestVerifyClockSkew(t *testing.T) {
	t.Parallel()

	req := signWithSDK(t, "GET", "https://s3.example/bucket/key", nil, nil)
	signedAt, err := time.Parse(amzDateFormat, req.Header.Get("X-Amz-Date"))
	if err != nil {
		t.Fatalf("parsing the signed timestamp: %v", err)
	}

	tests := []struct {
		name   string
		offset time.Duration
		ok     bool
	}{
		{"now", 0, true},
		{"fourteen minutes later", 14 * time.Minute, true},
		{"fourteen minutes earlier", -14 * time.Minute, true},
		{"sixteen minutes later", 16 * time.Minute, false},
		{"sixteen minutes earlier", -16 * time.Minute, false},
		{"a day later", 24 * time.Hour, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := testVerifier(t)
			v.now = func() time.Time { return signedAt.Add(tc.offset) }

			_, err := v.Verify(req, "bucket")
			switch {
			case tc.ok && err != nil:
				t.Errorf("a request %s was rejected: %v", tc.name, err)
			case !tc.ok && !errors.Is(err, ErrRequestTimeTooSkewed):
				t.Errorf("a request %s returned %v, want ErrRequestTimeTooSkewed", tc.name, err)
			}
		})
	}
}

func TestPayloadModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		claimed string
		want    PayloadMode
		allow   bool
		wantErr bool
	}{
		{claimed: strings.Repeat("a", 64), want: PayloadHashed},
		{claimed: strings.ToUpper(strings.Repeat("a", 64)), want: PayloadHashed},
		{claimed: StreamingSigned, want: PayloadStreamingSigned},
		{claimed: StreamingSignedTrailer, want: PayloadStreamingSignedTrailer},
		{claimed: StreamingUnsignedTrail, want: PayloadStreamingUnsignedTrailer},
		{claimed: UnsignedPayload, allow: true, want: PayloadUnsigned},
		{claimed: UnsignedPayload, allow: false, wantErr: true},
		{claimed: "", wantErr: true},
		{claimed: "not-a-hash", wantErr: true},
		{claimed: strings.Repeat("z", 64), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.claimed+"/allow="+map[bool]string{true: "yes", false: "no"}[tc.allow], func(t *testing.T) {
			t.Parallel()
			v := &Verifier{allowUnsignedPayload: tc.allow}
			r := &http.Request{Header: http.Header{}}
			if tc.claimed != "" {
				r.Header.Set("X-Amz-Content-Sha256", tc.claimed)
			}
			got, _, err := v.payloadMode(r)
			if tc.wantErr {
				if err == nil {
					t.Errorf("%q was accepted", tc.claimed)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q was rejected: %v", tc.claimed, err)
			}
			if got != tc.want {
				t.Errorf("mode = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanonicalQuerySorting(t *testing.T) {
	t.Parallel()

	// Sorted by name, then by value, both encoded with the AWS rules.
	values := url.Values{
		"b":      {"2"},
		"a":      {"z", "a"},
		"prefix": {"a/b c"},
		"empty":  {""},
	}
	want := "a=a&a=z&b=2&empty=&prefix=a%2Fb%20c"
	if got := canonicalQuery(values); got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
	if got := canonicalQuery(nil); got != "" {
		t.Errorf("canonicalQuery(nil) = %q, want empty", got)
	}
}

func TestFoldWhitespace(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"  leading and trailing  ": "leading and trailing",
		"lots    of     space":     "lots of space",
		"tabs\tand\nnewlines":      "tabs and newlines",
		"single":                   "single",
		"":                         "",
	}
	for in, want := range tests {
		if got := foldWhitespace(in); got != want {
			t.Errorf("foldWhitespace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAuthorizationRejectsMalformed(t *testing.T) {
	t.Parallel()

	bad := []string{
		"",
		"Basic dXNlcjpwYXNz",
		"AWS4-HMAC-SHA256",
		"AWS4-HMAC-SHA256 Credential=a/b/c/s3/aws4_request",
		"AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/s3/aws4_request, SignedHeaders=host",
		"AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/ec2/aws4_request, SignedHeaders=host, Signature=" + strings.Repeat("a", 64),
		"AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/s3/wrong, SignedHeaders=host, Signature=" + strings.Repeat("a", 64),
		"AWS4-HMAC-SHA256 Credential=AK/notadate/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + strings.Repeat("a", 64),
		"AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/s3/aws4_request, SignedHeaders=, Signature=" + strings.Repeat("a", 64),
		"AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=tooshort",
		"AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=" + strings.Repeat("a", 64) + ", Extra=1",
	}
	for _, header := range bad {
		if _, err := ParseAuthorization(header); err == nil {
			t.Errorf("accepted %q", header)
		}
	}

	good := "AWS4-HMAC-SHA256 Credential=AK/20260911/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + strings.Repeat("a", 64)
	auth, err := ParseAuthorization(good)
	if err != nil {
		t.Fatalf("a well-formed header was rejected: %v", err)
	}
	if auth.Credential.AccessKeyID != "AK" || len(auth.SignedHeaders) != 3 {
		t.Errorf("parsed %+v, want AK with three signed headers", auth)
	}
	if auth.Credential.Scope() != "20260911/us-east-1/s3/aws4_request" {
		t.Errorf("scope = %q", auth.Credential.Scope())
	}
}

func TestRegistryValidation(t *testing.T) {
	t.Parallel()

	bad := [][]Client{
		{},
		{{Name: "a", SecretAccessKey: "s", Buckets: []string{"*"}}},
		{{Name: "a", AccessKeyID: "k", Buckets: []string{"*"}}},
		{{Name: "a", AccessKeyID: "k", SecretAccessKey: "s"}},
		{
			{Name: "a", AccessKeyID: "same", SecretAccessKey: "s", Buckets: []string{"*"}},
			{Name: "b", AccessKeyID: "same", SecretAccessKey: "s", Buckets: []string{"*"}},
		},
	}
	for i, clients := range bad {
		if _, err := NewRegistry(clients); err == nil {
			t.Errorf("registry %d was accepted", i)
		}
	}
}

func TestClientBucketScope(t *testing.T) {
	t.Parallel()

	scoped := Client{Buckets: []string{"backups", "logs"}}
	for bucket, want := range map[string]bool{
		"backups": true, "logs": true, "other": false, "": false, "backups2": false,
	} {
		if got := scoped.MayAccess(bucket); got != want {
			t.Errorf("MayAccess(%q) = %t, want %t", bucket, got, want)
		}
	}
	if !(Client{Buckets: []string{AllBuckets}}).MayAccess("anything") {
		t.Error("the wildcard did not match")
	}
}

// TestClientSecretIsRedacted keeps a credential out of the logs even when the
// whole struct is logged.
func TestClientSecretIsRedacted(t *testing.T) {
	t.Parallel()

	c := Client{Name: "n", AccessKeyID: "AKID", SecretAccessKey: "super-secret", Buckets: []string{"b"}}
	rendered := c.LogValue().String()
	if strings.Contains(rendered, "super-secret") {
		t.Errorf("the secret reached a log value: %s", rendered)
	}
	if !strings.Contains(rendered, "AKID") {
		t.Errorf("the access key id should still be visible: %s", rendered)
	}
}
