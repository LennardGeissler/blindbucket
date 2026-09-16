package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// These sign with the AWS SDK's own presigner rather than with this package's
// helpers. A test that presigned with the verifier's own code would only prove
// the two agree with each other; what has to be true is that the gateway accepts
// what a real client produces.

func presignVerifier(t *testing.T, options ...func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{
		Clients: []Client{{
			Name: "test", AccessKeyID: testAccessKey,
			SecretAccessKey: testSecretKey, Buckets: []string{AllBuckets},
		}},
		AllowPresign: true,
	}
	for _, option := range options {
		option(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// presignWithSDK builds a presigned request the way `aws s3 presign` does.
func presignWithSDK(
	t *testing.T, method, rawURL string, expires time.Duration, signedAt time.Time,
) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = req.URL.Host

	// The SDK does not add X-Amz-Expires itself, because its own presign client
	// puts it on the query before signing. Same here, so that it is covered.
	query := req.URL.Query()
	query.Set(QueryExpires, strconv.FormatInt(int64(expires.Seconds()), 10))
	req.URL.RawQuery = query.Encode()

	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	signedURL, _, err := signer.PresignHTTP(context.Background(), creds, req,
		UnsignedPayload, service, testRegion, signedAt.UTC())
	if err != nil {
		t.Fatalf("PresignHTTP: %v", err)
	}

	out, err := http.NewRequestWithContext(t.Context(), method, signedURL, nil)
	if err != nil {
		t.Fatalf("building the presigned request: %v", err)
	}
	out.Host = out.URL.Host
	return out
}

func TestPresignedURLFromTheSDKVerifies(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t)
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", time.Hour, time.Now())

	result, err := v.Verify(req, "bucket")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Presigned {
		t.Error("the result does not report itself as presigned")
	}
	if result.Client.Name != "test" {
		t.Errorf("client is %q, want the one that signed it", result.Client.Name)
	}
}

// TestPresignedURLStaysValidPastTheClockSkewBound is the rule that separates a
// presigned URL from a header-signed request, and the one most worth a test: a
// gateway that reused MaxClockSkew here would refuse every presigned URL a
// quarter of an hour after it was made, which is to say the feature would look
// implemented and not work.
func TestPresignedURLStaysValidPastTheClockSkewBound(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t)
	signedAt := time.Now().Add(-6 * time.Hour)
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", 24*time.Hour, signedAt)

	if _, err := v.Verify(req, "bucket"); err != nil {
		t.Fatalf("a URL signed %s ago with a 24h window was refused: %v",
			time.Since(signedAt).Round(time.Hour), err)
	}
}

func TestPresignedURLIsRefusedAfterItExpires(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t)
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", time.Hour, time.Now().Add(-2*time.Hour))

	if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrPresignExpired) {
		t.Errorf("got %v, want ErrPresignExpired", err)
	}
}

// TestPresignedURLIsRefusedBeforeItIsSigned bounds the other side. Without it a
// signer with a wildly fast clock could mint a URL valid from next year.
func TestPresignedURLIsRefusedBeforeItIsSigned(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t)
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", time.Hour, time.Now().Add(2*time.Hour))

	if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrRequestTimeTooSkewed) {
		t.Errorf("got %v, want ErrRequestTimeTooSkewed", err)
	}
}

// TestPresignedURLWithinSkewOfNowIsAccepted keeps the bound above from being so
// tight that an ordinary clock difference breaks a fresh URL.
func TestPresignedURLWithinSkewOfNowIsAccepted(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t)
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", time.Hour, time.Now().Add(5*time.Minute))

	if _, err := v.Verify(req, "bucket"); err != nil {
		t.Errorf("a URL signed 5 minutes ahead was refused: %v", err)
	}
}

func TestPresignedExpiryIsCapped(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t, func(c *Config) { c.MaxPresignExpiry = time.Hour })
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", 24*time.Hour, time.Now())

	if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrPresignExpired) {
		t.Errorf("got %v, want a refusal naming the cap", err)
	}
}

func TestVerifierRefusesAnExpiryCapAboveS3(t *testing.T) {
	t.Parallel()
	_, err := NewVerifier(Config{
		Clients: []Client{{
			Name: "test", AccessKeyID: testAccessKey,
			SecretAccessKey: testSecretKey, Buckets: []string{AllBuckets},
		}},
		MaxPresignExpiry: 30 * 24 * time.Hour,
	})
	if err == nil {
		t.Error("a 30-day cap was accepted; S3's own maximum is 7 days")
	}
}

// TestPresignedSignatureCoversTheQuery. Every parameter but the signature is
// covered, so a holder cannot extend the window, point the URL at another object
// or change the credential.
func TestPresignedSignatureCoversTheQuery(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		tamper func(*url.URL)
	}{
		{"a longer window", func(u *url.URL) {
			q := u.Query()
			q.Set(QueryExpires, "604800")
			u.RawQuery = q.Encode()
		}},
		{"a shifted timestamp", func(u *url.URL) {
			q := u.Query()
			// Shifted from whatever is there rather than set to a fixed value:
			// an earlier draft set it to time.Now(), which is what the URL was
			// signed with, so it changed nothing and the subtest passed against
			// a signature it had not tampered with.
			was, err := time.Parse(amzDateFormat, q.Get(QueryDate))
			if err != nil {
				panic(err)
			}
			q.Set(QueryDate, was.Add(time.Minute).UTC().Format(amzDateFormat))
			u.RawQuery = q.Encode()
		}},
		{"another object", func(u *url.URL) { u.Path = "/bucket/photos/b.jpg" }},
		{"an added parameter", func(u *url.URL) {
			q := u.Query()
			q.Set("response-content-disposition", "attachment")
			u.RawQuery = q.Encode()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := presignVerifier(t)
			req := presignWithSDK(t, http.MethodGet,
				"https://s3.example/bucket/photos/a.jpg", time.Hour, time.Now())
			tc.tamper(req.URL)

			if _, err := v.Verify(req, "bucket"); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
}

// TestPresignedURLIsBoundToItsHost. The URL has to point at the gateway, and the
// signature is what makes that true: one signed for the provider's endpoint does
// not verify here, so the two cannot be confused (ADR-019).
func TestPresignedURLIsBoundToItsHost(t *testing.T) {
	t.Parallel()
	v := presignVerifier(t)
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/bucket/photos/a.jpg", time.Hour, time.Now())
	req.Host = "s3.amazonaws.com"

	if _, err := v.Verify(req, "bucket"); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("got %v, want ErrSignatureMismatch", err)
	}
}

func TestPresignedURLHonoursBucketScope(t *testing.T) {
	t.Parallel()
	v, err := NewVerifier(Config{
		Clients: []Client{{
			Name: "test", AccessKeyID: testAccessKey,
			SecretAccessKey: testSecretKey, Buckets: []string{"allowed"},
		}},
		AllowPresign: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	req := presignWithSDK(t, http.MethodGet,
		"https://s3.example/other/photos/a.jpg", time.Hour, time.Now())

	if _, err := v.Verify(req, "other"); !errors.Is(err, ErrBucketNotAllowed) {
		t.Errorf("got %v, want ErrBucketNotAllowed", err)
	}
}

func TestPresignedMalformedQueries(t *testing.T) {
	t.Parallel()
	base := "https://s3.example/bucket/key?"
	for _, tc := range []struct {
		name  string
		query string
	}{
		{"no algorithm", "X-Amz-Signature=abc&X-Amz-Credential=x/20260916/us-east-1/s3/aws4_request"},
		{"wrong algorithm", "X-Amz-Algorithm=AWS4-HMAC-SHA1&X-Amz-Signature=abc"},
		{"no signed headers", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc" +
			"&X-Amz-Credential=" + testAccessKey + "%2F20260916%2Fus-east-1%2Fs3%2Faws4_request" +
			"&X-Amz-Date=20260916T000000Z&X-Amz-Expires=3600"},
		{"signed headers without host", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc" +
			"&X-Amz-Credential=" + testAccessKey + "%2F20260916%2Fus-east-1%2Fs3%2Faws4_request" +
			"&X-Amz-Date=20260916T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=content-type"},
		{"expiry of zero", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc" +
			"&X-Amz-Credential=" + testAccessKey + "%2F20260916%2Fus-east-1%2Fs3%2Faws4_request" +
			"&X-Amz-Date=20260916T000000Z&X-Amz-Expires=0&X-Amz-SignedHeaders=host"},
		{"negative expiry", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc" +
			"&X-Amz-Credential=" + testAccessKey + "%2F20260916%2Fus-east-1%2Fs3%2Faws4_request" +
			"&X-Amz-Date=20260916T000000Z&X-Amz-Expires=-1&X-Amz-SignedHeaders=host"},
		{"timestamp outside the credential scope date", "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
			"&X-Amz-Signature=abc&X-Amz-Credential=" + testAccessKey +
			"%2F20260916%2Fus-east-1%2Fs3%2Faws4_request" +
			"&X-Amz-Date=20260101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := presignVerifier(t)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+tc.query, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			req.Host = req.URL.Host
			if _, err := v.Verify(req, "bucket"); err == nil {
				t.Errorf("%s was accepted", tc.name)
			}
		})
	}
}

func TestStripPresignParams(t *testing.T) {
	t.Parallel()
	in := url.Values{
		QueryAlgorithm:     {"AWS4-HMAC-SHA256"},
		QueryCredential:    {"k/20260916/us-east-1/s3/aws4_request"},
		QueryDate:          {"20260916T000000Z"},
		QueryExpires:       {"3600"},
		QuerySignedHeaders: {"host"},
		QuerySignature:     {"abc"},
		"prefix":           {"photos/"},
		"max-keys":         {"100"},
	}
	out := StripPresignParams(in)
	if len(out) != 2 {
		t.Fatalf("stripped query has %d parameters, want the 2 that are not presigning", len(out))
	}
	for name := range out {
		if PresignQueryParam(name) {
			t.Errorf("%s survived stripping", name)
		}
	}
	if out.Get("prefix") != "photos/" {
		t.Error("stripping dropped a parameter that was not presigning")
	}
	if len(in) != 8 {
		t.Error("stripping modified its input")
	}
}
