package proxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/LennardGeissler/blindbucket/internal/auth"
)

// A presigned URL is the one credential this gateway serves that arrives without
// a client behind it: whoever holds the link makes the request, with no SDK, no
// signing and often no S3 tooling at all. So these use a plain http.Client with
// no signing transport -- which is the whole point, and which the harness's own
// client would have hidden by signing every request a second time.

// withPresign turns presigned URLs on for one test. It adjusts the verifier
// rather than the proxy, because that is where the switch lives.
func withPresign(extra ...func(*auth.Config)) func(*auth.Config) {
	return func(c *auth.Config) {
		c.AllowPresign = true
		for _, adjust := range extra {
			adjust(c)
		}
	}
}

// presignURL signs a URL the way `aws s3 presign` does.
func presignURL(
	t *testing.T, h *harness, method, key string, expires time.Duration, signedAt time.Time,
) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = req.URL.Host

	query := req.URL.Query()
	query.Set(auth.QueryExpires, strconv.FormatInt(int64(expires.Seconds()), 10))
	req.URL.RawQuery = query.Encode()

	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	creds := aws.Credentials{AccessKeyID: clientAccessKey, SecretAccessKey: clientSecretKey}
	signed, _, err := signer.PresignHTTP(context.Background(), creds, req,
		auth.UnsignedPayload, "s3", "us-east-1", signedAt.UTC())
	if err != nil {
		t.Fatalf("PresignHTTP: %v", err)
	}
	return signed
}

// fetch follows a presigned URL with nothing but an HTTP client.
func fetch(t *testing.T, h *harness, method, signed string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, signed, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.unsigned.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, signed, err)
	}
	return resp
}

// TestPresignedGetServesTheObject is the feature: a link, and nothing else.
func TestPresignedGetServesTheObject(t *testing.T) {
	h := newHarness(t, withPresign())
	key := testKey(t, "obj")
	body := "handed to somebody who holds no credential at all"
	h.store(t, key, []byte(body))

	resp := fetch(t, h, http.MethodGet, presignURL(t, h, http.MethodGet, key, time.Hour, time.Now()))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if string(got) != body {
		t.Errorf("presigned GET returned %q, want %q", got, body)
	}
}

// TestPresignedGetDecryptsAMultipartObject. The link is served by the ordinary
// read path, so everything it does -- the manifest, the salts, the chunk tags --
// happens for a presigned request too.
func TestPresignedGetDecryptsAMultipartObject(t *testing.T) {
	h := newHarness(t, withPresign())
	key := testKey(t, "obj")
	parts := h.storeParts(t, key, 5*1024*1024, 1024)
	want := len(parts[0]) + len(parts[1])

	resp := fetch(t, h, http.MethodGet, presignURL(t, h, http.MethodGet, key, time.Hour, time.Now()))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if len(got) != want {
		t.Errorf("presigned GET returned %d bytes, want %d", len(got), want)
	}
}

func TestPresignedHeadIsServed(t *testing.T) {
	h := newHarness(t, withPresign())
	key := testKey(t, "obj")
	h.store(t, key, []byte("0123456789"))

	resp := fetch(t, h, http.MethodHead, presignURL(t, h, http.MethodHead, key, time.Hour, time.Now()))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != "10" {
		t.Errorf("Content-Length is %q, want the plaintext size 10", got)
	}
}

// TestPresignedWritesAreRefused is the scope decision of ADR-019, and the
// asymmetry behind it: a link preview that issues a GET is a GET, while one that
// issues a DELETE is data loss with no attacker in the story.
func TestPresignedWritesAreRefused(t *testing.T) {
	h := newHarness(t, withPresign())
	key := testKey(t, "obj")
	h.store(t, key, []byte("must survive every presigned URL below"))

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			resp := fetch(t, h, method, presignURL(t, h, method, key, time.Hour, time.Now()))
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("presigned %s returned %d, want 403", method, resp.StatusCode)
			}
		})
	}

	// And the object is still there and still readable.
	if got := h.getOK(t, key); got != "must survive every presigned URL below" {
		t.Errorf("the object changed: %q", got)
	}
}

func TestPresignedURLExpires(t *testing.T) {
	h := newHarness(t, withPresign())
	key := testKey(t, "obj")
	h.store(t, key, []byte("only briefly available"))

	signed := presignURL(t, h, http.MethodGet, key, time.Hour, time.Now().Add(-2*time.Hour))
	resp := fetch(t, h, http.MethodGet, signed)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("an expired URL returned %d, want 403", resp.StatusCode)
	}
}

// TestPresignedURLCannotBeExtended. Every parameter but the signature is covered,
// so the holder of a short-lived link cannot make it a long-lived one.
func TestPresignedURLCannotBeExtended(t *testing.T) {
	h := newHarness(t, withPresign())
	key := testKey(t, "obj")
	h.store(t, key, []byte("briefly available, and not for longer"))

	signed := presignURL(t, h, http.MethodGet, key, time.Minute, time.Now())
	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parsing the signed URL: %v", err)
	}
	q := u.Query()
	q.Set(auth.QueryExpires, "604800")
	u.RawQuery = q.Encode()

	resp := fetch(t, h, http.MethodGet, u.String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a lengthened URL returned %d, want 403", resp.StatusCode)
	}
}

// TestPresignedURLCannotBePointedAtAnotherObject is the property that makes a
// link safe to hand out: it names one object, and the name is signed.
func TestPresignedURLCannotBePointedAtAnotherObject(t *testing.T) {
	h := newHarness(t, withPresign())
	mine, theirs := testKey(t, "mine"), testKey(t, "theirs")
	h.store(t, mine, []byte("the object the link is for"))
	h.store(t, theirs, []byte("the object it is not for"))

	signed := presignURL(t, h, http.MethodGet, mine, time.Hour, time.Now())
	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parsing the signed URL: %v", err)
	}
	u.Path = "/" + testBucket + "/" + theirs

	resp := fetch(t, h, http.MethodGet, u.String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a repointed URL returned %d, want 403", resp.StatusCode)
	}
}

// TestPresignedURLIsRefusedWhenDisabled.
func TestPresignedURLIsRefusedWhenDisabled(t *testing.T) {
	h := newHarness(t) // no withPresign
	key := testKey(t, "obj")
	h.store(t, key, []byte("not reachable by link on this listener"))

	resp := fetch(t, h, http.MethodGet, presignURL(t, h, http.MethodGet, key, time.Hour, time.Now()))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("returned %d, want 403", resp.StatusCode)
	}
}

// TestPresignedExpiryCapIsEnforced.
func TestPresignedExpiryCapIsEnforced(t *testing.T) {
	h := newHarness(t, withPresign(func(c *auth.Config) { c.MaxPresignExpiry = time.Hour }))
	key := testKey(t, "obj")
	h.store(t, key, []byte("reachable only by a short-lived link"))

	short := fetch(t, h, http.MethodGet,
		presignURL(t, h, http.MethodGet, key, 30*time.Minute, time.Now()))
	_ = short.Body.Close()
	if short.StatusCode != http.StatusOK {
		t.Errorf("a link inside the cap returned %d, want 200", short.StatusCode)
	}

	long := fetch(t, h, http.MethodGet,
		presignURL(t, h, http.MethodGet, key, 24*time.Hour, time.Now()))
	_ = long.Body.Close()
	if long.StatusCode != http.StatusForbidden {
		t.Errorf("a link past the cap returned %d, want 403", long.StatusCode)
	}
}

// TestPresignedGetUnderNameEncryption. A presigned URL names the object the way
// the client does, so the gateway maps it to the stored key exactly as it would
// for any other read. This also demonstrates the leak ADR-019 records and
// THREAT_MODEL §4 states: the plaintext key is right there in the URL, which is
// the one thing name encryption otherwise keeps out of sight.
func TestPresignedGetUnderNameEncryption(t *testing.T) {
	nameOption, enc := withEncryptedNames(t)
	h := newHarness(t, nameOption, withPresign())
	key := testKey(t, "photos/holiday.jpg")
	body := "stored under a name the provider cannot read"
	h.store(t, key, []byte(body))

	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() {
		_ = h.upstream.DeleteObject(context.Background(), testBucket, stored)
	})

	signed := presignURL(t, h, http.MethodGet, key, time.Hour, time.Now())
	if !strings.Contains(signed, "holiday.jpg") {
		t.Error("the URL does not carry the plaintext key; this test no longer " +
			"demonstrates what ADR-019 says it does")
	}

	resp := fetch(t, h, http.MethodGet, signed)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", resp.StatusCode, readBody(t, resp))
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if string(got) != body {
		t.Errorf("presigned GET returned %q, want %q", got, body)
	}
}

// TestPresignedGetIsRollbackChecked. ADR-019 claims a presigned read is an
// ordinary read once authenticated, so everything else applies to it unchanged.
// This is that claim for the newest of those things.
func TestPresignedGetIsRollbackChecked(t *testing.T) {
	h := newHarness(t, withFreshness(t), withPresign())
	key := testKey(t, "obj")

	h.store(t, key, []byte("the first version"))
	first := h.snapshot(t, key)
	h.store(t, key, []byte("the current version"))
	_ = h.getOK(t, key)

	h.restore(t, key, first)

	resp := fetch(t, h, http.MethodGet, presignURL(t, h, http.MethodGet, key, time.Hour, time.Now()))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("a presigned read of a rolled-back object returned %d, want 502",
			resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "RollbackDetected") {
		t.Errorf("answered %q, want RollbackDetected", body)
	}
}
