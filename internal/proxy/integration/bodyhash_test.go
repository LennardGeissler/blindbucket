package integration

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Content-MD5 is what the header means.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// The bodies the gateway acts on without storing them -- the objects a
// DeleteObjects removes, the parts a completion assembles, a bucket request's
// configuration -- are checked against the hash the signature covers, as an
// upload's are. Until 1.5.1 they were not, and a request whose headers were
// signed was served with any body (GHSA-h6g6-fvvh-3r88).

// sendSignedFor signs a request for one body and sends another, as someone who
// alters the request on the way, or replays captured headers, would. headers
// are set before signing.
func sendSignedFor(t *testing.T, h *proxytest.Harness, method, target string,
	signed, sent []byte, headers map[string]string,
) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, bytes.NewReader(sent))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(len(sent))
	sum := sha256.Sum256(signed)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	creds := aws.Credentials{AccessKeyID: proxytest.ClientAccessKey, SecretAccessKey: proxytest.ClientSecretKey}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, hash, "s3", "us-east-1", time.Now()); err != nil {
		t.Fatalf("signing: %v", err)
	}
	resp, err := h.Unsigned.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, proxytest.ReadBody(t, resp)
}

func deleteXML(keys ...string) []byte {
	var b strings.Builder
	b.WriteString("<Delete>")
	for _, k := range keys {
		fmt.Fprintf(&b, "<Object><Key>%s</Key></Object>", k)
	}
	b.WriteString("</Delete>")
	return []byte(b.String())
}

func TestDeleteObjectsVerifiesItsBody(t *testing.T) {
	h := proxytest.New(t)
	keep := proxytest.TestKey(t, "keep")
	h.Store(t, keep, []byte("must survive a body nobody signed"))
	target := h.Server.URL + "/" + proxytest.Bucket + "?delete"

	signed := deleteXML(proxytest.TestKey(t, "absent"))
	code, msg := sendSignedFor(t, h, http.MethodPost, target, signed, deleteXML(keep), nil)
	if code != http.StatusBadRequest {
		t.Fatalf("a body other than the one signed: %d %s, want 400", code, msg)
	}
	if got := getOK(t, h, keep); got != "must survive a body nobody signed" {
		t.Fatalf("the object changed: %q", got)
	}

	// A Content-MD5 that does not match is refused the same way.
	honest := deleteXML(keep)
	wrongMD5 := md5.Sum([]byte("something else")) //nolint:gosec // as above.
	code, _ = sendSignedFor(t, h, http.MethodPost, target, honest, honest,
		map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(wrongMD5[:])})
	if code != http.StatusBadRequest {
		t.Fatalf("a Content-MD5 that does not match: %d, want 400", code)
	}
	_ = getOK(t, h, keep)

	// The body that was signed is served.
	if code, msg := sendSignedFor(t, h, http.MethodPost, target, honest, honest, nil); code != http.StatusOK {
		t.Fatalf("the signed body: %d %s", code, msg)
	}
	wantAbsent(t, h, keep)
}

func TestCompleteMultipartUploadVerifiesItsBody(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "mpu")
	h.CleanupStored(t, key)
	token := h.MpuStart(t, key, nil)
	one, two := proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1000)
	var parts []proxytest.CompletedPart
	for i, body := range [][]byte{one, two} {
		etag, resp := h.MpuPart(t, key, token, i+1, body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("part %d: %d", i+1, resp.StatusCode)
		}
		parts = append(parts, proxytest.CompletedPart{PartNumber: i + 1, ETag: etag})
	}
	signed, err := xml.Marshal(proxytest.CompleteRequest{Parts: parts})
	if err != nil {
		t.Fatal(err)
	}
	// The same upload with its last part left out.
	sent, err := xml.Marshal(proxytest.CompleteRequest{Parts: parts[:1]})
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("%s?uploadId=%s", h.URL(key), proxytest.URLQueryEscape(token))

	code, msg := sendSignedFor(t, h, http.MethodPost, target, signed, sent, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("a completion other than the one signed: %d %s, want 400", code, msg)
	}
	wantAbsent(t, h, key)

	if code, msg := sendSignedFor(t, h, http.MethodPost, target, signed, signed, nil); code != http.StatusOK {
		t.Fatalf("the signed completion: %d %s", code, msg)
	}
	if got := getOK(t, h, key); got != string(one)+string(two) {
		t.Fatal("the object is not its two parts")
	}
}

func TestBucketRequestsVerifyTheirBody(t *testing.T) {
	bucket := fmt.Sprintf("bb-bodyhash-%d", time.Now().UnixNano())
	// The client may name the bucket, so that what refuses the request is the
	// body and not the bucket's authorisation.
	h := proxytest.New(t, func(c *auth.Config) {
		c.Clients[0].Buckets = append(c.Clients[0].Buckets, bucket)
	})
	target := h.Server.URL + "/" + bucket
	signed := []byte(`<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>`)
	sent := []byte(`<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`)

	code, msg := sendSignedFor(t, h, http.MethodPut, target, signed, sent, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("a bucket request with a body other than the one signed: %d %s, want 400", code, msg)
	}
	if resp, err := h.Upstream.Passthrough(context.Background(), http.MethodHead, bucket, nil, nil); err == nil &&
		resp.StatusCode == http.StatusOK {
		_, _ = h.Upstream.Passthrough(context.Background(), http.MethodDelete, bucket, nil, nil)
		t.Fatal("the bucket was created from a body nobody signed")
	}
}
