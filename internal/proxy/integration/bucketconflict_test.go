package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// A bucket request that meets the bucket's state gets the provider's 409, not
// a 502 that reads as the gateway's fault. rclone creates the bucket before
// every multipart upload and took the 502 for a failure to retry (#194).
func TestBucketConflictsAreTheProviders(t *testing.T) {
	bucket := fmt.Sprintf("bb-conflict-%d", time.Now().UnixNano())
	h := proxytest.New(t, func(c *auth.Config) {
		c.Clients[0].Buckets = append(c.Clients[0].Buckets, bucket)
	})
	do := func(method, path string, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, h.Server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = int64(len(body))
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, proxytest.ReadBody(t, resp)
	}

	if code, msg := do(http.MethodPut, "/"+bucket, ""); code != http.StatusOK {
		t.Fatalf("creating %s: %d %s", bucket, code, msg)
	}
	t.Cleanup(func() {
		_, _ = do(http.MethodDelete, "/"+bucket+"/an-object", "")
		_, _ = do(http.MethodDelete, "/"+bucket, "")
	})

	// Creating it again. Providers differ: MinIO answers 409, and S3 in
	// us-east-1 answers 200 for a bucket the caller owns. Neither is a 502.
	code, msg := do(http.MethodPut, "/"+bucket, "")
	switch {
	case code == http.StatusConflict && strings.Contains(msg, "BucketAlready"):
	case code == http.StatusOK:
	default:
		t.Fatalf("creating an existing bucket: %d %s, want 409 BucketAlready* or 200", code, msg)
	}

	if code, msg := do(http.MethodPut, "/"+bucket+"/an-object", "something"); code != http.StatusOK {
		t.Fatalf("PUT into %s: %d %s", bucket, code, msg)
	}
	code, msg = do(http.MethodDelete, "/"+bucket, "")
	if code != http.StatusConflict || !strings.Contains(msg, "BucketNotEmpty") || !strings.Contains(msg, ".blindbucket/") {
		t.Fatalf("deleting a bucket that is not empty: %d %s, want 409 BucketNotEmpty naming .blindbucket/", code, msg)
	}
}
