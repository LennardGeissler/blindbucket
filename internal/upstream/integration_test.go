package upstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// These tests need a real S3-compatible provider and skip without one, so
// `go test ./...` stays runnable without Docker. internal/testprovider lists
// the variables that describe it; locally only the endpoint is needed.
//
//	docker compose up -d
//	BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/upstream
var testBucket = testprovider.Bucket()

func requireProvider(t *testing.T) *Client {
	t.Helper()
	p := testprovider.Require(t)
	c, err := New(Config{
		Endpoint:        p.Endpoint,
		Region:          p.Region,
		PathStyle:       p.PathStyle,
		AccessKeyID:     p.AccessKey,
		SecretAccessKey: p.SecretKey,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// uniqueKey keeps parallel runs and reruns from colliding.
func uniqueKey(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("%supstream-test/%s/%d/%s", testprovider.RunPrefix(),
		t.Name(), time.Now().UnixNano(), suffix)
}

func TestIntegrationObjectLifecycle(t *testing.T) {
	c := requireProvider(t)
	ctx := context.Background()
	key := uniqueKey(t, "object.bin")
	payload := bytes.Repeat([]byte("blindbucket"), 1000)

	put, err := c.PutObject(ctx, PutObjectInput{
		Bucket:        testBucket,
		Key:           key,
		Body:          bytes.NewReader(payload),
		ContentLength: int64(len(payload)),
		ContentType:   "application/octet-stream",
		Metadata:      map[string]string{"bb-v": "1", "bb-kid": "2026-09"},
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if put.ETag == "" {
		t.Error("PutObject returned no ETag")
	}
	t.Cleanup(func() {
		if err := c.DeleteObject(context.Background(), testBucket, key); err != nil {
			t.Errorf("cleanup DeleteObject: %v", err)
		}
	})

	head, err := c.HeadObject(ctx, testBucket, key)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if head.ContentLength != int64(len(payload)) {
		t.Errorf("HeadObject reports %d bytes, want %d", head.ContentLength, len(payload))
	}
	if head.Metadata["Bb-V"] != "1" || head.Metadata["Bb-Kid"] != "2026-09" {
		t.Errorf("metadata did not survive the round trip: %v", head.Metadata)
	}
	if head.ETag != put.ETag {
		t.Errorf("HeadObject ETag %q differs from PutObject's %q", head.ETag, put.ETag)
	}

	get, err := c.GetObject(ctx, GetObjectInput{Bucket: testBucket, Key: key})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	body, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Error("the object came back different from what was stored")
	}
}

// TestIntegrationRange covers the request shape the proxy's range mapping will
// depend on, including what Content-Range reports as the total size.
func TestIntegrationRange(t *testing.T) {
	c := requireProvider(t)
	ctx := context.Background()
	key := uniqueKey(t, "ranged.bin")

	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := c.PutObject(ctx, PutObjectInput{
		Bucket: testBucket, Key: key,
		Body: bytes.NewReader(payload), ContentLength: int64(len(payload)),
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	t.Cleanup(func() { _ = c.DeleteObject(context.Background(), testBucket, key) })

	get, err := c.GetObject(ctx, GetObjectInput{
		Bucket: testBucket, Key: key, Range: "bytes=100-199",
	})
	if err != nil {
		t.Fatalf("GetObject with range: %v", err)
	}
	defer func() { _ = get.Body.Close() }()

	if get.StatusCode != 206 {
		t.Errorf("status %d, want 206", get.StatusCode)
	}
	if get.ContentLength != 100 {
		t.Errorf("ContentLength %d, want 100", get.ContentLength)
	}
	if get.TotalSize != int64(len(payload)) {
		t.Errorf("TotalSize %d, want %d -- the proxy derives the chunk count from this",
			get.TotalSize, len(payload))
	}
	body, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !bytes.Equal(body, payload[100:200]) {
		t.Error("the range returned the wrong bytes")
	}
}

// TestIntegrationAwkwardKeys is the real test of the URI encoding: a signature
// mismatch here means ordinary object names would fail in production.
func TestIntegrationAwkwardKeys(t *testing.T) {
	c := requireProvider(t)
	ctx := context.Background()

	suffixes := []string{
		"plain.txt",
		"with space.txt",
		"plus+sign.txt",
		"amp&and=equals.txt",
		"paren(1).txt",
		"tilde~dash-under_dot.txt",
		"umlaut-ä-ö-ü.txt",
		"emoji-🔐.txt",
		"deep/nested/path/file.txt",
		"trailing.dots...",
		"percent%25encoded.txt",
		"hash#fragment.txt",
		"question?mark.txt",
		"colon:at@sign.txt",
		"quote'apostrophe.txt",
		"bracket[1].txt",
	}

	for _, suffix := range suffixes {
		t.Run(suffix, func(t *testing.T) {
			key := uniqueKey(t, suffix)
			payload := []byte("content for " + suffix)

			if _, err := c.PutObject(ctx, PutObjectInput{
				Bucket: testBucket, Key: key,
				Body: bytes.NewReader(payload), ContentLength: int64(len(payload)),
			}); err != nil {
				t.Fatalf("PutObject: %v", err)
			}
			t.Cleanup(func() { _ = c.DeleteObject(context.Background(), testBucket, key) })

			get, err := c.GetObject(ctx, GetObjectInput{Bucket: testBucket, Key: key})
			if err != nil {
				t.Fatalf("GetObject: %v", err)
			}
			body, err := io.ReadAll(get.Body)
			_ = get.Body.Close()
			if err != nil {
				t.Fatalf("reading body: %v", err)
			}
			if !bytes.Equal(body, payload) {
				t.Errorf("body differs for key %q", key)
			}
		})
	}
}

func TestIntegrationMissingObject(t *testing.T) {
	c := requireProvider(t)
	ctx := context.Background()
	key := uniqueKey(t, "does-not-exist")

	if _, err := c.HeadObject(ctx, testBucket, key); !NotFound(err) {
		t.Errorf("HeadObject on a missing key returned %v, want a not-found error", err)
	}
	if _, err := c.GetObject(ctx, GetObjectInput{Bucket: testBucket, Key: key}); !NotFound(err) {
		t.Errorf("GetObject on a missing key returned %v, want a not-found error", err)
	}
	// Deleting something that is not there is not an error, matching S3.
	if err := c.DeleteObject(ctx, testBucket, key); err != nil {
		t.Errorf("DeleteObject on a missing key returned %v, want nil", err)
	}
}

func TestIntegrationEmptyObject(t *testing.T) {
	c := requireProvider(t)
	ctx := context.Background()
	key := uniqueKey(t, "empty")

	if _, err := c.PutObject(ctx, PutObjectInput{
		Bucket: testBucket, Key: key, Body: strings.NewReader(""), ContentLength: 0,
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	t.Cleanup(func() { _ = c.DeleteObject(context.Background(), testBucket, key) })

	head, err := c.HeadObject(ctx, testBucket, key)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if head.ContentLength != 0 {
		t.Errorf("ContentLength = %d, want 0", head.ContentLength)
	}
}
