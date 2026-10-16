package integration

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// TestIntegrationListing checks that listings report plaintext sizes and hide
// the gateway's own objects.
func TestIntegrationListing(t *testing.T) {
	h := proxytest.New(t)
	prefix := fmt.Sprintf("listing-test/%d/", time.Now().UnixNano())

	sizes := map[string]int{"a.bin": 100, "b.bin": 4096, "c.bin": 10000}
	for name, size := range sizes {
		h.Store(t, prefix+name, bytes.Repeat([]byte{1}, size))
	}

	// An object under the reserved prefix, written directly, must not appear.
	hidden := ".blindbucket/m/deadbeef/manifest"
	if _, err := h.Upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: hidden,
		Body: strings.NewReader("manifest"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("writing the hidden object: %v", err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, hidden) })

	for _, listType := range []string{"2", ""} {
		name, query := "ListObjectsV2", "?list-type=2&prefix="+url.QueryEscape(prefix)
		if listType == "" {
			name, query = "ListObjects", "?prefix="+url.QueryEscape(prefix)
		}

		t.Run(name, func(t *testing.T) {
			resp, err := h.Client.Get(h.Server.URL + "/" + proxytest.Bucket + query)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, proxytest.ReadBody(t, resp))
			}

			var result upstream.ListBucketResult
			if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("the listing is not valid XML: %v", err)
			}
			if len(result.Contents) != len(sizes) {
				t.Fatalf("listed %d objects, want %d", len(result.Contents), len(sizes))
			}
			for _, entry := range result.Contents {
				base := strings.TrimPrefix(entry.Key, prefix)
				want, ok := sizes[base]
				if !ok {
					t.Errorf("unexpected key %q", entry.Key)
					continue
				}
				if entry.Size != int64(want) {
					t.Errorf("%s: listed size %d, want the plaintext size %d", base, entry.Size, want)
				}
			}
		})
	}

	t.Run("the reserved prefix is hidden", func(t *testing.T) {
		resp, err := h.Client.Get(h.Server.URL + "/" + proxytest.Bucket + "?list-type=2&prefix=.blindbucket/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var result upstream.ListBucketResult
		if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("the listing is not valid XML: %v", err)
		}
		if len(result.Contents) != 0 {
			t.Errorf("the gateway's own objects appeared in a listing: %d entries", len(result.Contents))
		}
	})
}

// TestIntegrationDeleteObjects covers the bulk delete `aws s3 rm --recursive`
// uses.
func TestIntegrationDeleteObjects(t *testing.T) {
	h := proxytest.New(t)
	prefix := fmt.Sprintf("bulk-delete/%d/", time.Now().UnixNano())

	keys := []string{prefix + "one", prefix + "two", prefix + "three"}
	for _, key := range keys {
		h.Store(t, key, []byte("payload"))
	}

	var body strings.Builder
	body.WriteString("<Delete>")
	for _, key := range keys {
		body.WriteString("<Object><Key>" + key + "</Key></Object>")
	}
	body.WriteString("</Delete>")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		h.Server.URL+"/"+proxytest.Bucket+"?delete", strings.NewReader(body.String()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, proxytest.ReadBody(t, resp))
	}

	for _, key := range keys {
		if _, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, key); !upstream.NotFound(err) {
			t.Errorf("%s survived the bulk delete", key)
		}
	}

	t.Run("the reserved prefix is refused", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			h.Server.URL+"/"+proxytest.Bucket+"?delete",
			strings.NewReader("<Delete><Object><Key>.blindbucket/m/x</Key></Object></Delete>"))
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})
}

func TestIntegrationBucketOperations(t *testing.T) {
	h := proxytest.New(t)

	t.Run("HeadBucket", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodHead,
			h.Server.URL+"/"+proxytest.Bucket, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("HEAD: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("GetBucketLocation", func(t *testing.T) {
		resp, err := h.Client.Get(h.Server.URL + "/" + proxytest.Bucket + "?location")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d, want 200", resp.StatusCode)
		}
		if body := proxytest.ReadBody(t, resp); !strings.Contains(body, "LocationConstraint") {
			t.Errorf("body = %q, want a LocationConstraint document", body)
		}
	})
}

// postDelete sends a DeleteObjects body and returns the status and response.
func postDelete(t *testing.T, h *proxytest.Harness, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		h.Server.URL+"/"+proxytest.Bucket+"?delete", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, proxytest.ReadBody(t, resp)
}

func deleteBody(keys ...string) string {
	var b strings.Builder
	b.WriteString("<Delete>")
	for _, key := range keys {
		b.WriteString("<Object><Key>" + key + "</Key></Object>")
	}
	b.WriteString("</Delete>")
	return b.String()
}

// TestIntegrationDeleteObjectsUnderEncryptedNames: the client names its own
// keys, the provider only knows the encrypted ones, and the answer has to come
// back in the client's names -- or a client matching the Deleted list against
// what it asked for would believe nothing was deleted.
func TestIntegrationDeleteObjectsUnderEncryptedNames(t *testing.T) {
	option, enc := proxytest.WithEncryptedNames(t)
	h := proxytest.New(t, option)
	prefix := fmt.Sprintf("bulk-delete-names/%d/", time.Now().UnixNano())
	keys := []string{prefix + "one", prefix + "two"}
	for _, key := range keys {
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		h.CleanupStored(t, stored)
		resp := h.Put(t, key, []byte("payload"), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s: %d", key, resp.StatusCode)
		}
	}

	status, body := postDelete(t, h, deleteBody(keys...))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var result upstream.DeleteResult
	if err := xml.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("parsing: %v\n%s", err, body)
	}
	got := map[string]bool{}
	for _, d := range result.Deleted {
		got[d.Key] = true
	}
	for _, key := range keys {
		if !got[key] {
			t.Errorf("%s is not reported deleted under its own name; the answer was:\n%s", key, body)
		}
		stored, _ := enc.EncryptKey(key)
		if _, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, stored); !upstream.NotFound(err) {
			t.Errorf("%s survived the bulk delete", key)
		}
	}
}

func TestIntegrationDeleteObjectsRefusesMalformedBodies(t *testing.T) {
	h := proxytest.New(t)
	for name, body := range map[string]string{
		"not XML":            "this is not a delete request",
		"no objects in it":   "<Delete><Quiet>true</Quiet></Delete>",
		"an unclosed object": "<Delete><Object><Key>a</Key>",
	} {
		t.Run(name, func(t *testing.T) {
			if status, resp := postDelete(t, h, body); status != http.StatusBadRequest {
				t.Errorf("status %d, want 400: %s", status, resp)
			}
		})
	}
}

// TestIntegrationListingHidesTheReservedPrefix: a multipart object leaves a
// manifest under the reserved prefix, and no listing a client can ask for may
// show it -- as an entry, or as a common prefix that groups it.
func TestIntegrationListingHidesTheReservedPrefix(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "multipart.bin")
	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1000)})
	if _, ok := h.ManifestKeyOfQuiet(key); !ok {
		t.Fatal("the multipart object left no manifest to hide")
	}

	for _, query := range []string{
		"list-type=2&delimiter=%2F",
		"delimiter=%2F",
		"list-type=2&delimiter=b",
		"list-type=2&delimiter=l",
		"list-type=2&prefix=" + url.QueryEscape(s3api.ReservedPrefix),
		"list-type=2&prefix=.",
		"list-type=2&prefix=.b",
	} {
		t.Run(query, func(t *testing.T) {
			status, body, out := listQuery(t, h, query)
			if query == "list-type=2&prefix=." {
				// MinIO rejects this client prefix; providers that accept it still
				// have to hide the reserved entries below.
				values, _ := url.ParseQuery(query)
				_, err := h.Upstream.ListObjects(t.Context(), proxytest.Bucket, values)
				if apiErr, ok := upstream.AsAPIError(err); ok && apiErr.StatusCode == http.StatusBadRequest {
					var result struct{ Code, Message string }
					if err := xml.Unmarshal([]byte(body), &result); err != nil {
						t.Fatalf("error document: %v", err)
					}
					if status != http.StatusBadRequest || result.Code != apiErr.Code || result.Message != apiErr.Message {
						t.Fatalf("listing returned %d: %s; want provider's 400 %s: %s", status, body, apiErr.Code, apiErr.Message)
					}
					return
				}
				if err != nil {
					t.Fatalf("direct provider listing: %v", err)
				}
			}
			if status != 200 {
				t.Fatalf("listing returned %d: %s", status, body)
			}
			for _, entry := range out.Contents {
				if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
					t.Errorf("the listing shows %q", entry.Key)
				}
			}
			for _, cp := range out.CommonPrefixes {
				// Under the reserved prefix, or a shorter grouping that
				// still collects exactly the gateway's objects.
				reserved := s3api.ReservedPrefix
				if strings.HasPrefix(cp.Prefix, reserved) ||
					(cp.Prefix != "" && len(cp.Prefix) < len(reserved) && reserved[:len(cp.Prefix)] == cp.Prefix) {
					t.Errorf("the listing groups the gateway's objects under %q", cp.Prefix)
				}
			}
			// The response echoes the requested prefix, so only a reserved name
			// the client did not send itself would be a leak.
			if !strings.Contains(query, url.QueryEscape(s3api.ReservedPrefix)) &&
				strings.Contains(body, s3api.ReservedPrefix) {
				t.Errorf("the reserved prefix appears in the response:\n%s", body)
			}
		})
	}
}
