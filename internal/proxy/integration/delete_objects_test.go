package integration

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

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
