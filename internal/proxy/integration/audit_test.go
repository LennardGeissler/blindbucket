package integration

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// TestAuditLogRecordsWhatWasServed drives real traffic through the gateway
// against a real provider and then verifies the log the way an auditor would:
// with the public key alone, and then with the keyring to read the names.
//
// The unit tests cover the chain and every attack on it. What this adds is that
// the gateway actually feeds it -- that each operation produces one entry, with
// the client, status and object the request really had.
func TestAuditLogRecordsWhatWasServed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	key := auditIntegrationKey(t)
	writer := auditIntegrationWriter(t, key, path)

	h := proxytest.New(t, func(cfg *proxy.Config) {
		cfg.Audit = writer
		cfg.AuditFailClosed = true
	})

	body := make([]byte, 4096)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	const objectKey = "audit/2026/report.pdf"

	if resp := h.Put(t, objectKey, body, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	if resp := h.Do(t, http.MethodGet, objectKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	if resp := h.Do(t, http.MethodDelete, objectKey); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}

	// An unsigned request, which must be recorded as a rejection rather than not
	// at all.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(objectKey), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.Unsigned.Do(req)
	if err != nil {
		t.Fatalf("unsigned GET: %v", err)
	}
	_ = resp.Body.Close()

	if err := writer.Close(); err != nil {
		t.Fatalf("closing the audit log: %v", err)
	}

	// Step one: verify with nothing but the public key, as an auditor would.
	pub, err := key.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var entries []audit.Entry
	result, err := audit.Verify(bytes.NewReader(data), audit.VerifyOptions{
		PublicKey: pub,
		OnEntry:   func(e *audit.Entry) error { entries = append(entries, *e); return nil },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Entries != 4 {
		t.Fatalf("the log holds %d entries, want 4 (PUT, GET, DELETE, rejected GET)",
			result.Entries)
	}

	// The plaintext key must not be anywhere in the file.
	if bytes.Contains(data, []byte("report.pdf")) {
		t.Error("the audit log contains the object key in clear")
	}

	// Step two: with the keyring, the names come back.
	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("NameKey: %v", err)
	}
	coder, err := names.New(nameKey)
	if err != nil {
		t.Fatalf("names.New: %v", err)
	}

	want := []struct {
		op     string
		status int
		client string
	}{
		{"PutObject", http.StatusOK, "integration"},
		{"GetObject", http.StatusOK, "integration"},
		{"DeleteObject", http.StatusNoContent, "integration"},
		{"GetObject", http.StatusForbidden, ""},
	}
	for i, w := range want {
		got := entries[i]
		if got.Op != w.op || got.Status != w.status || got.Client != w.client {
			t.Errorf("entry %d is %s/%d/%q, want %s/%d/%q",
				i+1, got.Op, got.Status, got.Client, w.op, w.status, w.client)
		}
		plain, err := coder.DecryptKey(got.Key)
		if err != nil {
			t.Errorf("entry %d: decrypting the key: %v", i+1, err)
			continue
		}
		if plain != objectKey {
			t.Errorf("entry %d names %q, want %q", i+1, plain, objectKey)
		}
	}

	// The successful PUT and GET moved the object, so they carry its size and
	// the key it was written under. The rejected request carries neither.
	if entries[0].Bytes != int64(len(body)) {
		t.Errorf("the PUT records %d bytes, want %d", entries[0].Bytes, len(body))
	}
	if entries[0].KID != h.Keyring.ActiveKID() {
		t.Errorf("the PUT records kid %q, want %q", entries[0].KID, h.Keyring.ActiveKID())
	}
	if entries[1].Bytes != int64(len(body)) {
		t.Errorf("the GET records %d bytes, want %d", entries[1].Bytes, len(body))
	}
	if entries[3].KID != "" || entries[3].Bytes != 0 {
		t.Errorf("the rejected request records kid %q and %d bytes, want neither",
			entries[3].KID, entries[3].Bytes)
	}
	if entries[3].Code == "" {
		t.Error("the rejected request records no error code")
	}
}

func auditIntegrationKey(t *testing.T) *keys.AuditKey {
	t.Helper()
	key, err := keys.NewAuditKey()
	if err != nil {
		t.Fatalf("NewAuditKey: %v", err)
	}
	return key
}

func auditIntegrationWriter(t *testing.T, key *keys.AuditKey, path string) *audit.Writer {
	t.Helper()
	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	nameKey, err := key.NameKey()
	if err != nil {
		t.Fatalf("NameKey: %v", err)
	}
	w, err := audit.Open(audit.Config{
		Path: path, Signer: signer, NameKey: nameKey, CheckpointInterval: -1,
	})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}
