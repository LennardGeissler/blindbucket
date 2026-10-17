package integration

import (
	"bytes"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// syncBuffer is a log destination the gateway's handlers can write to from
// several requests at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestIntegrationClientClosedDownloadIsNotAnIntegrityFailure is #150: a client
// that reads the start of an object and closes the connection -- Nextcloud
// does it on every partial read -- was logged at ERROR as an integrity or
// transport failure and audited with IntegrityCheckFailed. It is neither. On
// all four download paths the gateway now logs it at INFO, and the audit entry
// keeps the status the client was sent and the bytes it got, with no code.
//
// A chunk tampered with at the provider, read to the end, is still the
// integrity failure it always was: ERROR, and IntegrityCheckFailed.
func TestIntegrationClientClosedDownloadIsNotAnIntegrityFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	key := auditIntegrationKey(t)
	writer := auditIntegrationWriter(t, key, path)
	logs := &syncBuffer{}
	h := proxytest.New(t, func(cfg *proxy.Config) {
		cfg.Audit = writer
		cfg.AuditFailClosed = true
		cfg.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	})

	// Large enough that the gateway is still writing when the client leaves:
	// a few MiB, far beyond what the connection buffers.
	single := proxytest.TestKey(t, "single.bin")
	singleBody := proxytest.RandomBytes(t, 4<<20)
	h.Store(t, single, singleBody)
	multi := proxytest.TestKey(t, "multi.bin")
	whole := h.MpuStore(t, multi, [][]byte{
		proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 1<<20),
	})

	cases := []struct {
		name, key, rng string
		size           int
		status         int
	}{
		{"single, whole", single, "", len(singleBody), http.StatusOK},
		{"single, range", single, "bytes=0-", len(singleBody), http.StatusPartialContent},
		{"multipart, whole", multi, "", len(whole), http.StatusOK},
		{"multipart, range", multi, "bytes=0-", len(whole), http.StatusPartialContent},
	}
	for _, c := range cases {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.URL(c.key), nil)
		if err != nil {
			t.Fatalf("%s: building request: %v", c.name, err)
		}
		if c.rng != "" {
			req.Header.Set("Range", c.rng)
		}
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("%s: GET: %v", c.name, err)
		}
		if resp.StatusCode != c.status {
			t.Fatalf("%s: GET returned %d, want %d", c.name, resp.StatusCode, c.status)
		}
		if _, err := io.ReadFull(resp.Body, make([]byte, 1024)); err != nil {
			t.Fatalf("%s: reading the first KiB: %v", c.name, err)
		}
		_ = resp.Body.Close() // before the end: the client leaves
	}

	// The handlers notice the client is gone on their next write, after it has
	// left; wait for all four to say so before reading the audit log.
	deadline := time.Now().Add(30 * time.Second)
	for strings.Count(logs.String(), "client closed the connection") < len(cases) {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d downloads were logged as closed by the client:\n%s",
				strings.Count(logs.String(), "client closed the connection"), len(cases), logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(logs.String(), `"level":"ERROR"`) {
		t.Errorf("a client leaving was logged at ERROR:\n%s", logs.String())
	}

	// Then the integrity failure, read to the end: a byte flipped in the
	// ciphertext of a later chunk, so the headers have gone out before it is
	// found and the response has to be cut off.
	h.RewriteUpstream(t, single, func(stored []byte) []byte {
		stored[len(stored)-int(proxytest.TestChunk)] ^= 0x01
		return stored
	})
	resp := h.Do(t, http.MethodGet, single)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	deadline = time.Now().Add(30 * time.Second)
	for !strings.Contains(logs.String(), "aborting response after an integrity or transport failure") {
		if time.Now().After(deadline) {
			t.Fatalf("the tampered chunk was not logged as an integrity failure:\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("closing the audit log: %v", err)
	}
	pub, err := key.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // a test path.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var gets []audit.Entry
	if _, err := audit.Verify(bytes.NewReader(data), audit.VerifyOptions{
		PublicKey: pub,
		OnEntry: func(e *audit.Entry) error {
			if e.Op == "GetObject" {
				gets = append(gets, *e)
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(gets) != len(cases)+1 {
		t.Fatalf("the log holds %d GetObject entries, want %d", len(gets), len(cases)+1)
	}
	// The four left early. Their order in the log is the order they finished,
	// so they are checked as a set: each a success status, no code, and fewer
	// bytes than the object holds.
	for i, e := range gets[:len(cases)] {
		if e.Code != "" {
			t.Errorf("closed download %d is audited with code %q, want none", i+1, e.Code)
		}
		if e.Status != http.StatusOK && e.Status != http.StatusPartialContent {
			t.Errorf("closed download %d is audited with status %d", i+1, e.Status)
		}
		if e.Bytes <= 0 || e.Bytes >= int64(len(singleBody)) {
			t.Errorf("closed download %d records %d bytes; want some, and not the whole object", i+1, e.Bytes)
		}
	}
	if last := gets[len(cases)]; last.Code != "IntegrityCheckFailed" {
		t.Errorf("the tampered download is audited with code %q, want IntegrityCheckFailed", last.Code)
	}
}
