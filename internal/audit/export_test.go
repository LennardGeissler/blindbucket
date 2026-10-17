package audit

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"blindbucket-test"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return cert, certPath
}

// startLocalSyslogReceiver starts a local TLS server receiving RFC 5425 framed syslog messages.
func startLocalSyslogReceiver(t *testing.T) (addr string, certPath string, getMsgs func() []string, stop func()) {
	t.Helper()
	cert, certPath := generateTestCert(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	var mu sync.Mutex
	var msgs []string
	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				reader := bufio.NewReader(c)
				for {
					// RFC 5425 octet-counting framing: <MSG-LEN> <MSG>
					lenStr, err := reader.ReadString(' ')
					if err != nil {
						return
					}
					lenStr = strings.TrimSpace(lenStr)
					msgLen, err := strconv.Atoi(lenStr)
					if err != nil {
						return
					}
					buf := make([]byte, msgLen)
					if _, err := io.ReadFull(reader, buf); err != nil {
						return
					}
					mu.Lock()
					msgs = append(msgs, string(buf))
					mu.Unlock()
				}
			}(conn)
		}
	}()

	getMsgs = func() []string {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]string, len(msgs))
		copy(cp, msgs)
		return cp
	}

	return ln.Addr().String(), certPath, getMsgs, func() {
		close(done)
		_ = ln.Close()
	}
}

// TestSyslogExport verifies that audit entries are exported over RFC 5424 / RFC 5425 TLS syslog,
// carrying all file entry fields including chain position (Seq), and matching the local file.
func TestSyslogExport(t *testing.T) {
	addr, certPath, getMsgs, stop := startLocalSyslogReceiver(t)
	defer stop()

	syslogExp, err := NewSyslogExporter(SyslogConfig{
		Endpoint: addr,
		CACert:   certPath,
		AppName:  "test-gateway",
	})
	if err != nil {
		t.Fatalf("NewSyslogExporter: %v", err)
	}
	defer func() { _ = syslogExp.Close() }()

	key := testKey(t, 201)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cfg := testConfig(t, key, path)
	cfg.Exporter = syslogExp

	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	events := []Event{
		event("PutObject", "photos", "vacation/pic1.jpg"),
		event("GetObject", "photos", "vacation/pic1.jpg"),
		event("DeleteObject", "photos", "vacation/pic1.jpg"),
	}
	for _, ev := range events {
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify file on disk
	fileRes, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("verifyFile: %v", err)
	}
	if fileRes.Entries != 3 {
		t.Fatalf("file entries = %d, want 3", fileRes.Entries)
	}

	lines := readLines(t, path)
	var fileEntries []*Entry
	for _, line := range lines {
		r, err := parseLine(bytes.TrimRight(line, "\n"))
		if err != nil {
			t.Fatalf("parseLine: %v", err)
		}
		if r.Type == TypeEntry {
			fileEntries = append(fileEntries, r.Entry)
		}
	}
	if len(fileEntries) != 3 {
		t.Fatalf("got %d file entries, want 3", len(fileEntries))
	}

	// Verify received syslog messages
	received := getMsgs()
	if len(received) != 3 {
		t.Fatalf("received %d syslog messages, want 3", len(received))
	}

	for i, rawMsg := range received {
		wantEntry := fileEntries[i]

		// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
		if !strings.HasPrefix(rawMsg, "<110>1 ") {
			t.Errorf("msg %d does not start with <110>1: %q", i, rawMsg)
		}
		if !strings.Contains(rawMsg, "test-gateway") {
			t.Errorf("msg %d missing app-name test-gateway: %q", i, rawMsg)
		}
		wantSD := fmt.Sprintf("[audit@blindbucket seq=\"%d\" chain=\"%s\"]", wantEntry.Seq, fileRes.Chain)
		if !strings.Contains(rawMsg, wantSD) {
			t.Errorf("msg %d missing structured data %q: %q", i, wantSD, rawMsg)
		}

		// Extract MSG JSON
		jsonStart := strings.Index(rawMsg, " {")
		if jsonStart < 0 {
			t.Fatalf("msg %d has no JSON body: %q", i, rawMsg)
		}
		var exp ExportedEntry
		if err := json.Unmarshal([]byte(rawMsg[jsonStart+1:]), &exp); err != nil {
			t.Fatalf("msg %d JSON unmarshal: %v", i, err)
		}

		// Compare exported entry with file entry
		if exp.Seq != wantEntry.Seq {
			t.Errorf("entry %d seq = %d, want %d", i, exp.Seq, wantEntry.Seq)
		}
		if exp.Chain != fileRes.Chain {
			t.Errorf("entry %d chain = %q, want %q", i, exp.Chain, fileRes.Chain)
		}
		if exp.Hash != wantEntry.Hash {
			t.Errorf("entry %d hash = %q, want %q", i, exp.Hash, wantEntry.Hash)
		}
		if exp.Op != wantEntry.Op {
			t.Errorf("entry %d op = %q, want %q", i, exp.Op, wantEntry.Op)
		}
		if exp.Bucket != wantEntry.Bucket {
			t.Errorf("entry %d bucket = %q, want %q", i, exp.Bucket, wantEntry.Bucket)
		}
		if exp.Key != wantEntry.Key {
			t.Errorf("entry %d key = %q, want %q", i, exp.Key, wantEntry.Key)
		}
		if exp.Time != wantEntry.Time {
			t.Errorf("entry %d time = %q, want %q", i, exp.Time, wantEntry.Time)
		}
		if exp.Status != wantEntry.Status {
			t.Errorf("entry %d status = %d, want %d", i, exp.Status, wantEntry.Status)
		}
	}
}

// TestOTLPExport verifies that audit entries are exported to an OTLP HTTP receiver over TLS,
// carrying all file entry fields including chain position (Seq), and matching the local file.
func TestOTLPExport(t *testing.T) {
	var mu sync.Mutex
	var receivedRecords []otlpLogRecord
	var receivedHeaders []http.Header

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/logs" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req otlpRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		receivedHeaders = append(receivedHeaders, r.Header.Clone())
		for _, rl := range req.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				receivedRecords = append(receivedRecords, sl.LogRecords...)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	otlpExp, err := NewOTLPExporter(OTLPConfig{
		Endpoint: server.URL + "/v1/logs",
		CACert:   certPath,
		Headers: map[string]string{
			"Authorization": "Bearer test-secret-token",
		},
	})
	if err != nil {
		t.Fatalf("NewOTLPExporter: %v", err)
	}
	defer func() { _ = otlpExp.Close() }()

	key := testKey(t, 202)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cfg := testConfig(t, key, path)
	cfg.Exporter = otlpExp

	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	events := []Event{
		event("PutObject", "archive", "2026/report.pdf"),
		event("HeadObject", "archive", "2026/report.pdf"),
	}
	for _, ev := range events {
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify file on disk
	fileRes, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("verifyFile: %v", err)
	}
	if fileRes.Entries != 2 {
		t.Fatalf("file entries = %d, want 2", fileRes.Entries)
	}

	lines := readLines(t, path)
	var fileEntries []*Entry
	for _, line := range lines {
		r, err := parseLine(bytes.TrimRight(line, "\n"))
		if err != nil {
			t.Fatalf("parseLine: %v", err)
		}
		if r.Type == TypeEntry {
			fileEntries = append(fileEntries, r.Entry)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedRecords) != 2 {
		t.Fatalf("received %d OTLP log records, want 2", len(receivedRecords))
	}
	if len(receivedHeaders) != 2 {
		t.Fatalf("received %d OTLP requests, want 2", len(receivedHeaders))
	}
	if got := receivedHeaders[0].Get("Authorization"); got != "Bearer test-secret-token" {
		t.Errorf("header Authorization = %q, want Bearer test-secret-token", got)
	}

	for i, record := range receivedRecords {
		wantEntry := fileEntries[i]

		// Check body JSON
		var exp ExportedEntry
		if err := json.Unmarshal([]byte(record.Body.StringValue), &exp); err != nil {
			t.Fatalf("record %d body unmarshal: %v", i, err)
		}
		if exp.Seq != wantEntry.Seq {
			t.Errorf("record %d seq = %d, want %d", i, exp.Seq, wantEntry.Seq)
		}
		if exp.Hash != wantEntry.Hash {
			t.Errorf("record %d hash = %q, want %q", i, exp.Hash, wantEntry.Hash)
		}
		if exp.Chain != fileRes.Chain {
			t.Errorf("record %d chain = %q, want %q", i, exp.Chain, fileRes.Chain)
		}
		if exp.Op != wantEntry.Op {
			t.Errorf("record %d op = %q, want %q", i, exp.Op, wantEntry.Op)
		}

		// Check attributes
		attrs := map[string]string{}
		for _, attr := range record.Attributes {
			val := attr.Value.StringValue
			if val == "" {
				val = attr.Value.IntValue
			}
			attrs[attr.Key] = val
		}
		if attrs["audit.seq"] != strconv.FormatUint(wantEntry.Seq, 10) {
			t.Errorf("attr audit.seq = %q, want %d", attrs["audit.seq"], wantEntry.Seq)
		}
		if attrs["audit.chain"] != fileRes.Chain {
			t.Errorf("attr audit.chain = %q, want %q", attrs["audit.chain"], fileRes.Chain)
		}
		if attrs["audit.hash"] != wantEntry.Hash {
			t.Errorf("attr audit.hash = %q, want %q", attrs["audit.hash"], wantEntry.Hash)
		}
		if attrs["audit.op"] != wantEntry.Op {
			t.Errorf("attr audit.op = %q, want %q", attrs["audit.op"], wantEntry.Op)
		}
	}
}

// TestExportFailureDoesNotBlockOrStopFile verifies acceptance criterion 2:
// An export that fails does not block requests and does not stop the file from being written.
// It is reported to OnExportError and logged.
func TestExportFailureDoesNotBlockOrStopFile(t *testing.T) {
	// Exporter pointing to an unreachable port
	badSyslog, err := NewSyslogExporter(SyslogConfig{
		Endpoint: "127.0.0.1:1", // closed port
		Timeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSyslogExporter: %v", err)
	}
	defer func() { _ = badSyslog.Close() }()

	key := testKey(t, 203)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	var exportErrors int32
	cfg := testConfig(t, key, path)
	cfg.Exporter = badSyslog
	cfg.OnExportError = func(_ error) {
		atomic.AddInt32(&exportErrors, 1)
	}

	w, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Appending MUST succeed even though export fails
	for i := range 5 {
		err := w.Append(event("PutObject", "b", fmt.Sprintf("obj%d", i)))
		if err != nil {
			t.Fatalf("Append %d failed unexpectedly: %v", i, err)
		}
	}

	// Writer MUST NOT be marked broken
	if err := w.Err(); err != nil {
		t.Fatalf("w.Err() is %v, want nil (export failure must not break writer)", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Export error callback must have been notified
	if got := atomic.LoadInt32(&exportErrors); got != 5 {
		t.Errorf("export error count = %d, want 5", got)
	}

	// File on disk MUST be completely intact and verifiable
	res, err := verifyFile(t, path, testPublic(t, key))
	if err != nil {
		t.Fatalf("file verification failed: %v", err)
	}
	if res.Entries != 5 {
		t.Errorf("verified %d entries, want 5", res.Entries)
	}
}

// TestAsyncExporterQueueDrop verifies that AsyncExporter drops entries when the queue
// is full without blocking callers.
func TestAsyncExporterQueueDrop(t *testing.T) {
	blocker := make(chan struct{})
	blockingExporter := &stubExporter{
		onExport: func() error {
			<-blocker
			return nil
		},
	}

	var dropCount int32
	async := NewAsyncExporter(blockingExporter, "test-dest", 2, DefaultDrainTimeout, func(_ string, _ error) {
		atomic.AddInt32(&dropCount, 1)
	}, nil)

	dummyEntry := &Entry{Seq: 1, Op: "PutObject"}

	// Fill queue (capacity 2 + 1 active worker = 3)
	for i := range 10 {
		_ = async.Export("chain1", dummyEntry)
		_ = i
	}

	if got := atomic.LoadInt32(&dropCount); got == 0 {
		t.Error("expected queue overflow drops, got 0")
	}

	close(blocker)
	_ = async.Close()
}

// TestAsyncExporterDrainTimeout verifies that AsyncExporter does not hang during
// shutdown when downstream exports are slow, and that undrained entries are dropped.
func TestAsyncExporterDrainTimeout(t *testing.T) {
	var dropCount int32
	var successCount int32

	slowExp := &stubExporter{
		onExport: func() error {
			time.Sleep(40 * time.Millisecond)
			return nil
		},
	}

	drainTimeout := 70 * time.Millisecond
	async := NewAsyncExporter(slowExp, "test-slow", 20, drainTimeout, func(_ string, _ error) {
		atomic.AddInt32(&dropCount, 1)
	}, func(_ string) {
		atomic.AddInt32(&successCount, 1)
	})

	dummy := &Entry{Seq: 1, Op: "PutObject"}
	for range 10 {
		_ = async.Export("chain", dummy)
	}

	start := time.Now()
	_ = async.Close()
	elapsed := time.Since(start)

	if elapsed >= 300*time.Millisecond {
		t.Errorf("Close took %v, want < 300ms", elapsed)
	}

	if drops := atomic.LoadInt32(&dropCount); drops == 0 {
		t.Errorf("expected undrained entries to be counted as drops, got 0")
	}
	if succ := atomic.LoadInt32(&successCount); succ == 0 {
		t.Errorf("expected at least 1 success before deadline, got 0")
	}
}

func intPtr(v int) *int {
	return &v
}

// TestSyslogFacilitySeverityZero verifies that facility: 0 (kern) and severity: 0 (emerg)
// can be configured and are not mistaken for unset defaults.
func TestSyslogFacilitySeverityZero(t *testing.T) {
	addr, certPath, getMsgs, stop := startLocalSyslogReceiver(t)
	defer stop()

	syslogExp, err := NewSyslogExporter(SyslogConfig{
		Endpoint: addr,
		CACert:   certPath,
		Facility: intPtr(0), // kern
		Severity: intPtr(0), // emerg
	})
	if err != nil {
		t.Fatalf("NewSyslogExporter: %v", err)
	}
	defer func() { _ = syslogExp.Close() }()

	entry := &Entry{
		Seq:    1,
		Hash:   "abc",
		Op:     "PutObject",
		Bucket: "b",
		Key:    "k",
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Status: 200,
	}
	if err := syslogExp.Export("chain1", entry); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var msgs []string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		msgs = getMsgs()
		if len(msgs) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if len(msgs) != 1 {
		t.Fatalf("received %d messages, want 1", len(msgs))
	}
	// PRI = 0*8 + 0 = 0 -> <0>1
	if !strings.HasPrefix(msgs[0], "<0>1 ") {
		t.Errorf("message does not start with <0>1: %q", msgs[0])
	}
}

// TestSyslogStructuredDataEscaping verifies that SD-PARAM values escape \, ", and ] per RFC 5424.
func TestSyslogStructuredDataEscaping(t *testing.T) {
	addr, certPath, getMsgs, stop := startLocalSyslogReceiver(t)
	defer stop()

	syslogExp, err := NewSyslogExporter(SyslogConfig{
		Endpoint: addr,
		CACert:   certPath,
	})
	if err != nil {
		t.Fatalf("NewSyslogExporter: %v", err)
	}
	defer func() { _ = syslogExp.Close() }()

	entry := &Entry{
		Seq:    1,
		Hash:   "abc",
		Op:     "PutObject",
		Bucket: "b",
		Key:    "k",
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Status: 200,
	}
	specialChain := `test\chain"with]brackets`
	if err := syslogExp.Export(specialChain, entry); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var msgs []string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		msgs = getMsgs()
		if len(msgs) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if len(msgs) != 1 {
		t.Fatalf("received %d messages, want 1", len(msgs))
	}
	wantSD := `[audit@blindbucket seq="1" chain="test\\chain\"with\]brackets"]`
	if !strings.Contains(msgs[0], wantSD) {
		t.Errorf("message structured data missing or malformed.\nGot:  %s\nWant: %s", msgs[0], wantSD)
	}
}

type stubExporter struct {
	onExport func() error
}

func (s *stubExporter) Export(_ string, _ *Entry) error {
	if s.onExport != nil {
		return s.onExport()
	}
	return nil
}

func (s *stubExporter) Close() error {
	return nil
}
