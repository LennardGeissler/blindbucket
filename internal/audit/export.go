package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultDrainTimeout is how long AsyncExporter waits during shutdown to flush
// queued entries before dropping remaining entries.
const DefaultDrainTimeout = 2 * time.Second

// Exporter exports copies of audit entries to an external receiver.
// Implementations must be safe for concurrent use.
type Exporter interface {
	Export(chain string, entry *Entry) error
	Close() error
}

// ExportedEntry is one served request formatted for external SIEM export.
// It carries what the file entry carries, plus its chain identifier,
// including its position in the chain (Seq).
type ExportedEntry struct {
	Chain     string `json:"chain"`
	Seq       uint64 `json:"seq"`
	Time      string `json:"time"`
	Op        string `json:"op"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	Client    string `json:"client"`
	Principal string `json:"principal"`
	RequestID string `json:"request_id"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	KID       string `json:"kid"`
	Bytes     int64  `json:"bytes"`
	Hash      string `json:"hash"`
}

// NewExportedEntry creates an ExportedEntry from an Entry and chain ID.
func NewExportedEntry(chain string, e *Entry) ExportedEntry {
	return ExportedEntry{
		Chain:     chain,
		Seq:       e.Seq,
		Time:      e.Time,
		Op:        e.Op,
		Bucket:    e.Bucket,
		Key:       e.Key,
		Client:    e.Client,
		Principal: e.Principal,
		RequestID: e.RequestID,
		Status:    e.Status,
		Code:      e.Code,
		KID:       e.KID,
		Bytes:     e.Bytes,
		Hash:      e.Hash,
	}
}

// SyslogConfig configures an RFC 5424 syslog exporter over TLS (RFC 5425).
type SyslogConfig struct {
	Endpoint string
	Network  string
	CACert   string
	AppName  string
	Facility *int
	Severity *int
	Timeout  time.Duration
}

// SyslogExporter exports audit entries over RFC 5424 syslog with RFC 5425 TLS framing.
type SyslogExporter struct {
	cfg       SyslogConfig
	tlsConfig *tls.Config
	hostname  string
	mu        sync.Mutex
	conn      net.Conn
}

// escapeSDParam escapes '\', '"', and ']' characters per RFC 5424 §6.3.3.
func escapeSDParam(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

// NewSyslogExporter creates a SyslogExporter.
func NewSyslogExporter(cfg SyslogConfig) (*SyslogExporter, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("audit: syslog endpoint is required")
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.AppName == "" {
		cfg.AppName = "blindbucket"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.CACert != "" {
		caPEM, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("audit: reading syslog ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("audit: no valid CA certificates found in ca_cert")
		}
		tlsConf.RootCAs = pool
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "-"
	}

	return &SyslogExporter{
		cfg:       cfg,
		tlsConfig: tlsConf,
		hostname:  hostname,
	}, nil
}

// Export sends an entry formatted as RFC 5424 syslog message over TLS with RFC 5425 octet-counting framing.
func (s *SyslogExporter) Export(chain string, entry *Entry) error {
	exp := NewExportedEntry(chain, entry)
	jsonBytes, err := json.Marshal(exp)
	if err != nil {
		return err
	}

	facility := 13 // LOG_AUDIT
	if s.cfg.Facility != nil {
		facility = *s.cfg.Facility
	}
	severity := 6 // LOG_INFO
	if s.cfg.Severity != nil {
		severity = *s.cfg.Severity
	}
	pri := facility*8 + severity
	procID := chain
	if procID == "" {
		procID = "-"
	}
	msgID := "audit"
	sd := fmt.Sprintf("[audit@blindbucket seq=\"%d\" chain=\"%s\"]", entry.Seq, escapeSDParam(chain))
	syslogMsg := fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		pri, entry.Time, s.hostname, s.cfg.AppName, procID, msgID, sd, string(jsonBytes))

	// RFC 5425 §4.3 octet-counting framing: MSG-LEN SP SYSLOG-MSG
	framed := fmt.Sprintf("%d %s", len(syslogMsg), syslogMsg)

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writeLocked([]byte(framed))
}

func (s *SyslogExporter) writeLocked(b []byte) error {
	if s.conn == nil {
		dialer := &net.Dialer{Timeout: s.cfg.Timeout}
		conn, err := tls.DialWithDialer(dialer, s.cfg.Network, s.cfg.Endpoint, s.tlsConfig)
		if err != nil {
			return err
		}
		s.conn = conn
	}

	_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
	_, err := s.conn.Write(b)
	if err != nil {
		_ = s.conn.Close()
		s.conn = nil
		// Reconnect once on broken pipe or connection drop
		dialer := &net.Dialer{Timeout: s.cfg.Timeout}
		conn, dialErr := tls.DialWithDialer(dialer, s.cfg.Network, s.cfg.Endpoint, s.tlsConfig)
		if dialErr != nil {
			return fmt.Errorf("write failed: %w (reconnect failed: %w)", err, dialErr)
		}
		s.conn = conn
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
		if _, writeErr := s.conn.Write(b); writeErr != nil {
			_ = s.conn.Close()
			s.conn = nil
			return writeErr
		}
	}
	return nil
}

// Close closes any active TLS connection.
func (s *SyslogExporter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// OTLPConfig configures an OTLP logs exporter over HTTPS.
type OTLPConfig struct {
	Endpoint string
	Headers  map[string]string
	CACert   string
	Timeout  time.Duration
}

// OTLPExporter exports audit entries to an OTLP logs receiver over HTTPS.
type OTLPExporter struct {
	cfg    OTLPConfig
	client *http.Client
}

// NewOTLPExporter creates an OTLPExporter.
func NewOTLPExporter(cfg OTLPConfig) (*OTLPExporter, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("audit: otlp endpoint is required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "https" {
		return nil, errors.New("audit: otlp endpoint must be an https URL")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.CACert != "" {
		caPEM, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("audit: reading otlp ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("audit: no valid CA certificates found in ca_cert")
		}
		tlsConf.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConf,
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       30 * time.Second,
	}

	return &OTLPExporter{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
	}, nil
}

type otlpRequest struct {
	ResourceLogs []otlpResourceLog `json:"resourceLogs"`
}

type otlpResourceLog struct {
	Resource  otlpResource   `json:"resource"`
	ScopeLogs []otlpScopeLog `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeLog struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	TimeUnixNano         string         `json:"timeUnixNano"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
	SeverityNumber       int            `json:"severityNumber"`
	SeverityText         string         `json:"severityText"`
	Body                 otlpAnyValue   `json:"body"`
	Attributes           []otlpKeyValue `json:"attributes"`
}

type otlpAnyValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

type otlpKeyValue struct {
	Key   string           `json:"key"`
	Value otlpAttributeVal `json:"value"`
}

type otlpAttributeVal struct {
	StringValue string `json:"stringValue,omitempty"`
	IntValue    string `json:"intValue,omitempty"`
}

// Export sends an entry to the OTLP logs endpoint.
func (o *OTLPExporter) Export(chain string, entry *Entry) error {
	exp := NewExportedEntry(chain, entry)
	jsonBytes, err := json.Marshal(exp)
	if err != nil {
		return err
	}

	var timeNano int64
	if t, parseErr := time.Parse(timeFormat, entry.Time); parseErr == nil {
		timeNano = t.UnixNano()
	} else {
		timeNano = time.Now().UnixNano()
	}
	nowNano := time.Now().UnixNano()

	severityNumber := 9 // INFO
	severityText := "INFO"
	if entry.Status >= 500 {
		severityNumber = 17 // ERROR
		severityText = "ERROR"
	} else if entry.Status >= 400 || entry.Code != "" {
		severityNumber = 13 // WARN
		severityText = "WARN"
	}

	reqBody := otlpRequest{
		ResourceLogs: []otlpResourceLog{
			{
				Resource: otlpResource{
					Attributes: []otlpKeyValue{
						{Key: "service.name", Value: otlpAttributeVal{StringValue: "blindbucket"}},
					},
				},
				ScopeLogs: []otlpScopeLog{
					{
						Scope: otlpScope{
							Name:    "blindbucket.audit",
							Version: "1.0",
						},
						LogRecords: []otlpLogRecord{
							{
								TimeUnixNano:         strconv.FormatInt(timeNano, 10),
								ObservedTimeUnixNano: strconv.FormatInt(nowNano, 10),
								SeverityNumber:       severityNumber,
								SeverityText:         severityText,
								Body:                 otlpAnyValue{StringValue: string(jsonBytes)},
								Attributes: []otlpKeyValue{
									{Key: "audit.chain", Value: otlpAttributeVal{StringValue: chain}},
									{Key: "audit.seq", Value: otlpAttributeVal{IntValue: strconv.FormatUint(entry.Seq, 10)}},
									{Key: "audit.time", Value: otlpAttributeVal{StringValue: entry.Time}},
									{Key: "audit.op", Value: otlpAttributeVal{StringValue: entry.Op}},
									{Key: "audit.bucket", Value: otlpAttributeVal{StringValue: entry.Bucket}},
									{Key: "audit.key", Value: otlpAttributeVal{StringValue: entry.Key}},
									{Key: "audit.client", Value: otlpAttributeVal{StringValue: entry.Client}},
									{Key: "audit.principal", Value: otlpAttributeVal{StringValue: entry.Principal}},
									{Key: "audit.request_id", Value: otlpAttributeVal{StringValue: entry.RequestID}},
									{Key: "audit.status", Value: otlpAttributeVal{IntValue: strconv.Itoa(entry.Status)}},
									{Key: "audit.code", Value: otlpAttributeVal{StringValue: entry.Code}},
									{Key: "audit.kid", Value: otlpAttributeVal{StringValue: entry.KID}},
									{Key: "audit.bytes", Value: otlpAttributeVal{IntValue: strconv.FormatInt(entry.Bytes, 10)}},
									{Key: "audit.hash", Value: otlpAttributeVal{StringValue: entry.Hash}},
								},
							},
						},
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, o.cfg.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range o.cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: receiver returned status %d", resp.StatusCode)
	}
	return nil
}

// Close closes idle connections in the HTTP client.
func (o *OTLPExporter) Close() error {
	o.client.CloseIdleConnections()
	return nil
}

// AsyncExporter wraps an Exporter with a non-blocking queue and background worker,
// ensuring that network export never stalls or blocks gateway requests.
type AsyncExporter struct {
	inner        Exporter
	destination  string
	queue        chan exportItem
	done         chan struct{}
	wg           sync.WaitGroup
	drainTimeout time.Duration
	onError      func(destination string, err error)
	onSuccess    func(destination string)
}

type exportItem struct {
	chain string
	entry *Entry
}

// NewAsyncExporter creates an AsyncExporter with the given queue size and drain timeout.
// If drainTimeout <= 0, DefaultDrainTimeout is used.
func NewAsyncExporter(
	inner Exporter,
	destination string,
	queueSize int,
	drainTimeout time.Duration,
	onError func(dest string, err error),
	onSuccess func(dest string),
) *AsyncExporter {
	if queueSize <= 0 {
		queueSize = 2048
	}
	if drainTimeout <= 0 {
		drainTimeout = DefaultDrainTimeout
	}
	a := &AsyncExporter{
		inner:        inner,
		destination:  destination,
		queue:        make(chan exportItem, queueSize),
		done:         make(chan struct{}),
		drainTimeout: drainTimeout,
		onError:      onError,
		onSuccess:    onSuccess,
	}
	a.wg.Add(1)
	go a.worker()
	return a
}

// Export queues an entry for background export. If the queue is full, the entry
// is dropped and reported to onError without blocking.
func (a *AsyncExporter) Export(chain string, entry *Entry) error {
	select {
	case a.queue <- exportItem{chain: chain, entry: entry}:
		return nil
	default:
		err := fmt.Errorf("audit: %s export queue is full; dropping entry", a.destination)
		if a.onError != nil {
			a.onError(a.destination, err)
		}
		return nil
	}
}

func (a *AsyncExporter) worker() {
	defer a.wg.Done()
	for {
		select {
		case item := <-a.queue:
			if err := a.inner.Export(item.chain, item.entry); err != nil {
				if a.onError != nil {
					a.onError(a.destination, err)
				}
			} else if a.onSuccess != nil {
				a.onSuccess(a.destination)
			}
		case <-a.done:
			// Drain remaining queued items up to the deadline
			deadline := time.Now().Add(a.drainTimeout)
			for {
				select {
				case item := <-a.queue:
					if time.Now().After(deadline) {
						if a.onError != nil {
							a.onError(a.destination, fmt.Errorf("audit: %s export drain deadline exceeded; dropped entry", a.destination))
						}
						continue
					}
					if err := a.inner.Export(item.chain, item.entry); err != nil {
						if a.onError != nil {
							a.onError(a.destination, err)
						}
					} else if a.onSuccess != nil {
						a.onSuccess(a.destination)
					}
				default:
					return
				}
			}
		}
	}
}

// Close signals the worker to finish draining queued entries within the drain
// timeout, then closes the inner exporter.
func (a *AsyncExporter) Close() error {
	close(a.done)
	a.wg.Wait()
	return a.inner.Close()
}

// MultiExporter fans out exports to multiple exporters.
type MultiExporter []Exporter

// Export exports the entry to each exporter in the slice.
func (m MultiExporter) Export(chain string, entry *Entry) error {
	var firstErr error
	for _, exp := range m {
		if err := exp.Export(chain, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes each exporter in the slice.
func (m MultiExporter) Close() error {
	var firstErr error
	for _, exp := range m {
		if err := exp.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
