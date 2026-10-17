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
	"sync"
	"time"
)

// DefaultDrainTimeout is how long AsyncExporter waits during shutdown to flush
// queued entries before dropping remaining entries. It bounds the whole of
// shutdown, an export in flight included: that one is cancelled at the deadline.
const DefaultDrainTimeout = 2 * time.Second

// MaxBatch is the most entries AsyncExporter hands its destination at once.
//
// One request per entry made an OTLP export as fast as the receiver's round
// trip and no faster: about 180 entries a second against a receiver answering
// in 5 ms, which a busy gateway exceeds, so a healthy receiver lost entries.
// Sending what queued up while the last send was in flight keeps the export up
// with the gateway, and costs nothing when there is little to send.
const MaxBatch = 512

// syslogTimeFormat is RFC 5424's TIMESTAMP: TIME-SECFRAC has at most six
// digits, so the file's nanoseconds are cut to microseconds.
const syslogTimeFormat = "2006-01-02T15:04:05.000000Z07:00"

// Exporter exports copies of audit entries to an external receiver.
// Implementations must be safe for concurrent use.
type Exporter interface {
	Export(chain string, entry *Entry) error
	Close() error
}

// queued is one entry on its way to a receiver, with the chain it belongs to.
// The entries of one batch can belong to two chains, either side of a rotation.
type queued struct {
	Chain string
	Entry *Entry
}

// batchSender is an exporter that can send several records at once, and be
// cancelled. Both exporters here are; an Exporter that is not is sent one
// entry at a time.
type batchSender interface {
	send(ctx context.Context, records []queued) error
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
	if !syslogHeaderField(cfg.AppName, 48) {
		return nil, fmt.Errorf("audit: syslog app_name %q is not 1 to 48 printable ASCII "+
			"characters without spaces (RFC 5424)", cfg.AppName)
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

	// A host name that does not fit the header is left out rather than allowed
	// to shift every field after it.
	hostname, err := os.Hostname()
	if err != nil || !syslogHeaderField(hostname, 255) {
		hostname = "-"
	}

	return &SyslogExporter{
		cfg:       cfg,
		tlsConfig: tlsConf,
		hostname:  hostname,
	}, nil
}

// syslogHeaderField reports whether s fits an RFC 5424 header field: 1 to
// maxLen printable ASCII characters, none of them a space.
func syslogHeaderField(s string, maxLen int) bool {
	if len(s) == 0 || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// format renders one record as an RFC 5424 message:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME - audit - {"chain":"...","seq":...,...}
//
// PROCID and STRUCTURED-DATA are the NILVALUE. The record's chain and seq are
// in the JSON message with everything else, and a structured-data element of
// its own would need an SD-ID registered to a private enterprise number, which
// this project does not have (RFC 5424 section 6.3.2).
func (s *SyslogExporter) format(r queued) (string, error) {
	body, err := json.Marshal(NewExportedEntry(r.Chain, r.Entry))
	if err != nil {
		return "", err
	}
	facility := 13 // log audit
	if s.cfg.Facility != nil {
		facility = *s.cfg.Facility
	}
	severity := 6 // informational
	if s.cfg.Severity != nil {
		severity = *s.cfg.Severity
	}
	timestamp := "-"
	if t, err := time.Parse(timeFormat, r.Entry.Time); err == nil {
		timestamp = t.UTC().Format(syslogTimeFormat)
	}
	return fmt.Sprintf("<%d>1 %s %s %s - audit - %s",
		facility*8+severity, timestamp, s.hostname, s.cfg.AppName, body), nil
}

// Export sends one entry; see send.
func (s *SyslogExporter) Export(chain string, entry *Entry) error {
	return s.send(context.Background(), []queued{{Chain: chain, Entry: entry}})
}

// send writes records as RFC 5425 frames -- MSG-LEN SP SYSLOG-MSG -- in one
// write over a persistent TLS connection. A write that fails on a connection
// the receiver has since dropped is retried once on a new one, so a receiver
// can see a record twice; seq tells the copies apart.
func (s *SyslogExporter) send(ctx context.Context, records []queued) error {
	var frames bytes.Buffer
	for _, r := range records {
		msg, err := s.format(r)
		if err != nil {
			return err
		}
		fmt.Fprintf(&frames, "%d %s", len(msg), msg)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	reused := s.conn != nil
	err := s.writeLocked(ctx, frames.Bytes())
	if err != nil && reused && ctx.Err() == nil {
		if retryErr := s.writeLocked(ctx, frames.Bytes()); retryErr != nil {
			return fmt.Errorf("write failed: %w (and again on a new connection: %w)", err, retryErr)
		}
		return nil
	}
	return err
}

func (s *SyslogExporter) writeLocked(ctx context.Context, b []byte) error {
	if s.conn == nil {
		dialCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
		dialer := &tls.Dialer{Config: s.tlsConfig}
		conn, err := dialer.DialContext(dialCtx, s.cfg.Network, s.cfg.Endpoint)
		if err != nil {
			return err
		}
		s.conn = conn
	}
	conn := s.conn
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
	// Cancelling ctx -- a shutdown past its deadline -- ends a blocked write.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetWriteDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(b); err != nil {
		_ = conn.Close()
		s.conn = nil
		return err
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

// Export sends one entry; see send.
func (o *OTLPExporter) Export(chain string, entry *Entry) error {
	return o.send(context.Background(), []queued{{Chain: chain, Entry: entry}})
}

// logRecord renders one record as an OTLP log record: the entry as JSON in
// the body, and each of its fields as an attribute.
func logRecord(r queued, observed int64) (otlpLogRecord, error) {
	entry := r.Entry
	body, err := json.Marshal(NewExportedEntry(r.Chain, entry))
	if err != nil {
		return otlpLogRecord{}, err
	}
	timeNano := observed
	if t, parseErr := time.Parse(timeFormat, entry.Time); parseErr == nil {
		timeNano = t.UnixNano()
	}

	severityNumber := 9 // INFO
	severityText := "INFO"
	if entry.Status >= 500 {
		severityNumber = 17 // ERROR
		severityText = "ERROR"
	} else if entry.Status >= 400 || entry.Code != "" {
		severityNumber = 13 // WARN
		severityText = "WARN"
	}

	return otlpLogRecord{
		TimeUnixNano:         strconv.FormatInt(timeNano, 10),
		ObservedTimeUnixNano: strconv.FormatInt(observed, 10),
		SeverityNumber:       severityNumber,
		SeverityText:         severityText,
		Body:                 otlpAnyValue{StringValue: string(body)},
		Attributes: []otlpKeyValue{
			{Key: "audit.chain", Value: otlpAttributeVal{StringValue: r.Chain}},
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
	}, nil
}

// send posts records to the logs endpoint in one request, a log record each.
func (o *OTLPExporter) send(ctx context.Context, records []queued) error {
	observed := time.Now().UnixNano()
	logRecords := make([]otlpLogRecord, 0, len(records))
	for _, r := range records {
		lr, err := logRecord(r, observed)
		if err != nil {
			return err
		}
		logRecords = append(logRecords, lr)
	}
	reqBody := otlpRequest{
		ResourceLogs: []otlpResourceLog{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{
					{Key: "service.name", Value: otlpAttributeVal{StringValue: "blindbucket"}},
				},
			},
			ScopeLogs: []otlpScopeLog{{
				Scope:      otlpScope{Name: "blindbucket.audit", Version: "1.0"},
				LogRecords: logRecords,
			}},
		}},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.Endpoint, bytes.NewReader(bodyBytes))
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
//
// The worker sends what queued up while its last send was in flight, up to
// MaxBatch entries at once, to an exporter that can send batches.
type AsyncExporter struct {
	inner        Exporter
	sender       batchSender
	destination  string
	queue        chan queued
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	drainTimeout time.Duration
	onError      func(destination string, err error)
	onSuccess    func(destination string)
	closeOnce    sync.Once
	closeErr     error
}

// NewAsyncExporter creates an AsyncExporter with the given queue size and drain timeout.
// If drainTimeout <= 0, DefaultDrainTimeout is used.
//
// onError is called once for every entry that was dropped or failed to send,
// and onSuccess once for every send that succeeded.
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
	ctx, cancel := context.WithCancel(context.Background())
	a := &AsyncExporter{
		inner:        inner,
		destination:  destination,
		queue:        make(chan queued, queueSize),
		done:         make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
		drainTimeout: drainTimeout,
		onError:      onError,
		onSuccess:    onSuccess,
	}
	a.sender, _ = inner.(batchSender)
	a.wg.Add(1)
	go a.worker()
	return a
}

// Export queues an entry for background export. If the queue is full, or the
// exporter is closed, the entry is dropped and reported to onError without
// blocking.
func (a *AsyncExporter) Export(chain string, entry *Entry) error {
	select {
	case <-a.done:
		a.failed(1, fmt.Errorf("audit: %s export is closed; dropping entry", a.destination))
		return nil
	default:
	}
	select {
	case a.queue <- queued{Chain: chain, Entry: entry}:
	default:
		a.failed(1, fmt.Errorf("audit: %s export queue is full; dropping entry", a.destination))
	}
	return nil
}

func (a *AsyncExporter) worker() {
	defer a.wg.Done()
	batch := make([]queued, 0, MaxBatch)
	for {
		select {
		case r := <-a.queue:
			a.deliver(a.fill(append(batch[:0], r)))
		case <-a.done:
			a.drain(batch)
			return
		}
	}
}

// fill adds to batch what is queued, without waiting for more.
func (a *AsyncExporter) fill(batch []queued) []queued {
	for len(batch) < MaxBatch {
		select {
		case r := <-a.queue:
			batch = append(batch, r)
		default:
			return batch
		}
	}
	return batch
}

// drain sends what is left at shutdown until the deadline cancels a.ctx, and
// counts the rest as dropped.
func (a *AsyncExporter) drain(batch []queued) {
	for {
		batch = a.fill(batch[:0])
		if len(batch) == 0 {
			return
		}
		if a.ctx.Err() != nil {
			a.failed(len(batch), fmt.Errorf("audit: %s export drain deadline exceeded; dropped entries", a.destination))
			continue
		}
		a.deliver(batch)
	}
}

func (a *AsyncExporter) deliver(batch []queued) {
	if a.sender != nil {
		if err := a.sender.send(a.ctx, batch); err != nil {
			a.failed(len(batch), err)
		} else if a.onSuccess != nil {
			a.onSuccess(a.destination)
		}
		return
	}
	for i, r := range batch {
		// An Exporter that cannot be cancelled is at least not started on
		// once the shutdown deadline has passed.
		if a.ctx.Err() != nil {
			a.failed(len(batch)-i, fmt.Errorf("audit: %s export drain deadline exceeded; dropped entries", a.destination))
			return
		}
		if err := a.inner.Export(r.Chain, r.Entry); err != nil {
			a.failed(1, err)
		} else if a.onSuccess != nil {
			a.onSuccess(a.destination)
		}
	}
}

func (a *AsyncExporter) failed(n int, err error) {
	if a.onError == nil {
		return
	}
	for range n {
		a.onError(a.destination, err)
	}
}

// Close sends what is queued, for at most the drain timeout -- a send still in
// flight then is cancelled -- and closes the inner exporter.
func (a *AsyncExporter) Close() error {
	a.closeOnce.Do(func() {
		close(a.done)
		deadline := time.AfterFunc(a.drainTimeout, a.cancel)
		a.wg.Wait()
		deadline.Stop()
		a.cancel()
		a.closeErr = a.inner.Close()
	})
	return a.closeErr
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
