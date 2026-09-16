package obs

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Byte directions for blindbucket_bytes_total.
//
// The four are kept apart because their ratio is the thing worth watching: the
// gap between plaintext in and ciphertext out is the format's overhead, and a
// gap that moves without a configuration change means something else did.
const (
	InPlain   = "in_plain"   // plaintext read from a client
	OutCipher = "out_cipher" // ciphertext written to the provider
	InCipher  = "in_cipher"  // ciphertext read from the provider
	OutPlain  = "out_plain"  // plaintext written to a client
)

// Stream directions for blindbucket_active_streams.
const (
	Upload   = "upload"
	Download = "download"
)

// Kinds of integrity failure, for blindbucket_integrity_failures_total.
//
// A rise in any of them means either a bug here or a provider modifying stored
// data, and the two are worth telling apart from an ordinary 5xx.
const (
	KindChunk     = "chunk"
	KindHeader    = "header"
	KindDEKUnwrap = "dek_unwrap"
	KindManifest  = "manifest"
	KindToken     = "token"
	KindSize      = "size"
	KindFreshness = "freshness"
)

// Metrics is the gateway's instrument panel.
//
// A nil *Metrics is usable and records nothing, so a caller that was built
// without observability does not need a branch at every call site.
type Metrics struct {
	requests          *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	upstreamDuration  *prometheus.HistogramVec
	bytes             *prometheus.CounterVec
	activeStreams     *prometheus.GaugeVec
	integrityFailures *prometheus.CounterVec
	authFailures      *prometheus.CounterVec
	checksumMismatch  *prometheus.CounterVec
	auditFailures     prometheus.Counter
	auditBroken       prometheus.Gauge
	keyringKeys       prometheus.Gauge
	keyringCreated    *prometheus.GaugeVec
}

// KeyringInfo is what this package needs to know about a keyring. It is an
// interface so that observability stays out of the crypto packages' import
// graph, in the direction ADR-002 keeps them.
type KeyringInfo interface {
	KIDs() []string
	ActiveKID() string
	Created(kid string) (time.Time, bool)
}

// NewMetrics registers the collectors and returns them.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	factory := promauto{reg}
	return &Metrics{
		requests: factory.counterVec(prometheus.CounterOpts{
			Name: "blindbucket_requests_total",
			Help: "S3 requests served, by operation and HTTP status.",
		}, []string{"op", "status"}),

		requestDuration: factory.histogramVec(prometheus.HistogramOpts{
			Name: "blindbucket_request_duration_seconds",
			Help: "Time to serve an S3 request, by operation.",
			// Reaches into minutes on purpose: a multi-gigabyte GET is a normal
			// request here, and the default buckets stop at ten seconds.
			Buckets: []float64{0.001, 0.005, 0.025, 0.1, 0.5, 1, 5, 30, 120, 600},
		}, []string{"op"}),

		upstreamDuration: factory.histogramVec(prometheus.HistogramOpts{
			Name:    "blindbucket_upstream_duration_seconds",
			Help:    "Time spent in a call to the storage provider, by operation.",
			Buckets: []float64{0.001, 0.005, 0.025, 0.1, 0.5, 1, 5, 30, 120, 600},
		}, []string{"op"}),

		bytes: factory.counterVec(prometheus.CounterOpts{
			Name: "blindbucket_bytes_total",
			Help: "Bytes moved, by direction: in_plain, out_cipher, in_cipher, out_plain.",
		}, []string{"direction"}),

		activeStreams: factory.gaugeVec(prometheus.GaugeOpts{
			Name: "blindbucket_active_streams",
			Help: "Streams in flight. Memory is a function of this, not of object size.",
		}, []string{"direction"}),

		integrityFailures: factory.counterVec(prometheus.CounterOpts{
			Name: "blindbucket_integrity_failures_total",
			Help: "Stored data that failed authentication. A rise means a bug or a " +
				"provider modifying objects, and should alert.",
		}, []string{"kind"}),

		authFailures: factory.counterVec(prometheus.CounterOpts{
			Name: "blindbucket_auth_failures_total",
			Help: "Inbound requests that failed signature verification, by reason.",
		}, []string{"reason"}),

		checksumMismatch: factory.counterVec(prometheus.CounterOpts{
			Name: "blindbucket_checksum_mismatches_total",
			Help: "Uploads whose end-to-end checksum did not match, by algorithm.",
		}, []string{"algorithm"}),

		// Two metrics rather than one, because they answer different questions.
		// The counter says how many records were lost; the gauge says whether
		// the gateway is currently refusing traffic over it, which is the one an
		// alert should fire on.
		auditFailures: factory.counter(prometheus.CounterOpts{
			Name: "blindbucket_audit_failures_total",
			Help: "Requests the audit log could not record. Any value above zero " +
				"means the log has a gap and should alert.",
		}),

		auditBroken: factory.gauge(prometheus.GaugeOpts{
			Name: "blindbucket_audit_broken",
			Help: "1 while the audit log cannot be written. With fail_closed the " +
				"gateway is refusing requests.",
		}),

		// Key age is the input to a rotation decision, and until these existed
		// the only way to see it was to open the keyring by hand. A creation
		// timestamp rather than an age, because a gauge that has to be
		// refreshed to stay true is a gauge that will be wrong: `time() -
		// blindbucket_keyring_key_created_timestamp_seconds` is the age, at
		// scrape time, without this process doing anything.
		keyringKeys: factory.gauge(prometheus.GaugeOpts{
			Name: "blindbucket_keyring_keys",
			Help: "Key-encryption keys in the loaded keyring. Keys accumulate " +
				"until `blindbucket keys remove` retires one.",
		}),

		keyringCreated: factory.gaugeVec(prometheus.GaugeOpts{
			Name: "blindbucket_keyring_key_created_timestamp_seconds",
			Help: "When each key-encryption key was created, as a Unix timestamp. " +
				"Absent for keys whose keyring records no date.",
		}, []string{"kid", "active"}),
	}
}

// KeyringLoaded records the keyring the gateway started with.
//
// Called once, at startup: a keyring only changes through the CLI, and that
// takes a restart to reach a running gateway. The label cardinality is the
// number of KEKs in the file, which is a handful.
func (m *Metrics) KeyringLoaded(ring KeyringInfo) {
	if m == nil || ring == nil {
		return
	}
	kids := ring.KIDs()
	m.keyringKeys.Set(float64(len(kids)))
	m.keyringCreated.Reset()
	for _, kid := range kids {
		created, ok := ring.Created(kid)
		if !ok || created.IsZero() {
			continue
		}
		active := "false"
		if kid == ring.ActiveKID() {
			active = "true"
		}
		m.keyringCreated.WithLabelValues(kid, active).Set(float64(created.Unix()))
	}
}

// Request records one served request.
func (m *Metrics) Request(op string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues(op, statusLabel(status)).Inc()
	m.requestDuration.WithLabelValues(op).Observe(d.Seconds())
}

// Upstream records one call to the storage provider.
func (m *Metrics) Upstream(op string, d time.Duration) {
	if m == nil {
		return
	}
	m.upstreamDuration.WithLabelValues(op).Observe(d.Seconds())
}

// Bytes records bytes moved in one direction.
func (m *Metrics) Bytes(direction string, n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.bytes.WithLabelValues(direction).Add(float64(n))
}

// StreamStarted records a stream entering flight.
func (m *Metrics) StreamStarted(direction string) {
	if m != nil {
		m.activeStreams.WithLabelValues(direction).Inc()
	}
}

// StreamFinished records a stream leaving flight. Every StreamStarted needs
// exactly one of these, or the gauge drifts and stops meaning anything.
func (m *Metrics) StreamFinished(direction string) {
	if m != nil {
		m.activeStreams.WithLabelValues(direction).Dec()
	}
}

// IntegrityFailure records stored data that failed authentication.
func (m *Metrics) IntegrityFailure(kind string) {
	if m != nil {
		m.integrityFailures.WithLabelValues(kind).Inc()
	}
}

// AuthFailure records a request that failed verification.
func (m *Metrics) AuthFailure(reason string) {
	if m != nil {
		m.authFailures.WithLabelValues(reason).Inc()
	}
}

// AuditFailure records a request the audit log could not record.
//
// It also raises blindbucket_audit_broken, because the writer is sticky: one
// failed append means every later one fails too, until an operator intervenes.
func (m *Metrics) AuditFailure() {
	if m != nil {
		m.auditFailures.Inc()
		m.auditBroken.Set(1)
	}
}

// ChecksumMismatch records an upload whose checksum did not match.
func (m *Metrics) ChecksumMismatch(algorithm string) {
	if m != nil {
		m.checksumMismatch.WithLabelValues(algorithm).Inc()
	}
}

// statusLabel buckets a status by class.
//
// The exact code is in the logs; as a metric label it would be unbounded enough
// to matter and is not what an alert looks at.
func statusLabel(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return "other"
	}
}

// promauto registers each collector as it is built, so a duplicate name is a
// panic at startup rather than a metric that silently never appears.
type promauto struct{ reg prometheus.Registerer }

func (p promauto) counterVec(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(opts, labels)
	p.register(c)
	return c
}

func (p promauto) counter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	p.register(c)
	return c
}

func (p promauto) gauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	p.register(g)
	return g
}

func (p promauto) histogramVec(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(opts, labels)
	p.register(h)
	return h
}

func (p promauto) gaugeVec(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(opts, labels)
	p.register(g)
	return g
}

func (p promauto) register(c prometheus.Collector) {
	if p.reg == nil {
		return
	}
	p.reg.MustRegister(c)
}
