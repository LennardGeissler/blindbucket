// Package proxy implements the S3 operations blindbucket serves, translating
// between a plaintext-speaking client and a ciphertext-only upstream.
package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/freshness"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/obs"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// errNotEncrypted reports an upstream object that blindbucket did not write.
var errNotEncrypted = objectmeta.ErrNotEncrypted

// errNotEncryptedAPI is what a client sees for such an object.
var errNotEncryptedAPI = &s3api.Error{
	Code:       "ObjectNotEncrypted",
	Message:    "The object was not written by this gateway and cannot be decrypted.",
	HTTPStatus: http.StatusBadGateway,
}

// Config configures a Proxy.
type Config struct {
	Upstream *upstream.Client
	Keys     keys.KeyProvider
	// Verifier authenticates inbound requests. It is required: a gateway that
	// can be configured to serve unauthenticated requests will eventually be
	// deployed that way by accident.
	Verifier *auth.Verifier
	// BaseDomain enables virtual-hosted-style addressing.
	BaseDomain string
	// Log2ChunkSize is the chunk size new objects are written with, and the
	// fallback for reading objects whose metadata does not record one.
	Log2ChunkSize uint8
	Logger        *slog.Logger
	// Metrics records what the gateway did. A nil value records nothing, which
	// is what the tests use.
	Metrics *obs.Metrics
	// StallTimeout is how long a transfer may make no progress before its
	// connection is dropped. Zero selects defaultStallTimeout.
	StallTimeout time.Duration
	// Audit records what the gateway served, in a hash-chained and signed log
	// (ADR-016). A nil value records nothing, which is the default: a gateway
	// that wrote an audit log nobody asked for would produce something that
	// looks like evidence without being any.
	// Names maps object keys to the keys the provider stores them under
	// (ADR-015). Nil leaves names in clear, which is the default.
	Names *names.Encrypter
	// MaxListingKeys and MaxConcurrentListings bound the buffered listing tier
	// of ADR-017. Zero means the default.
	MaxListingKeys        int
	MaxConcurrentListings int

	Audit *audit.Writer
	// AuditFailClosed refuses requests once the audit log cannot be written,
	// rather than serving on with a record known to be incomplete.
	AuditFailClosed bool

	// Freshness detects rollback: a provider serving an older but genuine
	// version of an object (ADR-018). Nil detects nothing, which is the default
	// -- the index is memory proportional to live objects, and in a deployment
	// where several instances write the same objects it cannot tell a rollback
	// from a peer's write.
	Freshness freshness.Store
}

// Proxy serves the S3 API, encrypting on the way in and decrypting on the way
// out.
type Proxy struct {
	upstream   *upstream.Client
	keys       keys.KeyProvider
	verifier   *auth.Verifier
	baseDomain string
	log2C      uint8
	log        *slog.Logger
	metrics    *obs.Metrics
	stall      time.Duration

	names          *names.Encrypter
	maxListingKeys int
	// listings bounds concurrent buffered listings; the memory a listing holds
	// is per listing in flight, so a per-prefix bound alone does not bound the
	// process.
	listings  chan struct{}
	listCache *listingCache

	audit           *audit.Writer
	auditFailClosed bool

	fresh freshness.Store

	// hook is called at the coordination points named in hooks.go. It exists so
	// that the integration tests can replay the model's counterexamples, and is
	// nil everywhere else.
	hook func(point string, req s3api.Request)
}

// New validates cfg and builds a Proxy.
func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Upstream == nil:
		return nil, errors.New("proxy: an upstream client is required")
	case cfg.Keys == nil:
		return nil, errors.New("proxy: a key provider is required")
	case cfg.Verifier == nil:
		return nil, errors.New("proxy: a request verifier is required")
	}
	log2C := cfg.Log2ChunkSize
	if log2C == 0 {
		log2C = stream.DefaultLog2ChunkSize
	}
	if err := stream.ValidateLog2ChunkSize(log2C); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxListingKeys := cfg.MaxListingKeys
	if maxListingKeys <= 0 {
		maxListingKeys = defaultMaxListingKeys
	}
	maxConcurrent := cfg.MaxConcurrentListings
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentListings
	}
	return &Proxy{
		upstream:   cfg.Upstream,
		keys:       cfg.Keys,
		verifier:   cfg.Verifier,
		baseDomain: cfg.BaseDomain,
		log2C:      log2C,
		log:        logger,
		metrics:    cfg.Metrics,
		stall:      cfg.StallTimeout,

		names:          cfg.Names,
		maxListingKeys: maxListingKeys,
		listings:       make(chan struct{}, maxConcurrent),
		listCache:      newListingCache(listingCacheTTL, maxConcurrent*2),

		audit:           cfg.Audit,
		auditFailClosed: cfg.AuditFailClosed,
		fresh:           cfg.Freshness,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	w.Header().Set("x-amz-request-id", requestID)

	// Counting here rather than in each handler means a new operation is
	// instrumented by existing, and a handler that returns early still counts.
	started := time.Now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	w = recorder

	// req and client are read by the deferred audit record below, which is why
	// they are declared here rather than at the point they are first known.
	var (
		req    s3api.Request
		client string
	)
	if p.audit != nil {
		var facts *auditFacts
		r, facts = withAuditFacts(r)
		// Deferred, so that every exit records: an early routing failure, a
		// rejected signature, a served request, and -- because the panic of
		// ADR-004 unwinds through here -- a download aborted mid-body.
		defer func() { p.recordRequest(req, requestID, client, recorder.status, facts, started) }()
	}

	// A broken audit log refuses the request before the provider is touched.
	if apiErr := p.auditGate(); apiErr != nil {
		p.fail(w, r, requestID, req, apiErr)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}

	req, apiErr := s3api.Route(r, p.baseDomain)
	if apiErr != nil {
		p.fail(w, r, requestID, req, apiErr)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}

	log := p.log.With(
		"request_id", requestID,
		"op", string(req.Op),
		"bucket", req.Bucket,
		"key", req.Key,
	)

	// Authentication comes before anything that touches the provider, so an
	// unsigned request cannot be used to probe what exists.
	authResult, authErr := p.verifier.Verify(r, req.Bucket)
	if authErr != nil {
		log.Warn("rejecting a request that failed verification", "err", authErr)
		translated := translateAuth(authErr)
		p.metrics.AuthFailure(translated.Code)
		p.notePrincipal(r, attemptedAccessKeyID(r))
		p.fail(w, r, requestID, req, translated)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}
	client = authResult.Client.Name
	log = log.With("client", client)

	var err *s3api.Error
	if gate := p.presignGate(authResult.Presigned, req.Op); gate != nil {
		log.Warn("refusing an operation a presigned URL may not reach")
		p.fail(w, r, requestID, req, gate)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}
	if gate := p.nameEncryptionGate(req.Op); gate != nil {
		p.fail(w, r, requestID, req, gate)
		p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
		return
	}
	switch req.Op {
	case s3api.OpPutObject:
		err = p.putObject(w, r, req, authResult, log)
	case s3api.OpCopyObject:
		err = p.copyObject(w, r, req, authResult, log)
	case s3api.OpGetObject:
		err = p.getObject(w, r, req, log)
	case s3api.OpHeadObject:
		err = p.headObject(w, r, req, log)
	case s3api.OpDeleteObject:
		err = p.deleteObject(w, r, req, log)
	case s3api.OpGetObjectTagging:
		err = p.getObjectTagging(w, r, req, log)
	case s3api.OpListObjectsV2, s3api.OpListObjects:
		err = p.listObjects(w, r, req, log)
	case s3api.OpDeleteObjects:
		err = p.deleteObjects(w, r, req, log)
	case s3api.OpCreateMultipartUpload:
		err = p.createMultipartUpload(w, r, req, log)
	case s3api.OpUploadPart:
		err = p.uploadPart(w, r, req, authResult, log)
	case s3api.OpUploadPartCopy:
		err = p.uploadPartCopy(w, r, req, authResult, log)
	case s3api.OpCompleteMultipartUpload:
		err = p.completeMultipartUpload(w, r, req, log)
	case s3api.OpAbortMultipartUpload:
		err = p.abortMultipartUpload(w, r, req, log)
	case s3api.OpListParts:
		err = p.listParts(w, r, req, log)
	case s3api.OpListMultipartUploads:
		err = p.listMultipartUploads(w, r, req)
	case s3api.OpListBuckets, s3api.OpHeadBucket, s3api.OpCreateBucket,
		s3api.OpDeleteBucket, s3api.OpGetBucketLocation:
		err = p.passthrough(w, r, req, log)
	default:
		err = s3api.ErrNotImplemented
	}
	if err != nil {
		p.fail(w, r, requestID, req, err)
	}
	p.metrics.Request(string(req.Op), recorder.status, time.Since(started))
}

// statusRecorder remembers the status a handler wrote.
//
// It does not wrap Write beyond the implicit 200, because the byte counts are
// recorded where the plaintext and the ciphertext are actually distinguishable,
// which this layer cannot do.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if !r.written {
		r.status, r.written = status, true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

// Unwrap lets net/http reach the underlying writer for Flush and the like.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// fail logs and renders an error response.
func (p *Proxy) fail(w http.ResponseWriter, r *http.Request, requestID string, req s3api.Request, apiErr *s3api.Error) {
	// A 501 is a documented limit of this build, not a fault: logging it at
	// error level would make an alert fire every time a client tries a feature
	// that is simply not here yet.
	level := slog.LevelWarn
	if apiErr.HTTPStatus >= http.StatusInternalServerError &&
		apiErr.HTTPStatus != http.StatusNotImplemented {
		level = slog.LevelError
	}
	p.log.Log(r.Context(), level, "request failed",
		"request_id", requestID, "op", string(req.Op), "bucket", req.Bucket, "key", req.Key,
		"code", apiErr.Code, "status", apiErr.HTTPStatus, "detail", apiErr.Message)
	p.noteCode(r, apiErr.Code)
	s3api.WriteError(w, r, apiErr, requestID)
}

// attemptedAccessKeyID recovers the identity a rejected request claimed.
//
// It reads the credential field directly instead of going through
// auth.ParseAuthorization, and that is deliberate rather than lazy. The verifier
// is strict because it must be: a header whose signature is the wrong length is
// not a request it will ever accept. But a *rejected* request is precisely the
// one an audit log exists to record, and the headers attackers send are
// malformed far more often than not. Requiring a well-formed header here would
// leave the log silent about exactly the traffic worth seeing.
//
// The result is attacker-controlled and is bounded and stripped of control
// characters by the audit writer before it is recorded.
func attemptedAccessKeyID(r *http.Request) string {
	if id := credentialOf(r.Header.Get("Authorization"), "Credential="); id != "" {
		return id
	}
	// A presigned URL carries it in the query instead. This build refuses those
	// (auth.ErrUnsupportedPayload), which does not make who tried less worth
	// recording.
	return credentialOf(r.URL.Query().Get("X-Amz-Credential"), "")
}

// credentialOf pulls the access key id out of a SigV4 credential scope.
//
// The scope is "<id>/<date>/<region>/<service>/aws4_request", so the id is
// everything up to the first separator -- and a value with no separator at all
// is taken whole, because a caller that sent only an id still named one.
func credentialOf(value, prefix string) string {
	if prefix != "" {
		_, rest, found := strings.Cut(value, prefix)
		if !found {
			return ""
		}
		value = rest
	}
	if i := strings.IndexAny(value, "/, \t"); i >= 0 {
		value = value[:i]
	}
	return value
}

// newRequestID returns an opaque id echoed to the client and carried in logs.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
