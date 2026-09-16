package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PayloadMode says how a request body is protected, which decides what has to be
// verified while it streams.
type PayloadMode int

// The payload modes a client may signal in x-amz-content-sha256.
const (
	// PayloadHashed means x-amz-content-sha256 carries the SHA-256 of the whole
	// body, which is checked as the body streams through.
	PayloadHashed PayloadMode = iota
	// PayloadUnsigned means the body is not covered by the signature. Accepted
	// only when configured, because without TLS it leaves the body unprotected
	// between client and proxy.
	PayloadUnsigned
	// PayloadStreamingSigned is aws-chunked with a signature per chunk.
	PayloadStreamingSigned
	// PayloadStreamingSignedTrailer adds a checksum trailer to the above.
	PayloadStreamingSignedTrailer
	// PayloadStreamingUnsignedTrailer is aws-chunked with only a checksum
	// trailer, which is what current AWS SDKs send by default.
	PayloadStreamingUnsignedTrailer
)

// Streaming reports whether the body is aws-chunked encoded.
func (m PayloadMode) Streaming() bool {
	switch m {
	case PayloadStreamingSigned, PayloadStreamingSignedTrailer, PayloadStreamingUnsignedTrailer:
		return true
	default:
		return false
	}
}

// Signed reports whether each aws-chunked chunk carries its own signature.
func (m PayloadMode) Signed() bool {
	return m == PayloadStreamingSigned || m == PayloadStreamingSignedTrailer
}

// Result describes a verified request.
type Result struct {
	Client        Client
	Authorization Authorization
	PayloadMode   PayloadMode
	// PayloadHash is the hex SHA-256 the client claims for the body, when the
	// mode is PayloadHashed.
	PayloadHash string
	// SigningKey and Seed are what an aws-chunked body needs to verify its
	// per-chunk signatures.
	SigningKey []byte
	Seed       string
	// Time is the request timestamp the signature was built with.
	Time time.Time
	// Presigned reports that the signature arrived in the query string rather
	// than the Authorization header. The proxy uses it to decide which
	// operations a URL may reach (ADR-019); nothing else branches on it.
	Presigned bool
}

// Config configures a Verifier.
type Config struct {
	Clients []Client
	// AllowUnsignedPayload permits UNSIGNED-PAYLOAD. It is off by default:
	// without it the body between client and proxy is protected by the
	// signature, and turning it on is only reasonable behind TLS or in a
	// sidecar, where the hop is already trusted.
	AllowUnsignedPayload bool
	// AllowPresign accepts signatures that arrive in the query string. Unlike
	// the switch above it defaults to on, because it removes a refusal of
	// something every S3 client expects rather than weakening a hop -- a
	// presigned URL can do nothing the credential that signed it could not
	// already do. What it does change is that a credential holder can now
	// delegate, which is why it can be turned off (ADR-019).
	AllowPresign bool
	// MaxPresignExpiry caps the window a presigned URL may name. Zero selects
	// MaxPresignExpiry, which is S3's own maximum of seven days; most
	// deployments should set something far shorter.
	MaxPresignExpiry time.Duration
}

// Verifier checks inbound SigV4 signatures.
type Verifier struct {
	registry             *Registry
	allowUnsignedPayload bool
	allowPresign         bool
	maxPresignExpiry     time.Duration
	// now is overridable so skew handling can be tested without sleeping.
	now func() time.Time
}

// NewVerifier builds a Verifier from cfg.
func NewVerifier(cfg Config) (*Verifier, error) {
	registry, err := NewRegistry(cfg.Clients)
	if err != nil {
		return nil, err
	}
	maxExpiry := cfg.MaxPresignExpiry
	if maxExpiry <= 0 {
		maxExpiry = MaxPresignExpiry
	}
	if maxExpiry > MaxPresignExpiry {
		return nil, fmt.Errorf("auth: max presign expiry %s exceeds S3's own maximum of %s",
			maxExpiry, MaxPresignExpiry)
	}
	return &Verifier{
		registry:             registry,
		allowUnsignedPayload: cfg.AllowUnsignedPayload,
		allowPresign:         cfg.AllowPresign,
		maxPresignExpiry:     maxExpiry,
		now:                  time.Now,
	}, nil
}

// Verify authenticates a request and reports how its body is protected.
//
// It does not read the body. Whatever the body needs -- a rolling SHA-256, chunk
// signatures, a trailing checksum -- is set up from the Result and checked while
// the body streams, so nothing has to be buffered.
func (v *Verifier) Verify(r *http.Request, bucket string) (*Result, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		// A signature in the query is a presigned URL. Checked before the
		// missing-header case so that one answers "not signed" only when nothing
		// signed it at all.
		if IsPresigned(r) {
			return v.verifyPresigned(r, bucket)
		}
		return nil, ErrMissingAuth
	}

	auth, err := ParseAuthorization(header)
	if err != nil {
		return nil, err
	}
	if !containsFold(auth.SignedHeaders, "host") {
		return nil, fmt.Errorf("%w: SignedHeaders must include host", ErrMalformedAuth)
	}

	signedAt, err := v.requestTime(r)
	if err != nil {
		return nil, err
	}
	if signedAt.UTC().Format(dateFormat) != auth.Credential.Date {
		return nil, fmt.Errorf("%w: timestamp %s does not match credential scope date %s",
			ErrMalformedAuth, signedAt.UTC().Format(dateFormat), auth.Credential.Date)
	}

	client, ok := v.registry.lookup(auth.Credential.AccessKeyID)
	if !ok {
		return nil, ErrUnknownAccessKey
	}

	mode, payloadHash, err := v.payloadMode(r)
	if err != nil {
		return nil, err
	}

	signingKey := SigningKey(client.SecretAccessKey, auth.Credential.Date, auth.Credential.Region)
	canonical := CanonicalRequest(r, auth.SignedHeaders, payloadHash)
	expected := Sign(signingKey, StringToSign(signedAt, auth.Credential.Scope(), canonical))

	if !equalSignature(expected, auth.Signature) {
		return nil, ErrSignatureMismatch
	}

	// Authorisation comes after authentication on purpose: an unauthenticated
	// caller must not be able to probe which buckets exist by watching which
	// error it gets.
	if bucket != "" && !client.MayAccess(bucket) {
		return nil, fmt.Errorf("%w: %q", ErrBucketNotAllowed, bucket)
	}

	return &Result{
		Client:        client,
		Authorization: auth,
		PayloadMode:   mode,
		PayloadHash:   payloadHash,
		SigningKey:    signingKey,
		Seed:          auth.Signature,
		Time:          signedAt,
	}, nil
}

// requestTime reads and range-checks the request timestamp.
func (v *Verifier) requestTime(r *http.Request) (time.Time, error) {
	raw := r.Header.Get("X-Amz-Date")
	if raw == "" {
		raw = r.Header.Get("Date")
	}
	if raw == "" {
		return time.Time{}, fmt.Errorf("%w: neither X-Amz-Date nor Date is present", ErrMalformedAuth)
	}

	t, err := time.Parse(amzDateFormat, raw)
	if err != nil {
		// Some clients send an RFC 1123 Date header instead.
		if rfc, rfcErr := http.ParseTime(raw); rfcErr == nil {
			t = rfc
		} else {
			return time.Time{}, fmt.Errorf("%w: timestamp %q is not a recognised format",
				ErrMalformedAuth, raw)
		}
	}

	if skew := v.now().UTC().Sub(t.UTC()); skew > MaxClockSkew || skew < -MaxClockSkew {
		return time.Time{}, fmt.Errorf("%w: off by %s", ErrRequestTimeTooSkewed, skew.Round(time.Second))
	}
	return t, nil
}

// payloadMode classifies the body protection the client chose.
func (v *Verifier) payloadMode(r *http.Request) (PayloadMode, string, error) {
	claimed := r.Header.Get("X-Amz-Content-Sha256")
	if claimed == "" {
		return 0, "", fmt.Errorf("%w: x-amz-content-sha256 is required", ErrMalformedAuth)
	}

	switch claimed {
	case UnsignedPayload:
		if !v.allowUnsignedPayload {
			return 0, "", fmt.Errorf("%w: UNSIGNED-PAYLOAD is not enabled on this listener",
				ErrUnsupportedPayload)
		}
		return PayloadUnsigned, claimed, nil
	case StreamingSigned:
		return PayloadStreamingSigned, claimed, nil
	case StreamingSignedTrailer:
		return PayloadStreamingSignedTrailer, claimed, nil
	case StreamingUnsignedTrail:
		return PayloadStreamingUnsignedTrailer, claimed, nil
	}

	if len(claimed) != 64 || !isHex(claimed) {
		return 0, "", fmt.Errorf("%w: x-amz-content-sha256 %q is neither a hash nor a known sentinel",
			ErrUnsupportedPayload, claimed)
	}
	return PayloadHashed, strings.ToLower(claimed), nil
}

func isHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		hexDigit := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		if !hexDigit {
			return false
		}
	}
	return true
}

func containsFold(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}
