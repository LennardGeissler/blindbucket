package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The query parameters that carry a SigV4 signature in a URL: six always,
// and the payload hash when the signer puts it there.
//
// They are named here rather than matched by prefix because the router has to
// know them too: it refuses any query parameter it does not recognise, and
// guessing at an unknown one would be worse than refusing (docs/adr/ADR-019).
const (
	QueryAlgorithm = "X-Amz-Algorithm"
	// The name of a query parameter, not a credential: it carries the access key
	// id and the scope a signature was built under, which are public by design.
	QueryCredential = "X-Amz-Credential" //nolint:gosec // a parameter name.

	QueryDate          = "X-Amz-Date"
	QueryExpires       = "X-Amz-Expires"
	QuerySignedHeaders = "X-Amz-SignedHeaders"
	QuerySignature     = "X-Amz-Signature"

	// QueryContentSHA256 is the payload hash, when a signer puts it in the URL.
	// The AWS SDK for JavaScript v3 does, as UNSIGNED-PAYLOAD, in every URL it
	// presigns; boto3 leaves it out. It is covered by the signature like any
	// other query parameter.
	QueryContentSHA256 = "X-Amz-Content-Sha256"
)

// MaxPresignExpiry is the longest window S3 itself permits, and the ceiling this
// gateway will accept whatever it is configured with.
const MaxPresignExpiry = 7 * 24 * time.Hour

// DefaultPresignUploadExpiry is the longest window a presigned PUT may name
// unless configured otherwise. An hour covers what the SDKs default to -- boto3
// 3600 seconds, JavaScript v3 900 -- and no more (ADR-036).
const DefaultPresignUploadExpiry = time.Hour

// Presigned verification failures.
var (
	// ErrPresignDisabled reports a query-signed request against a listener that
	// does not serve them.
	ErrPresignDisabled = errors.New("auth: presigned URLs are not enabled on this listener")
	// ErrPresignExpired reports a URL used outside its window. It is separate
	// from ErrRequestTimeTooSkewed because the two bound different things: skew
	// is the server's tolerance for a clock, expiry is the signer's own choice.
	ErrPresignExpired = errors.New("auth: the presigned URL has expired")
	// ErrPresignMalformed reports a query that does not carry a usable signature.
	ErrPresignMalformed = errors.New("auth: malformed presigned URL")
)

// IsPresigned reports whether a request carries its signature in the query.
func IsPresigned(r *http.Request) bool {
	return r.URL.Query().Get(QuerySignature) != ""
}

// PresignQueryParam reports whether a query parameter is part of a presigned
// URL's signature rather than a sub-resource selector.
func PresignQueryParam(name string) bool {
	switch name {
	case QueryAlgorithm, QueryCredential, QueryDate, QueryExpires,
		QuerySignedHeaders, QuerySignature, QueryContentSHA256:
		return true
	}
	return false
}

// StripPresignParams returns query without the presigning parameters.
//
// Anything forwarded to the provider has to go through this. The gateway signs
// its upstream requests itself, and a client's signature parameters arriving
// alongside the gateway's own would at best be a request the provider rejects
// and at worst one it reads as a second, conflicting authentication.
func StripPresignParams(query url.Values) url.Values {
	out := make(url.Values, len(query))
	for name, values := range query {
		if PresignQueryParam(name) {
			continue
		}
		out[name] = values
	}
	return out
}

// presignParams is the parsed content of those parameters.
type presignParams struct {
	credential    Credential
	signedHeaders []string
	signature     string
	signedAt      time.Time
	expires       time.Duration
}

// parsePresign reads and range-checks the presigning parameters.
func parsePresign(query url.Values) (presignParams, error) {
	var p presignParams

	if got := query.Get(QueryAlgorithm); got != algorithm {
		return p, fmt.Errorf("%w: %s is %q, want %q",
			ErrPresignMalformed, QueryAlgorithm, got, algorithm)
	}

	credential, err := parseCredential(query.Get(QueryCredential))
	if err != nil {
		return p, err
	}
	p.credential = credential

	p.signature = query.Get(QuerySignature)
	if p.signature == "" {
		return p, fmt.Errorf("%w: %s is empty", ErrPresignMalformed, QuerySignature)
	}

	raw := query.Get(QuerySignedHeaders)
	if raw == "" {
		return p, fmt.Errorf("%w: %s is empty", ErrPresignMalformed, QuerySignedHeaders)
	}
	p.signedHeaders = strings.Split(raw, ";")
	if !containsFold(p.signedHeaders, "host") {
		return p, fmt.Errorf("%w: %s must include host", ErrPresignMalformed, QuerySignedHeaders)
	}

	signedAt, err := time.Parse(amzDateFormat, query.Get(QueryDate))
	if err != nil {
		return p, fmt.Errorf("%w: %s %q is not an ISO8601 basic timestamp",
			ErrPresignMalformed, QueryDate, query.Get(QueryDate))
	}
	p.signedAt = signedAt

	seconds, err := strconv.ParseInt(query.Get(QueryExpires), 10, 64)
	if err != nil || seconds <= 0 {
		return p, fmt.Errorf("%w: %s %q is not a positive number of seconds",
			ErrPresignMalformed, QueryExpires, query.Get(QueryExpires))
	}
	p.expires = time.Duration(seconds) * time.Second

	// A presigned body does not exist when the URL is signed, so the only
	// payload hash a URL can carry is the literal. A hex hash would ask for a
	// body bound by the signature, which no SDK produces and this gateway
	// would have to verify differently.
	if got := query.Get(QueryContentSHA256); got != "" && got != UnsignedPayload {
		return p, fmt.Errorf("%w: %s is %q; a presigned URL may carry only %s",
			ErrPresignMalformed, QueryContentSHA256, got, UnsignedPayload)
	}

	if signedAt.UTC().Format(dateFormat) != credential.Date {
		return p, fmt.Errorf("%w: timestamp %s does not match credential scope date %s",
			ErrPresignMalformed, signedAt.UTC().Format(dateFormat), credential.Date)
	}
	return p, nil
}

// checkWindow decides whether a presigned URL may be used now.
//
// This is deliberately not the clock-skew rule that governs header-signed
// requests, and the difference is the whole point of the feature. A presigned URL
// is meant to be used long after it was signed -- up to seven days -- so applying
// MaxClockSkew here would refuse every one of them a quarter of an hour in.
//
//	signedAt - MaxClockSkew  <=  now  <=  signedAt + expires
//
// The lower bound is the signer's clock running ahead of ours; the upper is the
// window the signer chose. Both bounds are covered by the signature, so a holder
// of the URL can lengthen neither.
//
// A PUT is held to the upload cap, which is shorter by default: it can write
// again and again until it expires.
func (v *Verifier) checkWindow(p presignParams, method string) error {
	if method == http.MethodPut && p.expires > v.maxUploadExpiry {
		return fmt.Errorf("%w: %s is %s, and this gateway accepts at most %s for an upload",
			ErrPresignExpired, QueryExpires, p.expires, v.maxUploadExpiry)
	}
	if p.expires > v.maxPresignExpiry {
		return fmt.Errorf("%w: %s is %s, and this gateway accepts at most %s",
			ErrPresignExpired, QueryExpires, p.expires, v.maxPresignExpiry)
	}
	now := v.now().UTC()
	signedAt := p.signedAt.UTC()
	if now.Before(signedAt.Add(-MaxClockSkew)) {
		return fmt.Errorf("%w: signed %s in the future",
			ErrRequestTimeTooSkewed, signedAt.Sub(now).Round(time.Second))
	}
	if expiry := signedAt.Add(p.expires); now.After(expiry) {
		return fmt.Errorf("%w: it expired %s ago", ErrPresignExpired,
			now.Sub(expiry).Round(time.Second))
	}
	return nil
}

// verifyPresigned authenticates a request whose signature arrived in the query.
//
// The canonical request differs from the header-signed one in exactly three
// places, all of them from the SigV4 specification: the query it covers omits
// X-Amz-Signature, the signed headers come from X-Amz-SignedHeaders, and the
// payload hash is the literal UNSIGNED-PAYLOAD because at signing time there was
// no body to hash. Everything after that is the same code path.
func (v *Verifier) verifyPresigned(r *http.Request, bucket string) (*Result, error) {
	if !v.allowPresign {
		return nil, ErrPresignDisabled
	}

	query := r.URL.Query()
	p, err := parsePresign(query)
	if err != nil {
		return nil, err
	}
	if err := v.checkWindow(p, r.Method); err != nil {
		return nil, err
	}

	client, ok := v.registry.lookup(p.credential.AccessKeyID)
	if !ok {
		return nil, ErrUnknownAccessKey
	}

	// Everything but the signature itself, which cannot cover itself.
	signed := make(url.Values, len(query))
	for name, values := range query {
		if name != QuerySignature {
			signed[name] = values
		}
	}

	signingKey := SigningKey(client.SecretAccessKey, p.credential.Date, p.credential.Region)
	canonical := CanonicalRequestWithQuery(r, signed, p.signedHeaders, UnsignedPayload)
	expected := Sign(signingKey, StringToSign(p.signedAt, p.credential.Scope(), canonical))

	if !equalSignature(expected, p.signature) {
		return nil, ErrSignatureMismatch
	}

	// Authorisation after authentication, as on the header path: an
	// unauthenticated caller must not learn which buckets exist from which error
	// it gets back.
	if bucket != "" && !client.MayAccess(bucket) {
		return nil, fmt.Errorf("%w: %q", ErrBucketNotAllowed, bucket)
	}

	return &Result{
		Client: client,
		Authorization: Authorization{
			Credential:    p.credential,
			SignedHeaders: p.signedHeaders,
			Signature:     p.signature,
		},
		// The signature covers no body: a presigned upload's is unsigned, and
		// what bounds it is the proxy's size limit and whatever checksum the
		// URL binds (ADR-036). The operations a presigned URL may reach are
		// gated in the proxy, which is where the operation is known.
		PayloadMode: PayloadUnsigned,
		SigningKey:  signingKey,
		Seed:        p.signature,
		Time:        p.signedAt,
		Presigned:   true,
	}, nil
}
