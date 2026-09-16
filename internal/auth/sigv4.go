// Package auth verifies inbound requests: SigV4 signatures, aws-chunked bodies
// and the payload checksums modern SDKs attach.
//
// The verification is written here rather than taken from the AWS SDK, which
// only signs. Having both in one binary is useful: the tests sign a request with
// the SDK and require this code to accept it, so the canonicalisation is checked
// against a reference implementation rather than against itself.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SigV4 constants.
const (
	algorithm  = "AWS4-HMAC-SHA256"
	terminator = "aws4_request"
	service    = "s3"

	// amzDateFormat is the ISO8601 basic format SigV4 uses.
	amzDateFormat = "20060102T150405Z"
	// dateFormat is the day portion used in the credential scope.
	dateFormat = "20060102"

	// MaxClockSkew is how far a request timestamp may be from the server's
	// clock. S3 uses fifteen minutes; the bound is what stops a captured
	// signature being replayed indefinitely.
	MaxClockSkew = 15 * time.Minute
)

// Payload hash sentinels a client may send in x-amz-content-sha256.
const (
	UnsignedPayload        = "UNSIGNED-PAYLOAD"
	StreamingSigned        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	StreamingSignedTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	StreamingUnsignedTrail = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// Credential is the scope portion of an Authorization header.
type Credential struct {
	AccessKeyID string
	Date        string
	Region      string
	Service     string
	Terminator  string
}

// Scope renders the credential scope as it appears in the string to sign.
func (c Credential) Scope() string {
	return strings.Join([]string{c.Date, c.Region, c.Service, c.Terminator}, "/")
}

// Authorization is a parsed SigV4 Authorization header.
type Authorization struct {
	Credential    Credential
	SignedHeaders []string
	Signature     string
}

// ParseAuthorization parses the Authorization header of a signed request.
func ParseAuthorization(header string) (Authorization, error) {
	rest, ok := strings.CutPrefix(header, algorithm+" ")
	if !ok {
		return Authorization{}, fmt.Errorf("%w: not an %s header", ErrMalformedAuth, algorithm)
	}

	var out Authorization
	var seenCred, seenHeaders, seenSig bool
	for _, part := range strings.Split(rest, ",") {
		name, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			return Authorization{}, fmt.Errorf("%w: %q is not name=value", ErrMalformedAuth, part)
		}
		switch name {
		case "Credential":
			cred, err := parseCredential(value)
			if err != nil {
				return Authorization{}, err
			}
			out.Credential, seenCred = cred, true
		case "SignedHeaders":
			if value == "" {
				return Authorization{}, fmt.Errorf("%w: SignedHeaders is empty", ErrMalformedAuth)
			}
			out.SignedHeaders, seenHeaders = strings.Split(value, ";"), true
		case "Signature":
			out.Signature, seenSig = value, true
		default:
			return Authorization{}, fmt.Errorf("%w: unexpected field %q", ErrMalformedAuth, name)
		}
	}
	if !seenCred || !seenHeaders || !seenSig {
		return Authorization{}, fmt.Errorf("%w: Credential, SignedHeaders and Signature are all required",
			ErrMalformedAuth)
	}
	if len(out.Signature) != sha256.Size*2 {
		return Authorization{}, fmt.Errorf("%w: signature is %d characters, want %d",
			ErrMalformedAuth, len(out.Signature), sha256.Size*2)
	}
	return out, nil
}

func parseCredential(value string) (Credential, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 5 {
		return Credential{}, fmt.Errorf("%w: credential scope has %d parts, want 5",
			ErrMalformedAuth, len(parts))
	}
	cred := Credential{
		AccessKeyID: parts[0], Date: parts[1], Region: parts[2],
		Service: parts[3], Terminator: parts[4],
	}
	switch {
	case cred.AccessKeyID == "":
		return Credential{}, fmt.Errorf("%w: credential has no access key id", ErrMalformedAuth)
	case cred.Service != service:
		return Credential{}, fmt.Errorf("%w: credential names service %q, want %q",
			ErrMalformedAuth, cred.Service, service)
	case cred.Terminator != terminator:
		return Credential{}, fmt.Errorf("%w: credential terminator is %q, want %q",
			ErrMalformedAuth, cred.Terminator, terminator)
	}
	if _, err := time.Parse(dateFormat, cred.Date); err != nil {
		return Credential{}, fmt.Errorf("%w: credential date %q is not %s",
			ErrMalformedAuth, cred.Date, dateFormat)
	}
	return cred, nil
}

// CanonicalRequest builds the canonical request SigV4 signs.
//
// The S3 dialect differs from every other AWS service in one place: the path is
// used as sent, not URI-encoded a second time. Encoding it again would break
// every key containing a character that needs escaping.
func CanonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) string {
	return CanonicalRequestWithQuery(r, r.URL.Query(), signedHeaders, payloadHash)
}

// CanonicalRequestWithQuery is CanonicalRequest over a query the caller chooses.
//
// It exists for presigned URLs, whose signature covers every query parameter
// except the signature itself (ADR-019). Everything else about the canonical
// request is identical, which is the point: there is one implementation of the
// thing that must be exactly right, and presigning passes it a query with one
// parameter removed.
func CanonicalRequestWithQuery(
	r *http.Request, query url.Values, signedHeaders []string, payloadHash string,
) string {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(query))
	b.WriteByte('\n')
	b.WriteString(canonicalHeaders(r, signedHeaders))
	b.WriteByte('\n')
	b.WriteString(strings.Join(signedHeaders, ";"))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

// canonicalQuery renders the query string with parameters sorted by name, then
// by value, each side encoded with the AWS rules.
func canonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	var parts []string
	for _, name := range names {
		vs := append([]string(nil), values[name]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(name)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// canonicalHeaders renders the signed headers, lowercased and whitespace-folded.
func canonicalHeaders(r *http.Request, signedHeaders []string) string {
	var b strings.Builder
	for _, name := range signedHeaders {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(headerValue(r, name))
		b.WriteByte('\n')
	}
	return b.String()
}

// headerValue returns a header's canonical value.
//
// Host is read from r.Host rather than the header map: net/http moves it there
// and deletes the header, so looking it up would yield an empty string and every
// signature would fail.
func headerValue(r *http.Request, name string) string {
	var values []string
	switch name {
	case "host":
		values = []string{r.Host}
	case "content-length":
		if r.ContentLength >= 0 {
			values = []string{fmt.Sprintf("%d", r.ContentLength)}
		}
	default:
		values = r.Header.Values(http.CanonicalHeaderKey(name))
	}

	folded := make([]string, 0, len(values))
	for _, v := range values {
		folded = append(folded, foldWhitespace(v))
	}
	return strings.Join(folded, ",")
}

// foldWhitespace trims a header value and collapses runs of spaces, as SigV4
// requires for values that are not inside quotes.
func foldWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// StringToSign builds the string a signature covers.
func StringToSign(t time.Time, scope, canonicalRequest string) string {
	sum := sha256.Sum256([]byte(canonicalRequest))
	return strings.Join([]string{
		algorithm,
		t.UTC().Format(amzDateFormat),
		scope,
		hex.EncodeToString(sum[:]),
	}, "\n")
}

// SigningKey derives the key a signature is computed with.
func SigningKey(secret, date, region string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	return hmacSHA256(key, terminator)
}

// Sign computes the hex signature of a string to sign.
func Sign(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// uriEncode percent-encodes every byte outside the unreserved set, as SigV4
// requires. A space becomes %20, never '+'.
func uriEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9',
			ch == '-', ch == '.', ch == '_', ch == '~':
			b.WriteByte(ch)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[ch>>4])
			b.WriteByte(upperhex[ch&0x0f])
		}
	}
	return b.String()
}
