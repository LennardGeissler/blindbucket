package s3api

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

// Error is an S3-shaped error response.
//
// Clients act on the Code, not on the HTTP status: the AWS SDKs branch on
// NoSuchKey, retry on SlowDown, and surface AccessDenied to the user. Collapsing
// everything into a 500 would make the proxy look broken where the provider is
// merely saying "not found".
type Error struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (HTTP %d): %s", e.Code, e.HTTPStatus, e.Message)
}

// The errors this proxy raises itself. Provider errors are translated separately.
var (
	ErrNoSuchKey    = &Error{"NoSuchKey", "The specified key does not exist.", http.StatusNotFound}
	ErrNoSuchBucket = &Error{"NoSuchBucket", "The specified bucket does not exist.",
		http.StatusNotFound}
	ErrAccessDenied   = &Error{"AccessDenied", "Access Denied.", http.StatusForbidden}
	ErrInvalidRequest = &Error{"InvalidRequest", "The request is not valid.",
		http.StatusBadRequest}
	ErrInvalidArgument = &Error{"InvalidArgument", "An argument is not valid.",
		http.StatusBadRequest}
	ErrMissingContentLength = &Error{"MissingContentLength",
		"You must provide the Content-Length HTTP header.", http.StatusLengthRequired}
	ErrEntityTooLarge = &Error{"EntityTooLarge",
		"Your proposed upload exceeds the maximum allowed object size.",
		http.StatusBadRequest}
	// ErrPreconditionFailed answers a conditional request whose condition did
	// not hold. On a copy it is the x-amz-copy-source-if-* headers, and it is a
	// 412 rather than the 304 a GET would give: a write has no cached version
	// for the client to fall back on.
	ErrPreconditionFailed = &Error{"PreconditionFailed",
		"At least one of the preconditions you specified did not hold.",
		http.StatusPreconditionFailed}
	ErrInvalidRange = &Error{"InvalidRange",
		"The requested range is not satisfiable.", http.StatusRequestedRangeNotSatisfiable}
	ErrAuthHeaderMalformed = &Error{"AuthorizationHeaderMalformed",
		"The authorization header is malformed.", http.StatusBadRequest}
	ErrInvalidAccessKeyID = &Error{"InvalidAccessKeyId",
		"The access key id you provided does not exist in our records.", http.StatusForbidden}
	ErrSignatureDoesNotMatch = &Error{"SignatureDoesNotMatch",
		"The request signature we calculated does not match the signature you provided.",
		http.StatusForbidden}
	ErrRequestTimeTooSkewed = &Error{"RequestTimeTooSkewed",
		"The difference between the request time and the current time is too large.",
		http.StatusForbidden}
	ErrBadDigest = &Error{"BadDigest",
		"The checksum you specified did not match what we received.", http.StatusBadRequest}
	// ErrKeyTooLong answers a key that S3 would accept but whose encrypted form
	// would not be a legal key. Encryption grows a key by a factor set by its
	// number of segments, so where this starts is a property of the client's
	// naming convention: see ADR-015 and BenchmarkKeyExpansion.
	ErrKeyTooLong = &Error{"KeyTooLongError",
		"Your key is too long once encrypted.", http.StatusBadRequest}
	ErrContentSHA256Mismatch = &Error{"XAmzContentSHA256Mismatch",
		"The provided x-amz-content-sha256 header does not match what was computed.",
		http.StatusBadRequest}
	ErrIncompleteBody = &Error{"IncompleteBody",
		"The request body terminated unexpectedly or was not framed correctly.",
		http.StatusBadRequest}
	// The multipart errors. Clients branch on these: the AWS SDKs treat
	// NoSuchUpload as "this upload is gone, start again" rather than retrying.
	ErrNoSuchUpload = &Error{"NoSuchUpload",
		"The specified upload does not exist. It may have been completed, aborted, " +
			"or expired.", http.StatusNotFound}
	ErrInvalidPart = &Error{"InvalidPart",
		"One or more of the specified parts could not be found. The part may not have been " +
			"uploaded, or the entity tag may not match.", http.StatusBadRequest}
	ErrInvalidPartOrder = &Error{"InvalidPartOrder",
		"The list of parts was not in ascending order. Parts must be ordered by part number.",
		http.StatusBadRequest}
	ErrNotImplemented = &Error{"NotImplemented",
		"A header or operation you provided implies functionality that is not implemented.",
		http.StatusNotImplemented}
	ErrInternal = &Error{"InternalError",
		"We encountered an internal error. Please try again.", http.StatusInternalServerError}
	// ErrIntegrity has no counterpart in S3. It reports that stored data failed
	// authentication, which for blindbucket is a first-class outcome rather than
	// a generic server fault -- it means either a bug or a provider tampering
	// with objects, and the two must not be confused with an ordinary 500.
	ErrIntegrity = &Error{"IntegrityCheckFailed",
		"The stored object failed authentication and was not returned.",
		http.StatusBadGateway}
)

// WithMessage returns a copy of e carrying a more specific message. The code and
// status stay put, because those are what clients branch on.
func (e *Error) WithMessage(format string, args ...any) *Error {
	return &Error{Code: e.Code, Message: fmt.Sprintf(format, args...), HTTPStatus: e.HTTPStatus}
}

// errorResponse is the XML body S3 returns for errors.
type errorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId,omitempty"`
}

// WriteError sends an S3-conformant error response.
//
// It does nothing if the response has already started: once a status line and
// Content-Length are on the wire, an error body would be appended to a partial
// object and read as data. That case is handled by aborting the connection
// instead; see docs/adr/ADR-004-fail-closed.md.
func WriteError(w http.ResponseWriter, r *http.Request, apiErr *Error, requestID string) {
	body, err := xml.MarshalIndent(errorResponse{
		Code:      apiErr.Code,
		Message:   apiErr.Message,
		Resource:  r.URL.Path,
		RequestID: requestID,
	}, "", "  ")
	if err != nil {
		// Marshalling a struct of strings cannot realistically fail, but a
		// silent empty body would be worse than a plain status.
		w.WriteHeader(apiErr.HTTPStatus)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Del("ETag")
	w.Header().Del("Content-Length")
	w.WriteHeader(apiErr.HTTPStatus)

	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(xml.Header))
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	}
}
