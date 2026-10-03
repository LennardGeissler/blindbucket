package upstream

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxErrorBody bounds how much of an error response is read. The upstream is
// untrusted, and an error path must not become a way to make the proxy allocate.
const maxErrorBody = 64 << 10

// APIError is an error response from the storage provider.
//
// The S3 error code is preserved verbatim so the proxy can pass through the
// distinctions clients act on -- NoSuchKey, NoSuchBucket, PreconditionFailed --
// rather than collapsing everything into a 500.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Resource   string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("upstream: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("upstream: %s (HTTP %d): %s", e.Code, e.StatusCode, e.Message)
}

// AsAPIError reports whether err is or wraps an *APIError.
func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	ok := errors.As(err, &ae)
	return ae, ok
}

// NotFound reports whether err is an upstream 404.
func NotFound(err error) bool {
	ae, ok := AsAPIError(err)
	return ok && ae.StatusCode == http.StatusNotFound
}

// NoSuchUpload reports whether err says the multipart upload is gone.
//
// It is distinct from a 404 on the object: an upload aborted by the bucket's
// lifecycle rule, or already completed, answers NoSuchUpload while the object
// itself may well exist. The proxy needs the distinction to tell a client "your
// upload expired" rather than "no such object".
func NoSuchUpload(err error) bool {
	ae, ok := AsAPIError(err)
	return ok && ae.Code == "NoSuchUpload"
}

// PreconditionFailed reports whether err is an upstream 412.
//
// A conditional CompleteMultipartUpload answers with this when the object
// changed under a rotation, which is the mechanism that keeps I2
// (docs/adr/ADR-009-rotation-by-copy.md).
func PreconditionFailed(err error) bool {
	ae, ok := AsAPIError(err)
	return ok && ae.StatusCode == http.StatusPreconditionFailed
}

// errorInBody reports an S3 error delivered inside a 2xx response.
//
// CompleteMultipartUpload is the call that does this: assembly can take minutes,
// so S3 sends 200 OK with the headers, keeps the connection alive with
// whitespace, and only then writes either the result or an Error document. A
// caller that trusts the status alone reports a completed upload that failed.
func errorInBody(resp *http.Response, body []byte) *APIError {
	parsed, isError := parseErrorXML(body)
	if !isError {
		return nil
	}
	requestID := parsed.RequestID
	if requestID == "" {
		requestID = resp.Header.Get("x-amz-request-id")
	}
	// The status was 2xx, so it says nothing about the failure. A failed
	// condition gets back the status it has when S3 answers it up front --
	// PreconditionFailed is recognised by its 412, and AWS delivers it inside a
	// 200 when the completion has already started streaming (measured on
	// 2026-10-03; until then a guard that held read as a provider failure).
	// Anything else maps onto 500, the status of an error with none of its own.
	status, ok := inBodyStatus[parsed.Code]
	if !ok {
		status = http.StatusInternalServerError
	}
	return &APIError{
		StatusCode: status,
		Code:       parsed.Code,
		Message:    parsed.Message,
		RequestID:  requestID,
		Resource:   parsed.Resource,
	}
}

// inBodyStatus is the status of each error code a conditional write can fail
// with, for when the code arrives inside a 2xx response.
var inBodyStatus = map[string]int{
	"PreconditionFailed":         http.StatusPreconditionFailed,
	"ConditionalRequestConflict": http.StatusConflict,
}

// parseErrorXML reports whether body is an S3 Error document, and decodes it.
//
// A body that does not parse, or parses without a Code, is not an error: on the
// success path of CompleteMultipartUpload it is the ordinary result document.
func parseErrorXML(body []byte) (errorXML, bool) {
	var parsed errorXML
	if err := xml.Unmarshal(body, &parsed); err != nil || parsed.Code == "" {
		return errorXML{}, false
	}
	return parsed, true
}

// errorXML is the shape S3 uses for error responses.
type errorXML struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
	Resource  string   `xml:"Resource"`
}

// newAPIError builds an APIError from a response, consuming its body.
//
// A provider that returns a body which is not the documented XML -- an HTML
// error page from a proxy in front of it, say -- still produces a usable error
// rather than a parse failure that hides the status code.
func newAPIError(resp *http.Response, op string) *APIError {
	out := &APIError{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("x-amz-request-id"),
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if err == nil && len(body) > 0 {
		var parsed errorXML
		if xml.Unmarshal(body, &parsed) == nil && parsed.Code != "" {
			out.Code = parsed.Code
			out.Message = parsed.Message
			out.Resource = parsed.Resource
			if parsed.RequestID != "" {
				out.RequestID = parsed.RequestID
			}
			return out
		}
	}

	out.Code = statusCode(resp.StatusCode, op)
	out.Message = http.StatusText(resp.StatusCode)
	return out
}

// bucketLevelOps address a bucket rather than an object, so a 404 from them
// means the bucket is missing and not the key.
var bucketLevelOps = map[string]bool{
	"Passthrough":          true,
	"ListObjects":          true,
	"DeleteObjects":        true,
	"ListMultipartUploads": true,
}

// statusCode maps a bare HTTP status to the S3 error code a client expects,
// for providers that answer without a body.
//
// A HEAD never carries one, so this path is the only source of a code for
// HeadObject and HeadBucket -- which is why the operation matters: answering
// NoSuchKey for a missing *bucket* sends a client looking for the wrong thing.
func statusCode(status int, op string) string {
	switch status {
	case http.StatusNotFound:
		if bucketLevelOps[op] {
			return "NoSuchBucket"
		}
		return "NoSuchKey"
	case http.StatusForbidden:
		return "AccessDenied"
	case http.StatusPreconditionFailed:
		return "PreconditionFailed"
	case http.StatusRequestedRangeNotSatisfiable:
		return "InvalidRange"
	case http.StatusNotModified:
		return "NotModified"
	default:
		return "InternalError"
	}
}
