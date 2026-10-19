package proxy

import (
	"net/http"
	"slices"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// CORS, for the browser-upload pattern (ADR-036). A browser sends a PUT to
// another origin only after an OPTIONS preflight, and reads a response from one
// only if it names that origin. Both come from the gateway's own configuration:
// the S3 bucket-CORS sub-resource would be stored by the provider and describe
// the provider's endpoint, which a browser never reaches.
//
// The answers name an origin on the list and nothing else -- never "*", never
// credentials. A presigned URL carries its own authority, and a browser's
// cookies mean nothing here.

// corsMethods are what a preflight may ask for: the reads, and the upload.
var corsMethods = []string{http.MethodGet, http.MethodHead, http.MethodPut}

// corsRequestHeaders are the request headers a cross-origin request may carry:
// the ones an upload may sign, and Range for a read. x-amz-checksum-* and
// x-amz-meta-* are matched by prefix.
var corsRequestHeaders = map[string]bool{
	"cache-control":                true,
	"content-disposition":          true,
	"content-encoding":             true,
	"content-language":             true,
	"content-md5":                  true,
	"content-type":                 true,
	"if-match":                     true,
	"if-none-match":                true,
	"range":                        true,
	"x-amz-sdk-checksum-algorithm": true,
}

// corsExposedHeaders are the response headers a page may read beyond the ones
// every browser exposes. The ETag is the one that matters: a multipart upload
// in the browser hands it back at completion, and it carries the part's salt
// (ADR-014).
const corsExposedHeaders = "ETag, x-amz-version-id, x-amz-request-id, " +
	"x-amz-checksum-crc32, x-amz-checksum-crc32c, x-amz-checksum-crc64nvme, " +
	"x-amz-checksum-sha1, x-amz-checksum-sha256, Content-Range, Content-Disposition, Content-Encoding"

// corsMaxAge is how long, in seconds, a browser may reuse a preflight.
const corsMaxAge = "3600"

// errCORS answers a preflight the configuration does not allow, in S3's words.
var errCORS = s3api.ErrAccessDenied.WithMessage(
	"CORSResponse: this CORS request is not allowed: the origin, the method or a " +
		"request header is not in server.cors")

// allowedOrigin returns the request's Origin if the configuration lists it.
func (p *Proxy) allowedOrigin(r *http.Request) (string, bool) {
	origin := r.Header.Get("Origin")
	if origin == "" || !slices.Contains(p.corsOrigins, origin) {
		return "", false
	}
	return origin, true
}

// allowCORS marks a response as readable by origin.
func allowCORS(h http.Header, origin string) {
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Expose-Headers", corsExposedHeaders)
	h.Add("Vary", "Origin")
}

// preflight answers an OPTIONS request with CORS on. It is unauthenticated, by
// the browser's design, and so says nothing about buckets or objects: only
// which methods and headers the listed origin may use.
func (p *Proxy) preflight(w http.ResponseWriter, r *http.Request, requestID string) {
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")

	origin, ok := p.allowedOrigin(r)
	method := r.Header.Get("Access-Control-Request-Method")
	headers, headersOK := corsHeadersAllowed(r.Header.Get("Access-Control-Request-Headers"))
	if !ok || !slices.Contains(corsMethods, method) || !headersOK {
		p.log.Info("refusing a CORS preflight", "request_id", requestID,
			"origin", r.Header.Get("Origin"), "method", method)
		s3api.WriteError(w, r, errCORS, requestID)
		return
	}

	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", strings.Join(corsMethods, ", "))
	if len(headers) > 0 {
		h.Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
	}
	h.Set("Access-Control-Max-Age", corsMaxAge)
	w.WriteHeader(http.StatusOK)
}

// corsHeadersAllowed parses Access-Control-Request-Headers and reports whether
// every header in it may be sent.
func corsHeadersAllowed(list string) ([]string, bool) {
	var out []string
	for _, name := range strings.Split(list, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if !corsRequestHeaders[name] && !strings.HasPrefix(name, "x-amz-checksum-") &&
			!strings.HasPrefix(name, "x-amz-meta-") {
			return nil, false
		}
		out = append(out, name)
	}
	return out, true
}
