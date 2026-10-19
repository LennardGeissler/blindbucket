package proxy

import (
	"net/http"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// writeConditions reads the conditions a client put on a write: If-Match with
// the ETag the object must still have, and If-None-Match: * for "only if
// nothing is there". They go to the provider with the write, against the stored
// key, so they hold under name encryption too.
//
// The ETag a client compares is the provider's: PutObject, the completion and
// every read hand the provider's ETag back unchanged, so the client's value
// needs no translation.
//
// Until #168 the gateway read neither, and a client that asked for a
// conditional write got an unconditional one without being told. Refusing what
// cannot be honoured is the rule everywhere else (tags, server-side
// encryption); forwarding is better still, where the provider honours it.
func writeConditions(r *http.Request) (ifMatch, ifNoneMatch string, apiErr *s3api.Error) {
	ifMatch = r.Header.Get("If-Match")
	ifNoneMatch = r.Header.Get("If-None-Match")
	// S3 serves only the wildcard on a write. An ETag here would ask "unless
	// it is this version", which S3 answers 501, and so does this gateway
	// rather than forwarding something no provider is promised to read alike.
	if ifNoneMatch != "" && ifNoneMatch != "*" {
		return "", "", s3api.ErrNotImplemented.WithMessage(
			"If-None-Match on a write takes only *, as on S3")
	}
	return ifMatch, ifNoneMatch, nil
}
