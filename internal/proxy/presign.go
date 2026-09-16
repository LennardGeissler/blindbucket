package proxy

import (
	"net/url"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// stripPresign removes the parameters that carry a presigned URL's signature.
//
// Anything built from a client's query and sent onward has to go through this.
// The gateway authenticates its own upstream requests with a header signature of
// its own; a client's X-Amz-* parameters arriving alongside it would be a second,
// conflicting authentication on the same request. It also keeps them out of the
// resume state of a buffered listing, where they mean nothing.
//
// It returns the input unchanged when there is nothing to strip, which is every
// request that is not presigned.
func stripPresign(query url.Values) url.Values {
	has := false
	for name := range query {
		if s3api.PresignQueryParam(name) {
			has = true
			break
		}
	}
	if !has {
		return query
	}
	out := make(url.Values, len(query))
	for name, values := range query {
		if !s3api.PresignQueryParam(name) {
			out[name] = values
		}
	}
	return out
}

// presignGate refuses the operations a presigned URL may not reach.
//
// A presigned URL is a bearer credential inside a URL, and URLs are the least
// confidential thing in a system: they land in browser history, Referer headers,
// proxy and CDN logs, chat clients that fetch a preview, CI output. S3 accepts
// that across its whole API. This gateway serves two operations and refuses the
// rest, because the asymmetry is what matters -- a link preview that issues a GET
// is a GET, while a link preview that issues a DELETE is data loss with no
// attacker anywhere in the story (ADR-019).
//
// It is not a boundary against someone who holds the URL and means harm: for the
// one request it names, they have the signing credential's authority either way.
// It is a refusal to make the destructive operations reachable by accident.
func (p *Proxy) presignGate(presigned bool, op s3api.Operation) *s3api.Error {
	if !presigned {
		return nil
	}
	switch op {
	case s3api.OpGetObject, s3api.OpHeadObject:
		return nil
	}
	return s3api.ErrAccessDenied.WithMessage(
		"a presigned URL may only read an object: %s is not served this way. A URL "+
			"carries its signature where URLs get copied, so this gateway keeps the "+
			"operations that change or remove data off that path. See "+
			"docs/adr/ADR-019-presigned-urls.md", op)
}
