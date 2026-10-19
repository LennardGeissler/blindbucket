package proxy

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/auth"
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

// presignGate refuses what a presigned URL may not do.
//
// A presigned URL is a bearer credential inside a URL, and URLs are the least
// confidential thing in a system: they land in browser history, Referer headers,
// proxy and CDN logs, chat clients that fetch a preview, CI output. S3 accepts
// that across its whole API. This gateway serves reads, and uploads only where
// the operator has set how much one may carry (ADR-019, ADR-036).
//
// It is not a boundary against someone who holds the URL and means harm: for the
// one request it names, they have the signing credential's authority either way.
// It keeps the operations that change or remove data off that path, and puts a
// bound on the two that write, because the holder of an upload URL is by design
// a browser nobody vouches for.
func (p *Proxy) presignGate(r *http.Request, res *auth.Result, op s3api.Operation) *s3api.Error {
	if !res.Presigned {
		return nil
	}
	switch op {
	case s3api.OpGetObject, s3api.OpHeadObject:
		return nil
	case s3api.OpPutObject, s3api.OpUploadPart:
		if p.uploadMax > 0 {
			return p.presignedUpload(r, res.Authorization.SignedHeaders)
		}
		return s3api.ErrAccessDenied.WithMessage(
			"presigned uploads are not served here: set server.presign.uploads.max_size " +
				"to serve them. See docs/adr/ADR-036-presigned-uploads.md")
	}
	return s3api.ErrAccessDenied.WithMessage(
		"a presigned URL may only read an object, or upload one where that is enabled: "+
			"%s is not served this way. A URL carries its signature where URLs get copied, "+
			"so this gateway keeps the operations that change or remove data off that path. "+
			"See docs/adr/ADR-019-presigned-urls.md", op)
}

// presignedUpload checks a presigned upload before a byte of its body is read,
// and turns the header values its query carries into the headers they stand for.
//
// The limit holds on Content-Length, which every browser sends for a file. A
// body without one could be any size, and an aws-chunked one has no signature
// for its chunks to chain to, so both are refused.
//
// Every x-amz-* header must be one the URL signed, as S3 requires. The holder of
// an upload URL is not the signer, and an unsigned x-amz-meta-* would let them
// store metadata the backend never agreed to. Values the URL carries in its
// query are signed as part of it.
func (p *Proxy) presignedUpload(r *http.Request, signed []string) *s3api.Error {
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") &&
			!slices.ContainsFunc(signed, func(s string) bool { return strings.EqualFold(s, lower) }) {
			return s3api.ErrAccessDenied.WithMessage(
				"%s is not among the headers this presigned URL signed; a presigned upload "+
					"may carry only the x-amz-* headers its signer chose", lower)
		}
	}
	if r.ContentLength < 0 {
		return s3api.ErrMissingContentLength.WithMessage(
			"a presigned upload must say its length in Content-Length")
	}
	if r.ContentLength > p.uploadMax {
		return s3api.ErrEntityTooLarge.WithMessage(
			"this presigned upload is %d bytes, and this gateway accepts at most %d by URL "+
				"(server.presign.uploads.max_size)", r.ContentLength, p.uploadMax)
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked") ||
		r.Header.Get("X-Amz-Decoded-Content-Length") != "" {
		return s3api.ErrInvalidRequest.WithMessage(
			"a presigned upload cannot be aws-chunked: there is no signature for its chunks")
	}
	return hoistUploadHeaders(r)
}

// hoistUploadHeaders copies the header values a presigned upload carries in its
// query into its headers, where the rest of the upload path reads them: the
// checksums the body is verified against (ADR-005), the user metadata, and
// x-amz-tagging, which is then refused as the header is.
//
// The signature has already covered them, as part of the query. A value given
// both ways is refused rather than merged: the two could disagree, and choosing
// one would be choosing what the signer meant.
func hoistUploadHeaders(r *http.Request) *s3api.Error {
	for name, values := range r.URL.Query() {
		if !s3api.HoistedUploadParam(name) {
			continue
		}
		if r.Header.Get(name) != "" {
			return s3api.ErrInvalidRequest.WithMessage(
				"%s is given both as a header and in the query", strings.ToLower(name))
		}
		if len(values) != 1 {
			return s3api.ErrInvalidRequest.WithMessage(
				"%s is given %d times in the query", strings.ToLower(name), len(values))
		}
		r.Header.Set(name, values[0])
	}
	return nil
}
