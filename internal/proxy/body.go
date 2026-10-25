package proxy

import (
	"io"
	"net/http"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// readVerifiedBody reads a small request body whole, through the same verifying
// reader an upload goes through: x-amz-content-sha256, Content-MD5, any
// x-amz-checksum-* and the chunk signatures of a signed aws-chunked body are
// all checked against the bytes before the handler sees them.
//
// Every body the gateway acts on has to come through here or through
// auth.NewBodyReader directly. A signature covers the hash the client
// announced, not the bytes, so a body read straight from r.Body is a body
// nobody checked: until 1.5.1, DeleteObjects, CompleteMultipartUpload and the
// bucket requests that carry a body were served with any body at all, as long
// as the headers were signed (GHSA-h6g6-fvvh-3r88).
//
// The limit is checked against the declared length first and against what
// arrives second. Reading only up to the limit would stop before the end of an
// oversized body, and the verification happens at the end.
func readVerifiedBody(r *http.Request, res *auth.Result, limit int64) ([]byte, *s3api.Error) {
	body, length, err := auth.NewBodyReader(r, res)
	if err != nil {
		return nil, translateBody(err)
	}
	if length > limit {
		return nil, s3api.ErrInvalidRequest.WithMessage(
			"the request body is %d bytes; this request takes at most %d", length, limit)
	}
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, translateBody(err)
	}
	if int64(len(raw)) > limit {
		return nil, s3api.ErrInvalidRequest.WithMessage(
			"the request body is over the %d bytes this request takes", limit)
	}
	return raw, nil
}
