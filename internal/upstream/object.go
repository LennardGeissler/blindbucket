package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// metaPrefix is the header prefix S3 uses for user-defined object metadata.
const metaPrefix = "X-Amz-Meta-"

// PutObjectInput describes an upload.
//
// ContentLength must be known before the first byte is sent. For blindbucket
// that is never a problem: the format is deterministic in length, so the exact
// ciphertext size follows from the plaintext size.
type PutObjectInput struct {
	Bucket string
	Key    string
	Body   io.Reader
	// ContentLength is the exact number of bytes Body will produce.
	ContentLength int64

	ContentType        string
	CacheControl       string
	ContentDisposition string
	ContentEncoding    string
	ContentLanguage    string

	// Metadata holds user metadata without the x-amz-meta- prefix.
	Metadata map[string]string

	// IfMatch and IfNoneMatch make the write conditional on what the key holds:
	// the ETag it must still have, or "*" for nothing at all. They are a
	// client's own conditions (#168), and the provider evaluates them.
	IfMatch     string
	IfNoneMatch string
}

// PutObjectOutput reports what the provider recorded.
type PutObjectOutput struct {
	ETag      string
	VersionID string
}

// PutObject streams Body to the provider.
//
// The request is never retried. By the time it fails the client's stream has
// been consumed, so only the client can resend the data -- and it will, because
// S3 clients retry failed uploads themselves.
func (c *Client) PutObject(ctx context.Context, in PutObjectInput) (*PutObjectOutput, error) {
	if in.ContentLength < 0 {
		return nil, errors.New("upstream: PutObject needs a known content length")
	}

	req, err := c.newRequest(ctx, http.MethodPut, in.Bucket, in.Key)
	if err != nil {
		return nil, err
	}
	// http.NoBody rather than an empty reader: net/http treats a non-nil Body
	// with ContentLength 0 as "length unknown" and switches to chunked encoding,
	// which S3 answers with 411. An empty object is a legitimate thing to store.
	if in.ContentLength == 0 {
		req.Body = http.NoBody
	} else {
		if in.Body == nil {
			return nil, errors.New("upstream: PutObject has no body but a non-zero content length")
		}
		req.Body = io.NopCloser(in.Body)
	}
	req.ContentLength = in.ContentLength
	applyObjectHeaders(req.Header, in)
	setIfNotEmpty(req.Header, "If-Match", in.IfMatch)
	setIfNotEmpty(req.Header, "If-None-Match", in.IfNoneMatch)

	//nolint:bodyclose // closed by drainAndClose, which the linter cannot see through.
	resp, err := c.do(ctx, req, "PutObject", false)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	return &PutObjectOutput{
		ETag:      resp.Header.Get("ETag"),
		VersionID: resp.Header.Get("x-amz-version-id"),
	}, nil
}

func applyObjectHeaders(h http.Header, in PutObjectInput) {
	setIfNotEmpty(h, "Content-Type", in.ContentType)
	setIfNotEmpty(h, "Cache-Control", in.CacheControl)
	setIfNotEmpty(h, "Content-Disposition", in.ContentDisposition)
	setIfNotEmpty(h, "Content-Encoding", in.ContentEncoding)
	setIfNotEmpty(h, "Content-Language", in.ContentLanguage)
	for k, v := range in.Metadata {
		h.Set(metaPrefix+k, v)
	}
}

func setIfNotEmpty(h http.Header, key, value string) {
	if value != "" {
		h.Set(key, value)
	}
}

// GetObjectInput describes a download.
type GetObjectInput struct {
	Bucket string
	Key    string
	// Range is a raw HTTP Range header value such as "bytes=0-31", or empty for
	// the whole object.
	Range string
	// IfMatch, when set, makes the read conditional on the object's ETag.
	IfMatch string
}

// ObjectInfo is the metadata both GetObject and HeadObject return.
type ObjectInfo struct {
	// ContentLength is the size of the ciphertext, or of the requested range.
	ContentLength int64
	// TotalSize is the full ciphertext size of the object. For a ranged read it
	// comes from Content-Range; otherwise it equals ContentLength.
	TotalSize    int64
	ContentRange string
	ETag         string
	LastModified time.Time
	ContentType  string
	CacheControl string
	Metadata     map[string]string
	Header       http.Header
	StatusCode   int
}

// GetObjectOutput carries the object body alongside its metadata. The caller
// must close Body.
type GetObjectOutput struct {
	ObjectInfo
	Body io.ReadCloser
}

// GetObject fetches an object, or a byte range of one.
func (c *Client) GetObject(ctx context.Context, in GetObjectInput) (*GetObjectOutput, error) {
	req, err := c.newRequest(ctx, http.MethodGet, in.Bucket, in.Key)
	if err != nil {
		return nil, err
	}
	setIfNotEmpty(req.Header, "Range", in.Range)
	setIfNotEmpty(req.Header, "If-Match", in.IfMatch)

	//nolint:bodyclose // the body is the point: it is handed to the caller, who closes it.
	resp, err := c.do(ctx, req, "GetObject", true)
	if err != nil {
		return nil, err
	}
	return &GetObjectOutput{ObjectInfo: objectInfo(resp), Body: resp.Body}, nil
}

// HeadObject fetches an object's metadata.
func (c *Client) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	req, err := c.newRequest(ctx, http.MethodHead, bucket, key)
	if err != nil {
		return nil, err
	}
	//nolint:bodyclose // closed by drainAndClose, which the linter cannot see through.
	resp, err := c.do(ctx, req, "HeadObject", true)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	info := objectInfo(resp)
	return &info, nil
}

// DeleteObject removes an object. Deleting something that is not there is not
// an error, which matches S3's own behaviour.
func (c *Client) DeleteObject(ctx context.Context, bucket, key string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, bucket, key)
	if err != nil {
		return err
	}
	//nolint:bodyclose // closed by drainAndClose, which the linter cannot see through.
	resp, err := c.do(ctx, req, "DeleteObject", true)
	if err != nil {
		if NotFound(err) {
			return nil
		}
		return err
	}
	drainAndClose(resp.Body)
	return nil
}

// objectInfo extracts metadata from a response.
func objectInfo(resp *http.Response) ObjectInfo {
	info := ObjectInfo{
		ContentLength: resp.ContentLength,
		TotalSize:     resp.ContentLength,
		ContentRange:  resp.Header.Get("Content-Range"),
		ETag:          resp.Header.Get("ETag"),
		ContentType:   resp.Header.Get("Content-Type"),
		CacheControl:  resp.Header.Get("Cache-Control"),
		Metadata:      make(map[string]string),
		Header:        resp.Header,
		StatusCode:    resp.StatusCode,
	}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		info.LastModified = t
	}
	if total, ok := parseContentRangeTotal(info.ContentRange); ok {
		info.TotalSize = total
	}
	for name, values := range resp.Header {
		if len(values) > 0 && strings.HasPrefix(name, metaPrefix) {
			info.Metadata[strings.TrimPrefix(name, metaPrefix)] = values[0]
		}
	}
	return info
}

// parseContentRangeTotal extracts the total size from "bytes a-b/total".
//
// The value comes from the provider and is not authenticated. It is used to
// decide which chunk of a range is the segment's last one -- and a provider that
// lies about it causes the final-flag check to fail, because that chunk was
// sealed under a different nonce. The lie is detected, not trusted.
func parseContentRangeTotal(cr string) (int64, bool) {
	slash := strings.LastIndex(cr, "/")
	if slash < 0 {
		return 0, false
	}
	total, err := strconv.ParseInt(strings.TrimSpace(cr[slash+1:]), 10, 64)
	if err != nil || total < 0 {
		return 0, false
	}
	return total, true
}

// drainAndClose releases a response body so the connection can be reused.
// The drain is bounded: an upstream must not be able to hold a connection open
// by trickling bytes into a body nobody wants.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}
