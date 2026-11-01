package upstream

import (
	"context"
	//nolint:gosec // S3 defines Content-MD5 to be MD5; this is compatibility.
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxListBody bounds a listing response. S3 caps a page at 1000 keys of at most
// 1024 bytes each, so a few megabytes is generous; the bound exists because the
// provider is untrusted and a response must not be able to exhaust memory.
const maxListBody = 16 << 20

// ListBucketResult is the body of ListObjects and ListObjectsV2.
//
// Both versions share a root element and differ only in their pagination
// fields, so one type covers both. The version-specific fields are omitted when
// empty, which is how they arrive from a provider answering the other version.
type ListBucketResult struct {
	XMLName xml.Name `xml:"ListBucketResult"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`

	Name        string `xml:"Name"`
	Prefix      string `xml:"Prefix"`
	MaxKeys     int    `xml:"MaxKeys"`
	Delimiter   string `xml:"Delimiter,omitempty"`
	IsTruncated bool   `xml:"IsTruncated"`

	// v1 pagination.
	Marker     string `xml:"Marker,omitempty"`
	NextMarker string `xml:"NextMarker,omitempty"`

	// v2 pagination.
	KeyCount              int    `xml:"KeyCount,omitempty"`
	ContinuationToken     string `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string `xml:"NextContinuationToken,omitempty"`
	StartAfter            string `xml:"StartAfter,omitempty"`

	EncodingType string `xml:"EncodingType,omitempty"`

	Contents       []ObjectEntry  `xml:"Contents"`
	CommonPrefixes []CommonPrefix `xml:"CommonPrefixes"`
}

// ObjectEntry is one object in a listing.
type ObjectEntry struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass,omitempty"`
	Owner        *Owner `xml:"Owner,omitempty"`
}

// Owner identifies an object's owner, when the provider reports one.
type Owner struct {
	ID          string `xml:"ID,omitempty"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

// CommonPrefix is a directory-like grouping produced by a delimiter.
type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// ListObjects performs a listing, passing the client's own query parameters
// through so pagination, prefixes and delimiters behave exactly as the client
// expects.
func (c *Client) ListObjects(ctx context.Context, bucket string, query url.Values) (*ListBucketResult, error) {
	u := c.bucketURL(bucket)
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "ListObjects", true)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the listing: %w", err)
	}

	var out ListBucketResult
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("upstream: the listing is not valid XML: %w", err)
	}
	return &out, nil
}

// ListVersionsResult is the body of ListObjectVersions: every version of every
// object, current and noncurrent, and the delete markers, in key order and,
// within a key, newest first.
type ListVersionsResult struct {
	XMLName xml.Name `xml:"ListVersionsResult"`

	Name                string `xml:"Name"`
	Prefix              string `xml:"Prefix"`
	KeyMarker           string `xml:"KeyMarker"`
	VersionIDMarker     string `xml:"VersionIdMarker"`
	NextKeyMarker       string `xml:"NextKeyMarker"`
	NextVersionIDMarker string `xml:"NextVersionIdMarker"`
	MaxKeys             int    `xml:"MaxKeys"`
	IsTruncated         bool   `xml:"IsTruncated"`

	Versions      []ObjectVersion `xml:"Version"`
	DeleteMarkers []DeleteMarker  `xml:"DeleteMarker"`
}

// ObjectVersion is one version of an object. A bucket that was never versioned
// lists each object once, with the version id "null" and IsLatest true.
type ObjectVersion struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// DeleteMarker is a version that records a deletion. It has no content.
type DeleteMarker struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
	IsLatest  bool   `xml:"IsLatest"`
}

// ListObjectVersions lists a bucket's object versions (GET /?versions). query
// carries prefix, max-keys and the key-marker and version-id-marker of the
// page before; versions is added here.
func (c *Client) ListObjectVersions(ctx context.Context, bucket string, query url.Values) (*ListVersionsResult, error) {
	u := c.bucketURL(bucket)
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("versions", "")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "ListObjectVersions", true)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the version listing: %w", err)
	}
	var out ListVersionsResult
	if err := xml.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("upstream: the version listing is not valid XML: %w", err)
	}
	return &out, nil
}

// DeleteRequest is the body of a DeleteObjects call.
type DeleteRequest struct {
	XMLName xml.Name           `xml:"Delete"`
	Quiet   bool               `xml:"Quiet,omitempty"`
	Objects []DeleteObjectSpec `xml:"Object"`
}

// DeleteObjectSpec names one object to delete.
type DeleteObjectSpec struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
}

// DeleteResult is the body of a DeleteObjects response.
type DeleteResult struct {
	XMLName xml.Name       `xml:"DeleteResult"`
	Xmlns   string         `xml:"xmlns,attr,omitempty"`
	Deleted []DeletedEntry `xml:"Deleted"`
	Errors  []DeleteError  `xml:"Error"`
}

// DeletedEntry reports one successful deletion.
type DeletedEntry struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
}

// DeleteError reports one deletion that failed.
type DeleteError struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// DeleteObjects removes several objects in one request.
func (c *Client) DeleteObjects(ctx context.Context, bucket string, in DeleteRequest) (*DeleteResult, error) {
	body, err := xml.Marshal(in)
	if err != nil {
		return nil, err
	}

	u := c.bucketURL(bucket)
	u.RawQuery = "delete="

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/xml")
	// S3 requires a Content-MD5 on DeleteObjects and rejects the request
	// without one. It is a protocol requirement, not a security choice, and the
	// body is ours and small, so hashing it costs nothing.
	//nolint:gosec // the algorithm is named by the header; see the comment above.
	sum := md5.Sum(body)
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "DeleteObjects", false)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the delete result: %w", err)
	}

	var out DeleteResult
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("upstream: the delete result is not valid XML: %w", err)
	}
	return &out, nil
}

// RawResponse is an upstream response forwarded without interpretation.
type RawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Passthrough forwards a request whose body and response blindbucket does not
// transform: bucket existence, location, creation, deletion, listing buckets.
//
// These carry no object content, so there is nothing to encrypt or decrypt, and
// reproducing the provider's answer verbatim is both simpler and more accurate
// than paraphrasing it.
func (c *Client) Passthrough(ctx context.Context, method, bucket string, query url.Values, body []byte) (*RawResponse, error) {
	var u *url.URL
	if bucket == "" {
		root := *c.endpoint
		root.Path = "/"
		root.RawPath = "/"
		u = &root
	} else {
		u = c.bucketURL(bucket)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host
	if len(body) > 0 {
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.ContentLength = int64(len(body))
	}

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "Passthrough", method == http.MethodGet || method == http.MethodHead)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the response: %w", err)
	}
	return &RawResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

// ObjectPassthrough forwards a sub-resource request against an object whose
// body blindbucket does not transform -- the tagging sub-resource, which carries
// no object content.
func (c *Client) ObjectPassthrough(
	ctx context.Context, method, bucket, key string, query url.Values,
) (*RawResponse, error) {
	u := c.objectURL(bucket, key)
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "ObjectPassthrough", method == http.MethodGet || method == http.MethodHead)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the response: %w", err)
	}
	return &RawResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

// bucketURL builds the URL addressing a bucket itself.
func (c *Client) bucketURL(bucket string) *url.URL {
	u := *c.endpoint
	if c.pathStyle {
		u.Path = "/" + bucket
		u.RawPath = "/" + uriEncodePath(bucket)
	} else {
		u.Host = bucket + "." + u.Host
		u.Path = "/"
		u.RawPath = "/"
	}
	return &u
}
