package upstream

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// maxMultipartBody bounds the XML bodies of the multipart calls. A ListParts
// page of 1000 entries is well under a megabyte.
const maxMultipartBody = 8 << 20

// CreateMultipartUploadInput describes a new upload.
type CreateMultipartUploadInput struct {
	Bucket string
	Key    string

	ContentType        string
	CacheControl       string
	ContentDisposition string
	ContentEncoding    string
	ContentLanguage    string

	// Metadata holds user metadata without the x-amz-meta- prefix.
	Metadata map[string]string
}

type initiateResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// CreateMultipartUpload opens an upload and returns the provider's UploadId.
//
// The metadata is set here rather than at completion: S3 records the metadata of
// a multipart object from the create call, and there is no way to add it later.
func (c *Client) CreateMultipartUpload(ctx context.Context, in CreateMultipartUploadInput) (string, error) {
	u := c.objectURL(in.Bucket, in.Key)
	u.RawQuery = "uploads="

	req, err := c.newRequestURL(ctx, http.MethodPost, u)
	if err != nil {
		return "", err
	}
	req.ContentLength = 0
	req.Body = http.NoBody
	applyObjectHeaders(req.Header, PutObjectInput{
		ContentType:        in.ContentType,
		CacheControl:       in.CacheControl,
		ContentDisposition: in.ContentDisposition,
		ContentEncoding:    in.ContentEncoding,
		ContentLanguage:    in.ContentLanguage,
		Metadata:           in.Metadata,
	})

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "CreateMultipartUpload", false)
	if err != nil {
		return "", err
	}
	defer drainAndClose(resp.Body)

	var out initiateResult
	if err := decodeXML(resp.Body, &out, "create-multipart result"); err != nil {
		return "", err
	}
	if out.UploadID == "" {
		return "", errors.New("upstream: the provider returned no UploadId")
	}
	return out.UploadID, nil
}

// UploadPartInput describes one part upload.
type UploadPartInput struct {
	Bucket   string
	Key      string
	UploadID string
	// PartNumber is 1..10000.
	PartNumber int
	Body       io.Reader
	// ContentLength is the exact number of bytes Body will produce.
	ContentLength int64
}

// UploadPart streams one part to the provider and returns its ETag.
//
// Like PutObject it is never retried here: the body is the client's stream and
// cannot be replayed. A client that sees a failed part re-sends it, and because
// every part attempt is its own segment with a fresh salt, a retry is safe even
// when the failed attempt reached the provider (docs/FORMAT.md section 4.1).
func (c *Client) UploadPart(ctx context.Context, in UploadPartInput) (string, error) {
	if in.ContentLength < 0 {
		return "", errors.New("upstream: UploadPart needs a known content length")
	}
	if in.PartNumber < 1 || in.PartNumber > 10000 {
		return "", fmt.Errorf("upstream: part number %d outside 1..10000", in.PartNumber)
	}

	u := c.objectURL(in.Bucket, in.Key)
	u.RawQuery = url.Values{
		"partNumber": {strconv.Itoa(in.PartNumber)},
		"uploadId":   {in.UploadID},
	}.Encode()

	req, err := c.newRequestURL(ctx, http.MethodPut, u)
	if err != nil {
		return "", err
	}
	if in.Body == nil {
		return "", errors.New("upstream: UploadPart has no body")
	}
	req.Body = io.NopCloser(in.Body)
	req.ContentLength = in.ContentLength

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "UploadPart", false)
	if err != nil {
		return "", err
	}
	defer drainAndClose(resp.Body)

	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("upstream: the provider returned no ETag for the part")
	}
	return etag, nil
}

// CompletedPart names one part in a completion request.
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

type completeRequest struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

type completeResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// CompleteMultipartUploadInput describes a completion.
type CompleteMultipartUploadInput struct {
	Bucket   string
	Key      string
	UploadID string
	Parts    []CompletedPart
	// IfMatch makes the completion conditional on the current object's ETag.
	// Rotation uses it so that a client write landing mid-rotation wins instead
	// of being silently replaced; see ADR-009 and the I2
	// counterexample in spec/tla/README.md.
	IfMatch string
	// IfNoneMatch, set to "*", makes the completion fail if any object is at
	// the key. migrate-names uses it so that a client write that reaches the
	// encrypted key before the copy does is not replaced by the older object;
	// see ADR-022 and MCMigrateNoCreateGuard in spec/tla/README.md.
	IfNoneMatch string
}

// CompleteMultipartUploadOutput reports what the provider assembled.
type CompleteMultipartUploadOutput struct {
	ETag      string
	VersionID string
}

// CompleteMultipartUpload assembles the parts into an object.
//
// S3 answers this call with 200 OK and *then* streams the result, because
// assembly can take minutes; a failure therefore arrives as an Error document
// inside a 200 response. Treating the status alone as success would report a
// completed upload that never happened, so the body is parsed before anything is
// believed.
func (c *Client) CompleteMultipartUpload(
	ctx context.Context, in CompleteMultipartUploadInput,
) (*CompleteMultipartUploadOutput, error) {
	if len(in.Parts) == 0 {
		return nil, errors.New("upstream: CompleteMultipartUpload names no parts")
	}
	body, err := xml.Marshal(completeRequest{Parts: in.Parts})
	if err != nil {
		return nil, err
	}

	u := c.objectURL(in.Bucket, in.Key)
	u.RawQuery = url.Values{"uploadId": {in.UploadID}}.Encode()

	req, err := c.newRequestURL(ctx, http.MethodPost, u)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/xml")
	setIfNotEmpty(req.Header, "If-Match", in.IfMatch)
	setIfNotEmpty(req.Header, "If-None-Match", in.IfNoneMatch)

	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "CompleteMultipartUpload", false)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMultipartBody))
	if err != nil {
		return nil, fmt.Errorf("upstream: reading the completion result: %w", err)
	}
	if apiErr := errorInBody(resp, raw); apiErr != nil {
		return nil, apiErr
	}

	var out completeResult
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("upstream: the completion result is not valid XML: %w", err)
	}
	if out.ETag == "" {
		return nil, errors.New("upstream: the completion result carries no ETag")
	}
	return &CompleteMultipartUploadOutput{
		ETag:      out.ETag,
		VersionID: resp.Header.Get("x-amz-version-id"),
	}, nil
}

// AbortMultipartUpload discards an upload and the parts already stored for it.
//
// Aborting an upload that is already gone is not an error: the outcome the
// caller wanted is the outcome that holds.
func (c *Client) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	u := c.objectURL(bucket, key)
	u.RawQuery = url.Values{"uploadId": {uploadID}}.Encode()

	req, err := c.newRequestURL(ctx, http.MethodDelete, u)
	if err != nil {
		return err
	}
	//nolint:bodyclose // closed by drainAndClose below.
	resp, err := c.do(ctx, req, "AbortMultipartUpload", true)
	if err != nil {
		if NotFound(err) || NoSuchUpload(err) {
			return nil
		}
		return err
	}
	drainAndClose(resp.Body)
	return nil
}

// Part is one part as ListParts reports it.
type Part struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
	Size       int64  `xml:"Size"`
}

type listPartsResult struct {
	XMLName              xml.Name `xml:"ListPartsResult"`
	IsTruncated          bool     `xml:"IsTruncated"`
	NextPartNumberMarker string   `xml:"NextPartNumberMarker"`
	Parts                []Part   `xml:"Part"`
}

// ListParts returns every part stored for an upload, in ascending part order.
//
// It pages until the provider reports no more. An upload may hold up to 10000
// parts and a page carries 1000, so a large upload costs ten calls -- once, at
// completion.
func (c *Client) ListParts(ctx context.Context, bucket, key, uploadID string) ([]Part, error) {
	var all []Part
	marker := ""

	for {
		query := url.Values{"uploadId": {uploadID}, "max-parts": {"1000"}}
		if marker != "" {
			query.Set("part-number-marker", marker)
		}
		u := c.objectURL(bucket, key)
		u.RawQuery = query.Encode()

		req, err := c.newRequestURL(ctx, http.MethodGet, u)
		if err != nil {
			return nil, err
		}
		//nolint:bodyclose // closed by drainAndClose below.
		resp, err := c.do(ctx, req, "ListParts", true)
		if err != nil {
			return nil, err
		}

		var page listPartsResult
		err = decodeXML(resp.Body, &page, "ListParts result")
		drainAndClose(resp.Body)
		if err != nil {
			return nil, err
		}

		all = append(all, page.Parts...)
		if len(all) > 10000 {
			return nil, fmt.Errorf("upstream: the provider reported more than 10000 parts")
		}
		if !page.IsTruncated || page.NextPartNumberMarker == "" {
			return all, nil
		}
		marker = page.NextPartNumberMarker
	}
}

// MultipartUpload is one open upload as ListMultipartUploads reports it.
type MultipartUpload struct {
	Key      string `xml:"Key"`
	UploadID string `xml:"UploadId"`
}

type listUploadsResult struct {
	XMLName            xml.Name          `xml:"ListMultipartUploadsResult"`
	IsTruncated        bool              `xml:"IsTruncated"`
	NextKeyMarker      string            `xml:"NextKeyMarker"`
	NextUploadIDMarker string            `xml:"NextUploadIdMarker"`
	Uploads            []MultipartUpload `xml:"Upload"`
}

// ListMultipartUploads returns the uploads open under a prefix.
//
// This is step 2 of the gc order in ADR-010: an upload in flight
// may be about to publish a manifest that the listing already picked up, so gc
// skips such a key entirely. The step order is load-bearing and model-checked;
// see spec/tla/README.md.
func (c *Client) ListMultipartUploads(ctx context.Context, bucket, prefix string) ([]MultipartUpload, error) {
	var all []MultipartUpload
	keyMarker, idMarker := "", ""

	for {
		query := url.Values{"uploads": {""}, "max-uploads": {"1000"}}
		if prefix != "" {
			query.Set("prefix", prefix)
		}
		if keyMarker != "" {
			query.Set("key-marker", keyMarker)
		}
		if idMarker != "" {
			query.Set("upload-id-marker", idMarker)
		}
		u := c.bucketURL(bucket)
		u.RawQuery = query.Encode()

		req, err := c.newRequestURL(ctx, http.MethodGet, u)
		if err != nil {
			return nil, err
		}
		//nolint:bodyclose // closed by drainAndClose below.
		resp, err := c.do(ctx, req, "ListMultipartUploads", true)
		if err != nil {
			return nil, err
		}

		var page listUploadsResult
		err = decodeXML(resp.Body, &page, "ListMultipartUploads result")
		drainAndClose(resp.Body)
		if err != nil {
			return nil, err
		}

		all = append(all, page.Uploads...)
		if !page.IsTruncated || (page.NextKeyMarker == "" && page.NextUploadIDMarker == "") {
			return all, nil
		}
		// A provider that keeps reporting truncation without advancing its
		// markers would loop for ever; treat a stalled marker as the end.
		if page.NextKeyMarker == keyMarker && page.NextUploadIDMarker == idMarker {
			return all, nil
		}
		keyMarker, idMarker = page.NextKeyMarker, page.NextUploadIDMarker
	}
}

// newRequestURL builds an unsigned request against an already-built URL.
func (c *Client) newRequestURL(ctx context.Context, method string, u *url.URL) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// http.NewRequest re-parses the URL and loses RawPath; set the carefully
	// built one back, as the object and bucket calls do.
	req.URL = u
	req.Host = u.Host
	return req, nil
}

// decodeXML reads a bounded XML body into out.
func decodeXML(body io.Reader, out any, what string) error {
	raw, err := io.ReadAll(io.LimitReader(body, maxMultipartBody))
	if err != nil {
		return fmt.Errorf("upstream: reading the %s: %w", what, err)
	}
	if err := xml.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("upstream: the %s is not valid XML: %w", what, err)
	}
	return nil
}
