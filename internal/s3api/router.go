// Package s3api routes HTTP requests according to S3 semantics and renders
// S3-conformant XML errors.
//
// Routing cannot be expressed as ordinary path matching. S3 distinguishes
// operations by method, by query parameters (?uploads, ?partNumber=,
// ?list-type=2) and by headers (x-amz-copy-source) at least as much as by path,
// which is why this is a hand-written router rather than a mux.
package s3api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Operation names an S3 operation.
type Operation string

// The operations this build recognises. Anything else is reported as
// unsupported rather than guessed at.
const (
	OpPutObject Operation = "PutObject"
	// OpCopyObject is a PUT carrying x-amz-copy-source: the body is empty and
	// the bytes come from another object rather than from the request.
	OpCopyObject   Operation = "CopyObject"
	OpGetObject    Operation = "GetObject"
	OpHeadObject   Operation = "HeadObject"
	OpDeleteObject Operation = "DeleteObject"
	// OpGetObjectTagging reads an object's tags. The gateway writes none, so
	// for anything it stored the answer is an empty set.
	OpGetObjectTagging Operation = "GetObjectTagging"

	OpListObjectsV2 Operation = "ListObjectsV2"
	OpListObjects   Operation = "ListObjects"
	OpDeleteObjects Operation = "DeleteObjects"

	OpCreateMultipartUpload   Operation = "CreateMultipartUpload"
	OpUploadPart              Operation = "UploadPart"
	OpUploadPartCopy          Operation = "UploadPartCopy"
	OpCompleteMultipartUpload Operation = "CompleteMultipartUpload"
	OpAbortMultipartUpload    Operation = "AbortMultipartUpload"
	OpListParts               Operation = "ListParts"
	OpListMultipartUploads    Operation = "ListMultipartUploads"

	OpListBuckets       Operation = "ListBuckets"
	OpHeadBucket        Operation = "HeadBucket"
	OpCreateBucket      Operation = "CreateBucket"
	OpDeleteBucket      Operation = "DeleteBucket"
	OpGetBucketLocation Operation = "GetBucketLocation"

	OpUnsupported Operation = "Unsupported"
)

// IsObject reports whether the operation addresses a single object.
func (o Operation) IsObject() bool {
	switch o {
	case OpPutObject, OpCopyObject, OpGetObject, OpHeadObject, OpDeleteObject,
		OpGetObjectTagging, OpCreateMultipartUpload, OpUploadPart, OpUploadPartCopy,
		OpCompleteMultipartUpload, OpAbortMultipartUpload, OpListParts:
		return true
	default:
		return false
	}
}

// IsMultipart reports whether the operation is part of a multipart upload.
func (o Operation) IsMultipart() bool {
	switch o {
	case OpCreateMultipartUpload, OpUploadPart, OpUploadPartCopy,
		OpCompleteMultipartUpload, OpAbortMultipartUpload, OpListParts,
		OpListMultipartUploads:
		return true
	default:
		return false
	}
}

// MaxKeyLength is S3's limit on object key length, in bytes.
const MaxKeyLength = 1024

// ReservedPrefix is where blindbucket keeps its own objects inside a user
// bucket. Client access to it is refused: it holds the multipart manifests, and
// a client that could delete one would make its own object unreadable.
const ReservedPrefix = ".blindbucket/"

// MaxPartNumber is S3's largest part number.
const MaxPartNumber = 10000

// Request is a classified S3 request.
type Request struct {
	Op     Operation
	Bucket string
	Key    string

	// UploadID is the opaque upload token a client presents on the multipart
	// operations. It is not the provider's own UploadId; see
	// docs/adr/ADR-006-upload-token.md.
	UploadID string
	// PartNumber is set for UploadPart, 1..MaxPartNumber.
	PartNumber int
}

// bucketQueryOps maps a bucket-level sub-resource to its operation. Only these
// are served; every other sub-resource is refused.
var bucketQueryOps = map[string]Operation{
	"location": OpGetBucketLocation,
	"delete":   OpDeleteObjects,
	"uploads":  OpListMultipartUploads,
}

// ignorableParams are query parameters that carry no meaning for the service.
//
// "x-id" is telemetry the AWS SDKs attach -- ?x-id=PutObject and friends --
// naming the operation the SDK believes it is performing. Real S3 ignores it,
// and rclone, which uses that SDK, sends it on every object request. Refusing it
// as an unknown sub-resource made every rclone upload fail with a 501, which is
// how this was found. It is still covered by the signature, because the
// canonical query string is built from the request as it arrived.
var ignorableParams = map[string]bool{
	"x-id": true,
}

// presignParams are the six query parameters that carry a SigV4 signature in a
// URL rather than selecting a sub-resource (ADR-019).
//
// The router runs before authentication, so it has to know them: without this
// every presigned URL would be refused as an unimplemented sub-resource before
// the verifier ever saw it. Naming them weakens nothing -- five of the six stay
// covered by the signature, because the canonical query string is built from the
// request as it arrived, which is the same reasoning ?x-id above already records.
//
// Repeated here rather than imported from internal/auth, so that routing does not
// depend on authentication. TestPresignParamsMatchTheVerifier is what keeps the
// two from drifting.
var presignParams = map[string]bool{
	"X-Amz-Algorithm":     true,
	"X-Amz-Credential":    true,
	"X-Amz-Date":          true,
	"X-Amz-Expires":       true,
	"X-Amz-SignedHeaders": true,
	"X-Amz-Signature":     true,
}

// PresignQueryParam reports whether a query parameter is part of a presigned
// URL's signature. Exported for the proxy, which must strip them from anything
// it forwards to the provider.
func PresignQueryParam(name string) bool { return presignParams[name] }

// sigV2Presigned recognises the older signature format a presigned URL can carry.
//
// SigV2 is not served: it is deprecated, weaker, and AWS removed it from regions
// launched after 2014. What this exists for is the error message. botocore still
// produces a SigV2 presigned URL by default against a custom endpoint -- found by
// pointing boto3 at this gateway with no signature_version set -- and without this
// the answer is `the sub-resource "AWSAccessKeyId" is not implemented`, which
// names a symptom nobody can act on.
func sigV2Presigned(query url.Values) bool {
	return query.Get("AWSAccessKeyId") != "" && query.Get("Signature") != ""
}

// errSigV2 says what happened and how to fix it in the two clients that hit it.
func errSigV2() *Error {
	return ErrInvalidRequest.WithMessage(
		"this is a SigV2 presigned URL; this gateway verifies AWS4-HMAC-SHA256 only. " +
			"With boto3, pass Config(signature_version=\"s3v4\") when building the " +
			"client -- botocore still defaults to SigV2 for presigned URLs against a " +
			"custom endpoint. The AWS CLI produces SigV4 already")
}

// listingParams are the query parameters that shape a listing rather than
// selecting a different operation. They are forwarded to the provider
// unchanged, so pagination, prefixes and delimiters behave exactly as a client
// expects.
var listingParams = map[string]bool{
	"list-type":             true,
	"prefix":                true,
	"delimiter":             true,
	"max-keys":              true,
	"marker":                true,
	"continuation-token":    true,
	"start-after":           true,
	"encoding-type":         true,
	"fetch-owner":           true,
	"expected-bucket-owner": true,
}

// Route classifies an inbound request.
//
// baseDomain enables virtual-hosted-style addressing: with "s3.internal.example"
// configured, a request to bucket.s3.internal.example addresses that bucket.
// Leave it empty to accept path-style only.
func Route(r *http.Request, baseDomain string) (Request, *Error) {
	bucket, key := splitTarget(r, baseDomain)

	switch {
	case bucket == "":
		return routeService(r)
	case key == "":
		return routeBucket(r, bucket)
	default:
		return routeObject(r, bucket, key)
	}
}

// routeService handles requests against the endpoint root.
func routeService(r *http.Request) (Request, *Error) {
	if r.Method == http.MethodGet && len(r.URL.Query()) == 0 {
		return Request{Op: OpListBuckets}, nil
	}
	return Request{Op: OpUnsupported}, ErrNotImplemented.WithMessage(
		"service-level operation %s is not implemented in this build", r.Method)
}

// routeBucket handles requests against a bucket rather than an object.
func routeBucket(r *http.Request, bucket string) (Request, *Error) {
	query := r.URL.Query()
	req := Request{Bucket: bucket}

	// A query parameter is either a sub-resource selecting a different
	// operation, or one of the parameters that shape a listing. Anything else
	// names something this build does not implement, and answering it as a
	// listing would silently ignore what the client asked for.
	for name := range query {
		if op, known := bucketQueryOps[name]; known {
			switch {
			case op == OpGetBucketLocation && r.Method == http.MethodGet:
				req.Op = OpGetBucketLocation
				return req, nil
			case op == OpDeleteObjects && r.Method == http.MethodPost:
				req.Op = OpDeleteObjects
				return req, nil
			case op == OpListMultipartUploads && r.Method == http.MethodGet:
				req.Op = OpListMultipartUploads
				return req, nil
			}
			continue
		}
		if ignorableParams[strings.ToLower(name)] || presignParams[name] {
			continue
		}
		if !listingParams[name] {
			return Request{Bucket: bucket, Op: OpUnsupported}, ErrNotImplemented.WithMessage(
				"the bucket sub-resource %q is not implemented in this build", name)
		}
	}

	switch r.Method {
	case http.MethodGet:
		// list-type=2 selects ListObjectsV2; its absence means the older call,
		// which rclone and some backup tools still use.
		if query.Get("list-type") == "2" {
			req.Op = OpListObjectsV2
		} else {
			req.Op = OpListObjects
		}
		return req, nil
	case http.MethodHead:
		req.Op = OpHeadBucket
		return req, nil
	case http.MethodPut:
		req.Op = OpCreateBucket
		return req, nil
	case http.MethodDelete:
		req.Op = OpDeleteBucket
		return req, nil
	}
	return Request{Bucket: bucket, Op: OpUnsupported}, ErrNotImplemented.WithMessage(
		"method %s is not implemented for buckets", r.Method)
}

// objectQueryParams are the query parameters an object request may carry. A
// parameter outside this set names a sub-resource this build does not implement,
// and guessing at it would be worse than refusing: ?acl answered as a PUT would
// send plaintext to the provider.
var objectQueryParams = map[string]bool{
	"uploads":            true,
	"uploadId":           true,
	"partNumber":         true,
	"max-parts":          true,
	"part-number-marker": true,
	"tagging":            true,
}

// routeObject handles requests against a single object.
func routeObject(r *http.Request, bucket, key string) (Request, *Error) {
	if len(key) > MaxKeyLength {
		return Request{}, ErrInvalidArgument.WithMessage(
			"object key is %d bytes, the maximum is %d", len(key), MaxKeyLength)
	}
	if strings.HasPrefix(key, ReservedPrefix) {
		return Request{}, ErrAccessDenied.WithMessage(
			"the %s prefix is reserved by the gateway", ReservedPrefix)
	}

	query := r.URL.Query()
	if sigV2Presigned(query) {
		return Request{Bucket: bucket, Key: key, Op: OpUnsupported}, errSigV2()
	}
	for name := range query {
		if ignorableParams[strings.ToLower(name)] || objectQueryParams[name] ||
			presignParams[name] {
			continue
		}
		return Request{Bucket: bucket, Key: key, Op: OpUnsupported},
			ErrNotImplemented.WithMessage("the sub-resource %q is not implemented in this build", name)
	}

	// Presence of the parameter decides, not its value. An empty ?uploadId= must
	// not fall through to the plain-object path: a PUT carrying ?partNumber=1 and
	// an empty upload id would then be served as PutObject, storing one part's
	// bytes as the whole object.
	if _, tagging := query["tagging"]; tagging {
		return routeTagging(r, bucket, key)
	}

	_, initiating := query["uploads"]
	_, hasUploadID := query["uploadId"]
	_, hasPartNumber := query["partNumber"]
	if initiating || hasUploadID || hasPartNumber {
		return routeMultipart(r, bucket, key, initiating, query.Get("uploadId"))
	}

	op := objectOperation(r.Method)
	if op == OpUnsupported {
		return Request{Bucket: bucket, Key: key, Op: op},
			ErrNotImplemented.WithMessage("method %s is not implemented for objects", r.Method)
	}
	// A PUT with a copy source is a different operation with the same method
	// and path: no body arrives, and the handler reads from another object
	// instead. Telling them apart here keeps the body-reading path free of a
	// case where there is no body.
	if op == OpPutObject && r.Header.Get("X-Amz-Copy-Source") != "" {
		op = OpCopyObject
	}
	return Request{Op: op, Bucket: bucket, Key: key}, nil
}

// routeTagging classifies the object tagging sub-resource.
//
// Reading is forwarded to the provider, because that is where tags live and
// this gateway never writes any. Writing is refused rather than quietly
// accepted: a tag is a key and a value the provider stores in the clear, and a
// gateway whose whole claim is that the provider sees only ciphertext must not
// take plaintext in through a side door. The AWS CLI asks for an object's tags
// before a server-side copy, which is why reading it has to work at all.
func routeTagging(r *http.Request, bucket, key string) (Request, *Error) {
	req := Request{Bucket: bucket, Key: key}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		req.Op = OpGetObjectTagging
		return req, nil
	case http.MethodPut, http.MethodDelete:
		return unsupported(req), ErrNotImplemented.WithMessage(
			"object tags are not accepted: the provider would store them in plaintext")
	}
	return unsupported(req), ErrNotImplemented.WithMessage(
		"method %s is not implemented for the tagging sub-resource", r.Method)
}

// routeMultipart classifies the five object-level multipart operations.
//
// They are told apart by method and by which of ?uploads and ?uploadId is
// present, which is the only thing that distinguishes, for instance, a
// CompleteMultipartUpload from a DeleteObjects -- both are POSTs.
func routeMultipart(r *http.Request, bucket, key string, initiating bool, uploadID string) (Request, *Error) {
	req := Request{Bucket: bucket, Key: key, UploadID: uploadID}

	if initiating {
		if uploadID != "" {
			return unsupported(req), ErrInvalidRequest.WithMessage(
				"a request cannot carry both ?uploads and ?uploadId")
		}
		if r.Method != http.MethodPost {
			return unsupported(req), ErrNotImplemented.WithMessage(
				"method %s is not implemented for ?uploads on an object", r.Method)
		}
		req.Op = OpCreateMultipartUpload
		return req, nil
	}

	// Every operation below acts on an existing upload, so it needs a usable id.
	if uploadID == "" {
		return unsupported(req), ErrInvalidArgument.WithMessage("the request names no upload id")
	}

	switch r.Method {
	case http.MethodPut:
		number, apiErr := partNumber(r.URL.Query().Get("partNumber"))
		if apiErr != nil {
			return unsupported(req), apiErr
		}
		// UploadPartCopy: a part whose bytes come from another object rather
		// than from the request body. Same method, same path, no body -- only
		// the copy source tells them apart.
		req.PartNumber = number
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			req.Op = OpUploadPartCopy
		} else {
			req.Op = OpUploadPart
		}
		return req, nil

	case http.MethodPost:
		req.Op = OpCompleteMultipartUpload
		return req, nil

	case http.MethodDelete:
		req.Op = OpAbortMultipartUpload
		return req, nil

	case http.MethodGet, http.MethodHead:
		req.Op = OpListParts
		return req, nil
	}
	return unsupported(req), ErrNotImplemented.WithMessage(
		"method %s is not implemented for multipart uploads", r.Method)
}

// partNumber parses and bounds the ?partNumber parameter.
func partNumber(raw string) (int, *Error) {
	if raw == "" {
		return 0, ErrInvalidArgument.WithMessage("a part upload must name a part number")
	}
	number, err := strconv.Atoi(raw)
	if err != nil || number < 1 || number > MaxPartNumber {
		return 0, ErrInvalidArgument.WithMessage(
			"part number %q is not an integer in 1..%d", raw, MaxPartNumber)
	}
	return number, nil
}

func unsupported(req Request) Request {
	req.Op = OpUnsupported
	return req
}

func objectOperation(method string) Operation {
	switch method {
	case http.MethodPut:
		return OpPutObject
	case http.MethodGet:
		return OpGetObject
	case http.MethodHead:
		return OpHeadObject
	case http.MethodDelete:
		return OpDeleteObject
	default:
		return OpUnsupported
	}
}

// splitTarget determines the bucket and key a request addresses, handling both
// addressing styles.
func splitTarget(r *http.Request, baseDomain string) (bucket, key string) {
	if b, ok := virtualHostBucket(r.Host, baseDomain); ok {
		return b, strings.TrimPrefix(r.URL.Path, "/")
	}
	return splitPath(r.URL.Path)
}

// virtualHostBucket extracts the bucket from a virtual-hosted-style authority.
func virtualHostBucket(host, baseDomain string) (string, bool) {
	if baseDomain == "" || host == "" {
		return "", false
	}
	// The authority may carry a port; the bucket never does.
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	base := strings.TrimSuffix(strings.ToLower(baseDomain), ".")

	prefix, ok := strings.CutSuffix(host, "."+base)
	if !ok || prefix == "" {
		return "", false
	}
	// A dotted prefix would be a sub-domain of the bucket, not a bucket name.
	if strings.Contains(prefix, ".") {
		return "", false
	}
	return prefix, true
}

// splitPath separates the bucket from the key in a path-style URL.
//
// The decoded path is used deliberately. S3 keys are flat strings in which '/'
// carries no special meaning, and a client that sends %2F means the same object
// as one that sends '/', so decoding first is what matches the real service.
func splitPath(path string) (bucket, key string) {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "", ""
	}
	bucket, key, _ = strings.Cut(trimmed, "/")
	return bucket, key
}
