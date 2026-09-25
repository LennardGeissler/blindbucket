// Package probe measures what a provider does with the conditional writes
// blindbucket relies on, rather than assuming it.
//
// Rotation guards two windows with a precondition each (ADR-009). A provider
// that refuses a precondition is safe -- the request fails and the object is
// left alone. A provider that ignores one is not, and Garage v2.4.1 ignores
// If-Match on CompleteMultipartUpload: the upload completes over whatever is
// there. Nothing in a response distinguishes that from a write that was allowed,
// so the only way to know is to ask with a condition that must fail and see
// whether it does. See docs/adr/ADR-020-conditional-writes-measured.md.
package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Prefix is where the probe keeps its one object. It is under the reserved
// prefix, so no client can read or write it, and outside the manifest prefix,
// so `gc` never considers it.
const Prefix = s3api.ReservedPrefix + "probe/"

// wrongETag is an ETag no object has: it is a quoted MD5 of the right length,
// so a provider that validates the shape of the header still has to compare it.
const wrongETag = `"00000000000000000000000000000000"`

// Outcome is what a provider did with a condition that should have failed.
type Outcome int

const (
	// Enforced means the provider answered 412, which is the only safe answer.
	Enforced Outcome = iota
	// Ignored means the request succeeded as if the condition were not there.
	Ignored
	// Refused means the provider answered with some other error -- typically that
	// it does not implement the header or the operation.
	Refused
)

func (o Outcome) String() string {
	switch o {
	case Enforced:
		return "enforced"
	case Ignored:
		return "ignored"
	case Refused:
		return "refused"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// Check is one condition and what happened to it.
type Check struct {
	// Name says which header on which request, as an operator would search for
	// it in the provider's documentation.
	Name    string
	Outcome Outcome
	// Detail is the provider's error for a Refused outcome, and empty otherwise.
	Detail string
}

// Conditions reports the two guards rotation depends on.
type Conditions struct {
	// CopySourceIfMatch is x-amz-copy-source-if-match on UploadPartCopy: the
	// guard between the rotation's HEAD and its copy.
	CopySourceIfMatch Check
	// CompleteIfMatch is If-Match on CompleteMultipartUpload: the guard between
	// the copy and the object being published.
	CompleteIfMatch Check
}

// Checks returns both checks in the order a rotation meets them.
func (c Conditions) Checks() []Check {
	return []Check{c.CopySourceIfMatch, c.CompleteIfMatch}
}

// Safe reports whether a rotation can rely on both guards.
func (c Conditions) Safe() bool {
	for _, check := range c.Checks() {
		if check.Outcome != Enforced {
			return false
		}
	}
	return true
}

// ConditionalWrites measures both guards against bucket.
//
// It writes one small object under Prefix and removes it again, whatever the
// outcome. An error means the measurement itself could not be made -- the
// bucket is unreachable, say -- and says nothing about the provider's
// conditions.
func ConditionalWrites(ctx context.Context, client *upstream.Client, bucket string) (Conditions, error) {
	if client == nil {
		return Conditions{}, errors.New("probe: an upstream client is required")
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return Conditions{}, err
	}
	key := Prefix + hex.EncodeToString(suffix)
	body := "blindbucket conditional-write probe\n"

	if _, err := client.PutObject(ctx, upstream.PutObjectInput{
		Bucket: bucket, Key: key,
		Body: strings.NewReader(body), ContentLength: int64(len(body)),
		ContentType: "text/plain",
	}); err != nil {
		return Conditions{}, fmt.Errorf("probe: writing %s: %w", key, err)
	}
	// Removed on every path out. The object is a few bytes that nothing reads,
	// so a failed delete is not worth failing the measurement over.
	defer func() { _ = client.DeleteObject(context.WithoutCancel(ctx), bucket, key) }()

	uploadID, err := client.CreateMultipartUpload(ctx, upstream.CreateMultipartUploadInput{
		Bucket: bucket, Key: key, ContentType: "text/plain",
	})
	if err != nil {
		return Conditions{}, fmt.Errorf("probe: opening an upload: %w", err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = client.AbortMultipartUpload(context.WithoutCancel(ctx), bucket, key, uploadID)
		}
	}()

	var out Conditions

	// Guard 1. The object is copied onto its own upload, so a provider that
	// ignored the condition has only copied a probe onto itself.
	_, err = client.UploadPartCopy(ctx, upstream.UploadPartCopyInput{
		SourceBucket: bucket, SourceKey: key,
		Bucket: bucket, Key: key, UploadID: uploadID,
		PartNumber: 1, WholeObject: true, SourceIfMatch: wrongETag,
	})
	if out.CopySourceIfMatch, err = classify("x-amz-copy-source-if-match on UploadPartCopy", err); err != nil {
		return Conditions{}, err
	}

	// Guard 2. The part is uploaded rather than copied, so that the answer does
	// not depend on whether guard 1 let the copy through.
	etag, err := client.UploadPart(ctx, upstream.UploadPartInput{
		Bucket: bucket, Key: key, UploadID: uploadID, PartNumber: 1,
		Body: strings.NewReader(body), ContentLength: int64(len(body)),
	})
	if err != nil {
		return Conditions{}, fmt.Errorf("probe: uploading a part: %w", err)
	}
	_, err = client.CompleteMultipartUpload(ctx, upstream.CompleteMultipartUploadInput{
		Bucket: bucket, Key: key, UploadID: uploadID,
		Parts:   []upstream.CompletedPart{{PartNumber: 1, ETag: etag}},
		IfMatch: wrongETag,
	})
	if err == nil {
		completed = true
	}
	if out.CompleteIfMatch, err = classify("If-Match on CompleteMultipartUpload", err); err != nil {
		return Conditions{}, err
	}
	return out, nil
}

// classify turns the answer to a request whose condition had to fail into an
// Outcome.
//
// Only an answer from the provider counts. A request that never got one -- a
// reset connection, a timeout -- measured nothing, and calling it Refused would
// report a network problem as a fact about the provider.
func classify(name string, err error) (Check, error) {
	if err == nil {
		return Check{Name: name, Outcome: Ignored}, nil
	}
	if upstream.PreconditionFailed(err) {
		return Check{Name: name, Outcome: Enforced}, nil
	}
	if _, ok := upstream.AsAPIError(err); ok {
		return Check{Name: name, Outcome: Refused, Detail: err.Error()}, nil
	}
	return Check{}, fmt.Errorf("probe: %s: no answer from the provider: %w", name, err)
}
