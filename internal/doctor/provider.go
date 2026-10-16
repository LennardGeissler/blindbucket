package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/probe"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Recorder is a transport that remembers the last response it saw.
//
// The upstream client turns an error response into an error and keeps the
// code and the message, not the headers. Two of the answers doctor needs are
// only in the headers, and come with failures as often as with successes: the
// provider's clock in Date, and where a bucket lives in x-amz-bucket-region.
type Recorder struct {
	Base http.RoundTripper

	mu       sync.Mutex
	header   http.Header
	received time.Time
	now      func() time.Time
}

// NewRecorder wraps base.
func NewRecorder(base http.RoundTripper) *Recorder {
	return &Recorder{Base: base, now: time.Now}
}

// RoundTrip implements http.RoundTripper.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.Base.RoundTrip(req)
	if err == nil {
		r.mu.Lock()
		r.header, r.received = resp.Header.Clone(), r.now()
		r.mu.Unlock()
	}
	return resp, err
}

// Last returns the headers of the last response, and when it arrived. The
// header is nil if no response has.
func (r *Recorder) Last() (http.Header, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.header, r.received
}

// Provider asks the configured provider. Client must send its requests
// through Recorder.
type Provider struct {
	Client   *upstream.Client
	Recorder *Recorder
	Endpoint string
	Region   string
}

// Bucket asks for one key of bucket. That single read answers most of what can
// be wrong between the gateway and the provider: whether the endpoint answers
// and its certificate verifies, whether the credentials and the region are
// right, whether the bucket exists, and whether the credentials may list it.
func (p Provider) Bucket(ctx context.Context, bucket string) Check {
	_, err := p.Client.ListObjects(ctx, bucket, url.Values{"list-type": {"2"}, "max-keys": {"1"}})
	if err == nil {
		c := Ok(NameBucket, fmt.Sprintf("%s answered a listing of %s", p.Endpoint, bucket))
		c.Bucket = bucket
		return c
	}
	header, _ := p.Recorder.Last()
	detail, fix := p.explain(err, header, bucket)
	c := Fail(NameBucket, detail, fix)
	c.Bucket = bucket
	return c
}

// expectingRegion finds the region in AWS's AuthorizationHeaderMalformed
// message: "the region 'us-east-1' is wrong; expecting 'eu-central-1'".
var expectingRegion = regexp.MustCompile(`expecting '([a-z0-9-]+)'`)

// explain turns an error from the provider into what was found and what to
// change.
func (p Provider) explain(err error, header http.Header, bucket string) (detail, fix string) {
	detail = err.Error()

	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if errors.As(err, &certErr) || errors.As(err, &unknownCA) || errors.As(err, &hostErr) {
		return detail, fmt.Sprintf("the certificate %s presents does not verify: use the name "+
			"the certificate is for in upstream.endpoint, or add its CA to this host's trust store", p.Endpoint)
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return detail, fmt.Sprintf("nothing answered at upstream.endpoint (%s): check the address "+
			"and port, and that this host can reach it", p.Endpoint)
	}

	apiErr, ok := upstream.AsAPIError(err)
	if !ok {
		return detail, "see the error above; it did not come from the provider"
	}
	region := header.Get("x-amz-bucket-region")
	if m := expectingRegion.FindStringSubmatch(apiErr.Message); m != nil {
		region = m[1]
	}
	switch apiErr.Code {
	case "InvalidAccessKeyId":
		return detail, "the provider does not know upstream.access_key_id: check the key, " +
			"and that it belongs to this provider and account"
	case "SignatureDoesNotMatch":
		return detail, "upstream.secret_access_key does not belong to upstream.access_key_id"
	case "RequestTimeTooSkewed":
		return detail, "this host's clock is too far from the provider's for a signature to " +
			"be accepted: synchronise it (NTP)"
	case "AuthorizationHeaderMalformed", "PermanentRedirect", "IllegalLocationConstraintException":
		if region != "" && region != p.Region {
			return detail, fmt.Sprintf("the provider says %s is in %s: set upstream.region to %q",
				bucket, region, region)
		}
		return detail, "check upstream.region and upstream.endpoint: the provider expects " +
			"this bucket to be addressed elsewhere"
	case "NoSuchBucket":
		return detail, fmt.Sprintf("create %s -- at the provider, or with `aws s3 mb s3://%s` "+
			"through the gateway -- or correct the bucket in clients[].buckets", bucket, bucket)
	case "AccessDenied", "AllAccessDisabled":
		return detail, fmt.Sprintf("the provider's credentials may not list %s: grant "+
			"s3:ListBucket on it, and for the gateway to work s3:GetObject, s3:PutObject, "+
			"s3:DeleteObject and the multipart actions on its objects", bucket)
	}
	return detail, "see the provider's error above"
}

// ConditionalWrites measures the conditions rotation and name migration rely
// on, by calling what `probe` calls. It writes one small object under
// .blindbucket/probe/ and removes it again, which also proves the credentials
// may write.
func (p Provider) ConditionalWrites(ctx context.Context, bucket string) Check {
	c := p.conditionalWrites(ctx, bucket)
	c.Bucket = bucket
	return c
}

func (p Provider) conditionalWrites(ctx context.Context, bucket string) Check {
	conds, err := probe.ConditionalWrites(ctx, p.Client, bucket)
	if err != nil {
		if apiErr, ok := upstream.AsAPIError(err); ok && (apiErr.Code == "AccessDenied" || apiErr.StatusCode == http.StatusForbidden) {
			return Fail(NameConditionalWrites, err.Error(), fmt.Sprintf("the provider's credentials may "+
				"list %s but not write to it: grant s3:PutObject, s3:DeleteObject and the multipart "+
				"actions -- or pass --no-write to skip this check where that is deliberate", bucket))
		}
		return Fail(NameConditionalWrites, err.Error(),
			"the measurement could not be made; `blindbucket probe` asks the same question on its own")
	}

	rotation, migration := conds.SafeForRotation(), conds.SafeForMigration()
	switch {
	case rotation && migration:
		return Ok(NameConditionalWrites, "enforced: rotate and migrate-names are guarded")
	case rotation:
		return Warn(NameConditionalWrites,
			"rotate is guarded; If-None-Match on CompleteMultipartUpload is "+
				conds.CompleteIfNoneMatch.Outcome.String(),
			"migrate-names will refuse here without --allow-unconditional (ADR-022); "+
				"the gateway itself is not affected")
	default:
		return Warn(NameConditionalWrites,
			fmt.Sprintf("x-amz-copy-source-if-match %s, If-Match on the completion %s",
				conds.CopySourceIfMatch.Outcome, conds.CompleteIfMatch.Outcome),
			"rotate and migrate-names will refuse here without --allow-unconditional "+
				"(ADR-020); the gateway itself is not affected")
	}
}

// The clock thresholds. SigV4 allows 15 minutes either way, and past that the
// provider refuses every request; a host whose clock is kept by NTP is within
// milliseconds, so a minute already means the clock is not being kept.
const (
	ClockWarning = time.Minute
	ClockFailure = 15 * time.Minute
)

// Clock compares this host's clock with the provider's Date header on the last
// response, which arrives on errors as well as on successes.
func (p Provider) Clock() Check {
	header, received := p.Recorder.Last()
	if header == nil {
		return Skip(NameClock, "no response from the provider to read its clock from")
	}
	theirs, err := http.ParseTime(header.Get("Date"))
	if err != nil {
		return Skip(NameClock, "the provider's response carried no usable Date header")
	}
	return clockCheck(received.Sub(theirs))
}

func clockCheck(skew time.Duration) Check {
	// Date has a resolution of one second.
	skew = skew.Round(time.Second)
	abs := skew.Abs()
	detail := "this host's clock agrees with the provider's"
	if abs > 0 {
		dir := "ahead of"
		if skew < 0 {
			dir = "behind"
		}
		detail = fmt.Sprintf("this host's clock is %s %s the provider's", abs, dir)
	}
	fix := "synchronise this host's clock (NTP)"
	switch {
	case abs >= ClockFailure:
		return Fail(NameClock, detail, fix+": past 15 minutes the provider refuses every signature")
	case abs >= ClockWarning:
		return Warn(NameClock, detail, fix+": a clock kept by NTP is within milliseconds")
	}
	return Ok(NameClock, detail)
}
