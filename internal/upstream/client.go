package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// unsignedPayload tells SigV4 that the body is not covered by the signature.
//
// Signing the body would mean hashing it before sending it, which for a stream
// means buffering the whole object -- exactly what this project refuses to do.
// Nothing is lost: transport integrity comes from TLS, and content integrity
// comes from the blindbucket format itself, which authenticates every chunk.
const unsignedPayload = "UNSIGNED-PAYLOAD"

// Config describes the storage provider to talk to.
type Config struct {
	// Endpoint is the provider's base URL, for example
	// https://<account>.r2.cloudflarestorage.com or http://localhost:9002.
	Endpoint string
	// Region is the SigV4 signing region: "auto" for R2, "us-east-1" for MinIO.
	Region string
	// PathStyle addresses buckets as /<bucket>/<key> rather than as a subdomain.
	PathStyle bool

	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// Credentials supplies the credentials instead of the three fields above,
	// and is asked before every request, so that a source whose credentials
	// expire -- web identity, a container endpoint, the instance role --
	// refreshes them behind it (ADR-024). Set it or the fields, not both.
	Credentials aws.CredentialsProvider

	// HTTPClient overrides the default transport. Mainly for tests.
	HTTPClient *http.Client

	// MaxRetries bounds retries of idempotent, bodyless requests. Zero selects
	// the default of 3.
	MaxRetries int

	// ObserveRequest, if set, is called with the S3 operation and how long the
	// provider took to answer it, retries included. It is how
	// blindbucket_upstream_duration_seconds is filled without this package
	// knowing anything about metrics.
	ObserveRequest func(op string, d time.Duration)
}

// Client is a small signing S3 client built on net/http.
//
// A full SDK client is deliberately avoided; see
// docs/adr/ADR-003-upstream-client.md. In short, its middleware wants to buffer
// or re-read bodies, attaches checksums of its own, and obscures what actually
// goes over the wire -- all of which fight a streaming proxy.
//
// A Client is safe for concurrent use.
type Client struct {
	endpoint   *url.URL
	region     string
	pathStyle  bool
	creds      aws.CredentialsProvider
	signer     *v4.Signer
	httpClient *http.Client
	maxRetries int
	observe    func(op string, d time.Duration)

	// now is overridable so signing can be tested against fixed timestamps.
	now func() time.Time
}

// New builds a client from cfg.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("upstream: endpoint is required")
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("upstream: parsing endpoint: %w", err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, fmt.Errorf("upstream: endpoint scheme %q is not http or https", endpoint.Scheme)
	}
	if cfg.Region == "" {
		return nil, errors.New("upstream: region is required")
	}
	creds := cfg.Credentials
	switch {
	case creds != nil && (cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" || cfg.SessionToken != ""):
		return nil, errors.New("upstream: credentials are configured twice, as keys and as a provider")
	case creds == nil && (cfg.AccessKeyID == "" || cfg.SecretAccessKey == ""):
		return nil, errors.New("upstream: credentials are required")
	case creds == nil:
		static := aws.Credentials{
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
			SessionToken:    cfg.SessionToken,
		}
		creds = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return static, nil
		})
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	retries := cfg.MaxRetries
	if retries == 0 {
		retries = 3
	}

	return &Client{
		endpoint:  endpoint,
		region:    cfg.Region,
		pathStyle: cfg.PathStyle,
		creds:     creds,
		// S3 does not double-encode the path in the canonical request, unlike
		// every other AWS service. Without this the signature is wrong for any
		// key containing a character that needs escaping.
		signer:     v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }),
		httpClient: httpClient,
		maxRetries: retries,
		observe:    cfg.ObserveRequest,
		now:        time.Now,
	}, nil
}

// defaultHTTPClient is tuned for many concurrent streams to one host, with
// timeouts on everything except the body transfer itself: a large object may
// legitimately take a long time, but a connection must not stall indefinitely.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          256,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			// Wait this long for the 100-continue before sending a body, so an
			// auth or bucket error is seen before gigabytes are streamed.
			ExpectContinueTimeout: 5 * time.Second,
		},
		// No Client.Timeout: it would cut off long but healthy transfers.
	}
}

// objectURL builds the URL for one object.
//
// Both Path and RawPath are set. Path is the decoded form Go needs internally;
// RawPath is the AWS-style encoding, which escapes everything outside the
// unreserved set. Go's own path escaping leaves characters such as '+', '$',
// ':' and '@' alone, and S3 signs the encoded path, so relying on it would
// produce signature mismatches for perfectly ordinary keys.
func (c *Client) objectURL(bucket, key string) *url.URL {
	u := *c.endpoint
	if c.pathStyle {
		u.Path = "/" + bucket + "/" + key
		u.RawPath = "/" + uriEncodePath(bucket) + "/" + uriEncodePath(key)
	} else {
		u.Host = bucket + "." + u.Host
		u.Path = "/" + key
		u.RawPath = "/" + uriEncodePath(key)
	}
	return &u
}

// uriEncodePath applies the AWS UriEncode rules to a path, leaving the '/'
// separators intact.
func uriEncodePath(p string) string {
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s)
	}
	return strings.Join(segments, "/")
}

// uriEncode percent-encodes every byte outside the unreserved set A-Z a-z 0-9
// - . _ ~, with uppercase hex digits, as SigV4 requires. Notably a space
// becomes %20 and never '+'.
func uriEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9',
			ch == '-', ch == '.', ch == '_', ch == '~':
			b.WriteByte(ch)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[ch>>4])
			b.WriteByte(upperhex[ch&0x0f])
		}
	}
	return b.String()
}

// sign adds the SigV4 Authorization header to req.
func (c *Client) sign(ctx context.Context, req *http.Request) error {
	// S3 requires this header to be present and signed. The SDK's own
	// middleware would set it; calling the signer directly means we do.
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	creds, err := c.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	return c.signer.SignHTTP(ctx, creds, req, unsignedPayload, "s3", c.region, c.now().UTC())
}

// do signs and sends a request, returning the response only for 2xx statuses.
//
// Retries are limited to requests that carry no body. A failed upload cannot be
// replayed -- the client's stream has already been consumed -- so the error goes
// back to the client, which is the only party still able to resend the data.
func (c *Client) do(ctx context.Context, req *http.Request, op string, retryable bool) (*http.Response, error) {
	if c.observe != nil {
		started := c.now()
		defer func() { c.observe(op, time.Since(started)) }()
	}

	attempts := 1
	if retryable {
		attempts = c.maxRetries
	}

	var lastErr error
	for attempt := range attempts {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		attemptReq := req.Clone(ctx)
		if err := c.sign(ctx, attemptReq); err != nil {
			return nil, fmt.Errorf("upstream: signing: %w", err)
		}
		// Expect is set after signing on purpose: it is not part of the signed
		// headers, and adding it beforehand would only invite confusion about
		// whether it is.
		if req.Body != nil && req.ContentLength > 0 {
			attemptReq.Header.Set("Expect", "100-continue")
		}

		resp, err := c.httpClient.Do(attemptReq)
		if err != nil {
			lastErr = fmt.Errorf("upstream: %w", err)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if resp.StatusCode < 300 {
			return resp, nil
		}

		apiErr := newAPIError(resp, op)
		_ = resp.Body.Close()
		if !shouldRetry(resp.StatusCode) {
			return nil, apiErr
		}
		lastErr = apiErr
	}
	return nil, lastErr
}

// shouldRetry reports whether a status is worth another attempt: transient
// server-side conditions only, never a client error the provider will repeat.
func shouldRetry(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusRequestTimeout ||
		status >= http.StatusInternalServerError
}

// newRequest builds an unsigned request against the object URL.
func (c *Client) newRequest(ctx context.Context, method, bucket, key string) (*http.Request, error) {
	u := c.objectURL(bucket, key)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// http.NewRequest re-parses the URL and loses RawPath when it round-trips
	// through String(); set the carefully built URL back.
	req.URL = u
	req.Host = u.Host
	return req, nil
}
