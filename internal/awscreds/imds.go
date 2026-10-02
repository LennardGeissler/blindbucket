package awscreds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// The EC2 instance role, through the instance metadata service -- version 2
// only. IMDSv2 asks for a session token with a PUT before it answers anything,
// which is what keeps a server-side request forgery on the instance, or a
// container one hop too far away, from reading the role's credentials with a
// plain GET. Falling back to version 1 when the PUT fails would throw exactly
// that away, so there is no fallback: a PUT that fails is an error that says
// why it usually does.

const (
	imdsDefaultEndpoint = "http://169.254.169.254"
	imdsIPv6Endpoint    = "http://[fd00:ec2::254]"
	imdsTokenTTL        = 6 * time.Hour
	imdsCredentialsPath = "/latest/meta-data/iam/security-credentials/" //nolint:gosec // a path, not a credential
	maxIMDSBody         = 1 << 20
)

type imdsAnswer struct {
	Code            string    `json:"Code"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

func imdsDisabled(opts *Options) bool {
	return strings.EqualFold(opts.getenv("AWS_EC2_METADATA_DISABLED"), "true")
}

func imdsEndpoint(opts *Options) string {
	if e := opts.getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT"); e != "" {
		return strings.TrimRight(e, "/")
	}
	if strings.EqualFold(opts.getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE"), "IPv6") {
		return imdsIPv6Endpoint
	}
	return imdsDefaultEndpoint
}

// imdsClient connects fast or not at all. Off EC2 the link-local address
// usually answers nothing, and a ten-second wait at every startup to find
// that out would be its own outage.
func imdsClient(opts *Options) *http.Client {
	if opts.HTTPClient != nil {
		return opts.HTTPClient
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil, // the metadata service is never behind a proxy
			DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
		},
	}
}

func imdsFetcher(opts *Options) (fetcher, string, error) {
	if imdsDisabled(opts) {
		return nil, "", errors.New("awscreds: the imds source is configured, and " +
			"AWS_EC2_METADATA_DISABLED says not to use it")
	}
	s := &imdsSession{endpoint: imdsEndpoint(opts), client: imdsClient(opts), now: opts.now}
	return s.fetch, "IMDSv2 instance role at " + s.endpoint, nil
}

// imdsSession holds the session token between fetches, for as long as it lasts.
type imdsSession struct {
	endpoint string
	client   *http.Client
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (s *imdsSession) fetch(ctx context.Context) (aws.Credentials, error) {
	token, err := s.sessionToken(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	roles, err := s.get(ctx, token, imdsCredentialsPath)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("listing the instance role: %w", err)
	}
	role := strings.TrimSpace(strings.SplitN(roles, "\n", 2)[0])
	if role == "" {
		return aws.Credentials{}, errors.New("the instance has no IAM role attached")
	}
	raw, err := s.get(ctx, token, imdsCredentialsPath+role)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("reading the credentials of role %s: %w", role, err)
	}
	var answer imdsAnswer
	if err := json.Unmarshal([]byte(raw), &answer); err != nil {
		return aws.Credentials{}, fmt.Errorf("the credentials of role %s are not JSON: %w", role, err)
	}
	if answer.Code != "Success" {
		return aws.Credentials{}, fmt.Errorf("IMDS answered code %q for role %s", answer.Code, role)
	}
	return aws.Credentials{
		AccessKeyID: answer.AccessKeyID, SecretAccessKey: answer.SecretAccessKey,
		SessionToken: answer.Token, Source: "imds",
		CanExpire: !answer.Expiration.IsZero(), Expires: answer.Expiration,
	}, nil
}

// sessionToken returns a valid IMDSv2 session token, asking for a new one a
// minute before the old one lapses.
func (s *imdsSession) sessionToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.expires.Add(-time.Minute)) {
		return s.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.endpoint+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds",
		strconv.Itoa(int(imdsTokenTTL/time.Second)))
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("asking IMDS at %s for a session token: %w -- off EC2 nothing "+
			"answers there; in a container on EC2, the instance's PUT response hop limit has to "+
			"be at least 2 for IMDSv2 to reach it", s.endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIMDSBody))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS refused a session token with %d; IMDSv1 is not used as a "+
			"fallback (ADR-024)", resp.StatusCode)
	}
	s.token = strings.TrimSpace(string(raw))
	s.expires = s.now().Add(imdsTokenTTL)
	return s.token, nil
}

func (s *imdsSession) get(ctx context.Context, token, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIMDSBody))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The token lapsed early, or the instance was restarted under it.
		s.mu.Lock()
		s.token = ""
		s.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS answered %d", resp.StatusCode)
	}
	return string(raw), nil
}
