package awscreds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// STS is spoken through its query API: a form POST and an XML answer, the
// same shape the S3 and KMS clients already handle by hand (ADR-003,
// ADR-013). Two actions are needed. AssumeRoleWithWebIdentity is unsigned --
// the token is the credential -- and is what IRSA, GitHub's OIDC token and a
// profile's web_identity_token_file all come down to. AssumeRole is signed
// with the credentials of a profile's source_profile.

const stsAPIVersion = "2011-06-15"

// maxSTSBody bounds what is read from STS: a credentials answer is a few
// kilobytes, and nothing on the wire should be able to make this read more.
const maxSTSBody = 1 << 20

// stsCredentials is the Credentials element of either action's answer.
type stsCredentials struct {
	AccessKeyID     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	SessionToken    string    `xml:"SessionToken"`
	Expiration      time.Time `xml:"Expiration"`
}

type stsAnswer struct {
	WebIdentity stsCredentials `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
	AssumeRole  stsCredentials `xml:"AssumeRoleResult>Credentials"`
}

type stsErrorAnswer struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// stsEndpoint is where STS is asked: AWS_ENDPOINT_URL_STS when set, else the
// regional endpoint, else the global one.
//
// AWS_ENDPOINT_URL -- the override for every service at once -- is
// deliberately not read. A shell that points the AWS CLI at this gateway with
// it would otherwise point the gateway's own STS calls at itself.
func stsEndpoint(opts *Options, region string) string {
	if override := opts.getenv("AWS_ENDPOINT_URL_STS"); override != "" {
		return strings.TrimRight(override, "/")
	}
	if region == "" {
		return "https://sts.amazonaws.com"
	}
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	return "https://sts." + region + "." + suffix
}

// stsRegion is the region STS is asked in, in the SDK's order of precedence.
func stsRegion(opts *Options, fromProfile string) string {
	if r := firstOf(opts, "AWS_REGION", "AWS_DEFAULT_REGION"); r != "" {
		return r
	}
	if fromProfile != "" {
		return fromProfile
	}
	return opts.Region
}

// webIdentity is one AssumeRoleWithWebIdentity configuration.
type webIdentity struct {
	tokenFile   string
	roleARN     string
	sessionName string
	region      string
}

// webIdentityFetcher reads the variables IRSA sets: AWS_WEB_IDENTITY_TOKEN_FILE,
// AWS_ROLE_ARN and, optionally, AWS_ROLE_SESSION_NAME.
func webIdentityFetcher(opts *Options) (fetcher, string, error) {
	wi := webIdentity{
		tokenFile:   opts.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"),
		roleARN:     opts.getenv("AWS_ROLE_ARN"),
		sessionName: opts.getenv("AWS_ROLE_SESSION_NAME"),
		region:      stsRegion(opts, ""),
	}
	return wi.fetcher(opts, "the environment")
}

func (wi webIdentity) fetcher(opts *Options, where string) (fetcher, string, error) {
	switch {
	case wi.tokenFile == "":
		return nil, "", fmt.Errorf("awscreds: web identity from %s needs a token file "+
			"(AWS_WEB_IDENTITY_TOKEN_FILE, or web_identity_token_file in a profile)", where)
	case wi.roleARN == "":
		return nil, "", fmt.Errorf("awscreds: web identity from %s needs a role (AWS_ROLE_ARN, "+
			"or role_arn in a profile)", where)
	}
	if wi.sessionName == "" {
		wi.sessionName = defaultSessionName(opts)
	}
	endpoint := stsEndpoint(opts, wi.region)
	describe := fmt.Sprintf("web identity from %s, role %s", where, wi.roleARN)

	return func(ctx context.Context) (aws.Credentials, error) {
		// Read on every fetch: a projected service-account token is rotated
		// by the kubelet, and the one read at startup expires long before
		// the pod does.
		//nolint:gosec // the path is the operator's configuration.
		token, err := os.ReadFile(wi.tokenFile)
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("reading the web identity token: %w", err)
		}
		form := url.Values{
			"Action":           {"AssumeRoleWithWebIdentity"},
			"Version":          {stsAPIVersion},
			"RoleArn":          {wi.roleARN},
			"RoleSessionName":  {wi.sessionName},
			"WebIdentityToken": {strings.TrimSpace(string(token))},
		}
		answer, err := callSTS(ctx, opts, endpoint, form, nil, "")
		if err != nil {
			return aws.Credentials{}, err
		}
		return answer.WebIdentity.credentials("web identity")
	}, describe, nil
}

// assumeRole is AssumeRole, signed with the credentials of a source profile.
func assumeRole(opts *Options, source fetcher, roleARN, sessionName, externalID, region string,
	duration int,
) fetcher {
	if sessionName == "" {
		sessionName = defaultSessionName(opts)
	}
	endpoint := stsEndpoint(opts, region)
	signingRegion := region
	if signingRegion == "" {
		signingRegion = "us-east-1"
	}
	return func(ctx context.Context) (aws.Credentials, error) {
		creds, err := source(ctx)
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("the source profile: %w", err)
		}
		form := url.Values{
			"Action":          {"AssumeRole"},
			"Version":         {stsAPIVersion},
			"RoleArn":         {roleARN},
			"RoleSessionName": {sessionName},
		}
		if externalID != "" {
			form.Set("ExternalId", externalID)
		}
		if duration > 0 {
			form.Set("DurationSeconds", strconv.Itoa(duration))
		}
		answer, err := callSTS(ctx, opts, endpoint, form, &creds, signingRegion)
		if err != nil {
			return aws.Credentials{}, err
		}
		return answer.AssumeRole.credentials("assumed role")
	}
}

// callSTS posts one query-API request and parses the answer. A non-nil signer
// credential signs it.
func callSTS(ctx context.Context, opts *Options, endpoint string, form url.Values,
	signWith *aws.Credentials, region string,
) (stsAnswer, error) {
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(body))
	if err != nil {
		return stsAnswer{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if signWith != nil {
		sum := sha256.Sum256([]byte(body))
		if err := v4.NewSigner().SignHTTP(ctx, *signWith, req, hex.EncodeToString(sum[:]),
			"sts", region, opts.now().UTC()); err != nil {
			return stsAnswer{}, fmt.Errorf("signing the STS request: %w", err)
		}
	}

	resp, err := opts.httpClient().Do(req)
	if err != nil {
		return stsAnswer{}, fmt.Errorf("asking STS at %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSTSBody))
	if err != nil {
		return stsAnswer{}, fmt.Errorf("reading the STS answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var failure stsErrorAnswer
		if xml.Unmarshal(raw, &failure) == nil && failure.Error.Code != "" {
			return stsAnswer{}, fmt.Errorf("STS %s: %s: %s", form.Get("Action"),
				failure.Error.Code, failure.Error.Message)
		}
		return stsAnswer{}, fmt.Errorf("STS %s answered %d", form.Get("Action"), resp.StatusCode)
	}
	var answer stsAnswer
	if err := xml.Unmarshal(raw, &answer); err != nil {
		return stsAnswer{}, fmt.Errorf("the STS answer is not valid XML: %w", err)
	}
	return answer, nil
}

func (c stsCredentials) credentials(source string) (aws.Credentials, error) {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.Expiration.IsZero() {
		return aws.Credentials{}, errors.New("STS answered without complete credentials")
	}
	return aws.Credentials{
		AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey,
		SessionToken: c.SessionToken, Source: source,
		CanExpire: true, Expires: c.Expiration,
	}, nil
}

// defaultSessionName names a session when nothing else does. CloudTrail shows
// it next to every call made with the credentials, so it says what made them.
func defaultSessionName(opts *Options) string {
	return "blindbucket-" + strconv.FormatInt(opts.now().UnixNano(), 10)
}
