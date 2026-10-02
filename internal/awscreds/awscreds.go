// Package awscreds resolves AWS credentials the way the AWS SDKs do, for the
// two places this gateway talks to AWS: the upstream S3 provider and KMS.
//
// It exists instead of the SDK's config module, which would solve the same
// problem and bring twelve more modules into a build that needs two
// (ADR-024). What it covers is what a gateway runs under: static keys, the
// environment, a shared profile, web identity (IRSA, and GitHub's OIDC
// token), a container endpoint (ECS task roles, EKS Pod Identity) and the EC2
// instance role through IMDSv2. What it leaves out is what a person runs
// under -- SSO, credential_process -- and says so when a profile asks for it.
//
// Two decisions differ from the SDK on purpose, both in ADR-024. A source is
// chosen explicitly by configuration, and the chain picks the first source
// whose configuration is present and stops there: a web identity that fails
// is an error, never a quiet fall-through to the node's instance role. And
// the cache keeps serving credentials that are still valid while a refresh
// fails, where the SDK's fails as soon as the refresh window opens.
package awscreds

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// The sources a configuration may name.
const (
	SourceStatic      = "static"
	SourceEnv         = "env"
	SourceProfile     = "profile"
	SourceWebIdentity = "web_identity"
	SourceContainer   = "container"
	SourceIMDS        = "imds"
	SourceChain       = "chain"
)

// Sources lists every source name, for validation and error messages.
var Sources = []string{
	SourceStatic, SourceEnv, SourceProfile, SourceWebIdentity, SourceContainer,
	SourceIMDS, SourceChain,
}

// Options says where credentials come from.
type Options struct {
	// Source is one of the Source constants.
	Source string

	// AccessKeyID, SecretAccessKey and SessionToken are the keys of
	// SourceStatic, and must be empty for every other source: keys and a
	// source together are two answers to one question.
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// Region is where STS is asked when neither AWS_REGION nor the profile
	// names one: the region of the service the credentials are for.
	Region string

	// HTTPClient makes the requests to STS and the container endpoint. Nil
	// means a client with a ten-second timeout. IMDS uses a client of its own
	// with a short connect timeout, because off EC2 the address answers
	// nothing at all.
	HTTPClient *http.Client

	// Getenv reads the environment; nil means os.Getenv. A test sets it rather
	// than the process environment.
	Getenv func(string) string

	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (o *Options) getenv(name string) string {
	if o.Getenv != nil {
		return o.Getenv(name)
	}
	return os.Getenv(name)
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *Options) httpClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// fetcher produces fresh credentials from one source.
type fetcher func(ctx context.Context) (aws.Credentials, error)

// New resolves the source and returns credentials that refresh themselves.
//
// Nothing is fetched here: the configuration of the source is checked, so
// that a source that cannot work is a startup error, and the first fetch
// happens at the first Retrieve. A caller that wants to fail at startup when
// the source does -- the gateway does -- retrieves once.
func New(opts Options) (*Credentials, error) {
	if opts.Source != SourceStatic && (opts.AccessKeyID != "" || opts.SecretAccessKey != "" || opts.SessionToken != "") {
		return nil, fmt.Errorf("awscreds: keys are configured and so is credential source %q; "+
			"use one or the other", opts.Source)
	}
	source := opts.Source
	if source == SourceChain {
		chosen, err := chooseFromChain(&opts)
		if err != nil {
			return nil, err
		}
		source = chosen
	}

	var (
		fetch    fetcher
		describe string
		err      error
	)
	switch source {
	case SourceStatic:
		fetch, describe, err = staticFetcher(opts.AccessKeyID, opts.SecretAccessKey, opts.SessionToken,
			"the configuration")
	case SourceEnv:
		fetch, describe, err = envFetcher(&opts)
	case SourceProfile:
		fetch, describe, err = profileFetcher(&opts)
	case SourceWebIdentity:
		fetch, describe, err = webIdentityFetcher(&opts)
	case SourceContainer:
		fetch, describe, err = containerFetcher(&opts)
	case SourceIMDS:
		fetch, describe, err = imdsFetcher(&opts)
	default:
		return nil, fmt.Errorf("awscreds: unknown credential source %q (want one of %v)",
			opts.Source, Sources)
	}
	if err != nil {
		return nil, err
	}
	if opts.Source == SourceChain {
		describe += ", chosen by the chain"
	}
	return &Credentials{fetch: fetch, describe: describe, now: opts.now}, nil
}

// Credentials are AWS credentials from one source, cached and refreshed
// before they expire. It implements aws.CredentialsProvider.
//
// The refresh policy, from ADR-024: credentials that can expire are refreshed
// in the last five minutes of their lifetime, a little earlier at random so
// that instances started together do not ask together. If the refresh fails,
// the credentials still held are served for as long as they are actually
// valid, and the refresh is tried again after a pause. Only credentials that
// have expired are an error -- a key service having a bad minute must not
// fail requests whose credentials are good for four more.
type Credentials struct {
	fetch    fetcher
	describe string
	now      func() time.Time

	mu        sync.Mutex
	held      aws.Credentials
	have      bool
	refreshAt time.Time
	lastErr   error

	// refreshing admits one refresh at a time. A caller that finds it taken
	// and holds valid credentials returns them instead of waiting.
	refreshing sync.Mutex
}

// expiryWindow is how early credentials are refreshed, at most.
const expiryWindow = 5 * time.Minute

// retryPause is how long a failed refresh waits before the next attempt,
// while the credentials held are still valid.
const retryPause = 30 * time.Second

// Source describes where the credentials come from, for logs: never a secret.
func (c *Credentials) Source() string { return c.describe }

// Retrieve returns valid credentials, refreshing them when they are due.
func (c *Credentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if creds, ok := c.current(); ok {
		return creds, nil
	}
	if !c.refreshing.TryLock() {
		// Somebody is refreshing. Credentials that are still valid do for
		// this request; without them, wait for the refresh.
		if creds, ok := c.valid(); ok {
			return creds, nil
		}
		c.refreshing.Lock()
	}
	defer c.refreshing.Unlock()

	// A refresh that finished while this caller waited is as good as one of
	// its own.
	if creds, ok := c.current(); ok {
		return creds, nil
	}

	fresh, err := c.fetch(ctx)
	if err == nil {
		err = checkFetched(fresh)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if err != nil {
		c.lastErr = err
		if c.have && (!c.held.CanExpire || now.Before(c.held.Expires)) {
			// Never past expiry: the pause must not outlive the credentials.
			c.refreshAt = now.Add(retryPause)
			if c.held.CanExpire && c.refreshAt.After(c.held.Expires) {
				c.refreshAt = c.held.Expires
			}
			return c.held, nil
		}
		return aws.Credentials{}, fmt.Errorf("awscreds: %s: %w", c.describe, err)
	}
	c.held, c.have, c.lastErr = fresh, true, nil
	c.refreshAt = refreshTime(now, fresh)
	return fresh, nil
}

// LastError is the error of the most recent failed refresh while valid
// credentials were still being served, or nil.
func (c *Credentials) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// current returns the credentials held if they are not yet due a refresh.
func (c *Credentials) current() (aws.Credentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.have {
		return aws.Credentials{}, false
	}
	if !c.held.CanExpire {
		return c.held, true
	}
	return c.held, c.now().Before(c.refreshAt)
}

// valid returns the credentials held if they have not expired, due or not.
func (c *Credentials) valid() (aws.Credentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.have {
		return aws.Credentials{}, false
	}
	return c.held, !c.held.CanExpire || c.now().Before(c.held.Expires)
}

// refreshTime is when credentials fetched at now become due: five minutes
// before they expire, or halfway through a lifetime shorter than ten, less a
// random part of a minute.
func refreshTime(now time.Time, creds aws.Credentials) time.Time {
	if !creds.CanExpire {
		return time.Time{}
	}
	lifetime := creds.Expires.Sub(now)
	window := expiryWindow
	if lifetime < 2*expiryWindow {
		window = lifetime / 2
	}
	//nolint:gosec // spreading refreshes across instances, not a secret.
	jitter := time.Duration(rand.Int64N(int64(time.Minute)))
	if jitter > window/2 {
		jitter = window / 2
	}
	return creds.Expires.Add(-window - jitter)
}

// errIncomplete reports credentials a source returned without a key or secret.
var errIncomplete = errors.New("the source returned credentials without a key id or secret")

func checkFetched(creds aws.Credentials) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errIncomplete
	}
	return nil
}

// staticFetcher serves fixed keys, which never expire on their own account.
func staticFetcher(id, secret, token, where string) (fetcher, string, error) {
	if id == "" || secret == "" {
		return nil, "", fmt.Errorf("awscreds: static credentials from %s need both an access key id "+
			"and a secret access key", where)
	}
	creds := aws.Credentials{
		AccessKeyID: id, SecretAccessKey: secret, SessionToken: token, Source: "static",
	}
	return func(context.Context) (aws.Credentials, error) { return creds, nil },
		"static keys from " + where + " (" + id + ")", nil
}

// envFetcher reads the standard variables, once: a process's environment does
// not change under it.
func envFetcher(opts *Options) (fetcher, string, error) {
	id := firstOf(opts, "AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY")
	secret := firstOf(opts, "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY")
	return staticFetcher(id, secret, opts.getenv("AWS_SESSION_TOKEN"), "the environment")
}

func firstOf(opts *Options, names ...string) string {
	for _, name := range names {
		if v := opts.getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// chooseFromChain picks the first source whose configuration is present, in
// the SDK's order. It looks only at configuration, never at whether a source
// answers: the source it picks is the source, and a failure of it is an error
// rather than a reason to try the next -- which on EKS would be the node's
// own role standing in for a pod's broken IRSA setup.
func chooseFromChain(opts *Options) (string, error) {
	switch {
	case opts.getenv("AWS_PROFILE") != "":
		return SourceProfile, nil
	case firstOf(opts, "AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY") != "":
		return SourceEnv, nil
	case opts.getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "":
		return SourceWebIdentity, nil
	case defaultProfilePresent(opts):
		return SourceProfile, nil
	case opts.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" ||
		opts.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "":
		return SourceContainer, nil
	case imdsDisabled(opts):
		return "", errors.New("awscreds: the chain found no configured source, and IMDS is " +
			"disabled by AWS_EC2_METADATA_DISABLED")
	default:
		return SourceIMDS, nil
	}
}
