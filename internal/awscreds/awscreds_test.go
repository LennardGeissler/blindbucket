package awscreds

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// envOf turns a map into the Getenv an Options takes, so that no test touches
// the process environment.
func envOf(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

// clock is a settable clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var epoch = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// scripted is a source whose answers a test decides.
type scripted struct {
	calls atomic.Int64
	next  func(n int64) (aws.Credentials, error)
}

func (s *scripted) fetch(context.Context) (aws.Credentials, error) {
	return s.next(s.calls.Add(1))
}

func expiring(at time.Time, id string) aws.Credentials {
	return aws.Credentials{AccessKeyID: id, SecretAccessKey: "s", CanExpire: true, Expires: at}
}

func cached(c *clock, s *scripted) *Credentials {
	return &Credentials{fetch: s.fetch, describe: "scripted", now: c.Now}
}

func TestStaticCredentialsAreFetchedOnce(t *testing.T) {
	creds, err := New(Options{Source: SourceStatic, AccessKeyID: "AKID", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for range 3 {
		got, err := creds.Retrieve(t.Context())
		if err != nil || got.AccessKeyID != "AKID" || got.CanExpire {
			t.Fatalf("Retrieve: %+v, %v", got, err)
		}
	}
	if !strings.Contains(creds.Source(), "AKID") || strings.Contains(creds.Source(), "secret") {
		t.Errorf("Source() = %q: it should name the key id and never the secret", creds.Source())
	}
}

// TestRefreshesBeforeExpiry: credentials good for an hour are used as they are
// for most of it, and refreshed in the last five minutes, not after.
func TestRefreshesBeforeExpiry(t *testing.T) {
	c := &clock{now: epoch}
	s := &scripted{next: func(n int64) (aws.Credentials, error) {
		return expiring(c.Now().Add(time.Hour), "gen"+string(rune('0'+n))), nil
	}}
	creds := cached(c, s)

	if _, err := creds.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}
	c.advance(50 * time.Minute)
	if _, err := creds.Retrieve(t.Context()); err != nil || s.calls.Load() != 1 {
		t.Fatalf("refreshed with ten minutes left (%d fetches, %v)", s.calls.Load(), err)
	}
	c.advance(6 * time.Minute) // four minutes left
	got, err := creds.Retrieve(t.Context())
	if err != nil || s.calls.Load() != 2 || got.AccessKeyID != "gen2" {
		t.Fatalf("not refreshed with four minutes left: %+v, %d fetches, %v", got, s.calls.Load(), err)
	}
}

// TestServesValidCredentialsWhileRefreshFails is the decision the cache is
// written for: a failing refresh does not fail requests whose credentials are
// still good, retries after a pause rather than on every request, and becomes
// an error only once they have expired.
func TestServesValidCredentialsWhileRefreshFails(t *testing.T) {
	c := &clock{now: epoch}
	outage := errors.New("STS is having a bad minute")
	s := &scripted{next: func(n int64) (aws.Credentials, error) {
		if n == 1 {
			return expiring(epoch.Add(time.Hour), "first"), nil
		}
		return aws.Credentials{}, outage
	}}
	creds := cached(c, s)
	if _, err := creds.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}

	c.advance(57 * time.Minute) // due, three minutes left
	got, err := creds.Retrieve(t.Context())
	if err != nil || got.AccessKeyID != "first" {
		t.Fatalf("a failed refresh failed a request with valid credentials: %+v, %v", got, err)
	}
	if !errors.Is(creds.LastError(), outage) {
		t.Errorf("LastError() = %v", creds.LastError())
	}
	attempts := s.calls.Load()
	c.advance(10 * time.Second)
	if _, err := creds.Retrieve(t.Context()); err != nil || s.calls.Load() != attempts {
		t.Errorf("retried within the pause: %d attempts, %v", s.calls.Load(), err)
	}
	c.advance(30 * time.Second)
	if _, err := creds.Retrieve(t.Context()); err != nil || s.calls.Load() != attempts+1 {
		t.Errorf("did not retry after the pause: %d attempts, %v", s.calls.Load(), err)
	}

	c.advance(3 * time.Minute) // expired
	if _, err := creds.Retrieve(t.Context()); !errors.Is(err, outage) {
		t.Fatalf("expired credentials were served: %v", err)
	}
}

// TestRetryPauseNeverOutlivesTheCredentials: a refresh that fails seconds
// before expiry does not schedule its retry past it, which would serve
// expired credentials in between.
func TestRetryPauseNeverOutlivesTheCredentials(t *testing.T) {
	c := &clock{now: epoch}
	s := &scripted{next: func(n int64) (aws.Credentials, error) {
		if n == 1 {
			return expiring(epoch.Add(time.Hour), "first"), nil
		}
		return aws.Credentials{}, errors.New("down")
	}}
	creds := cached(c, s)
	if _, err := creds.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Hour - 10*time.Second)
	if _, err := creds.Retrieve(t.Context()); err != nil {
		t.Fatalf("ten seconds before expiry: %v", err)
	}
	c.advance(11 * time.Second)
	if got, err := creds.Retrieve(t.Context()); err == nil {
		t.Fatalf("served credentials a second after they expired: %+v", got)
	}
}

func TestShortLivedCredentialsRefreshHalfway(t *testing.T) {
	now := epoch
	at := refreshTime(now, expiring(now.Add(4*time.Minute), "x"))
	if at.Before(now) || at.After(now.Add(2*time.Minute)) {
		t.Errorf("credentials good for four minutes are refreshed at +%s", at.Sub(now))
	}
}

func TestConcurrentRetrievesFetchOnce(t *testing.T) {
	c := &clock{now: epoch}
	release := make(chan struct{})
	s := &scripted{next: func(int64) (aws.Credentials, error) {
		<-release
		return expiring(epoch.Add(time.Hour), "once"), nil
	}}
	creds := cached(c, s)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := creds.Retrieve(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := s.calls.Load(); n != 1 {
		t.Errorf("%d fetches for sixteen concurrent first requests", n)
	}
}

func TestIncompleteCredentialsAreAnError(t *testing.T) {
	c := &clock{now: epoch}
	s := &scripted{next: func(int64) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKID"}, nil
	}}
	if _, err := cached(c, s).Retrieve(t.Context()); !errors.Is(err, errIncomplete) {
		t.Errorf("got %v", err)
	}
}

func TestConfigurationMistakes(t *testing.T) {
	for name, opts := range map[string]Options{
		"keys and a source": {Source: SourceEnv, AccessKeyID: "AKID", SecretAccessKey: "s",
			Getenv: envOf(nil)},
		"an unknown source":     {Source: "sso", Getenv: envOf(nil)},
		"static without secret": {Source: SourceStatic, AccessKeyID: "AKID"},
		"env without variables": {Source: SourceEnv, Getenv: envOf(nil)},
		"web identity without a token file": {Source: SourceWebIdentity,
			Getenv: envOf(map[string]string{"AWS_ROLE_ARN": "arn:aws:iam::1:role/r"})},
		"web identity without a role": {Source: SourceWebIdentity,
			Getenv: envOf(map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/t"})},
		"container without a URI": {Source: SourceContainer, Getenv: envOf(nil)},
		"imds disabled": {Source: SourceIMDS,
			Getenv: envOf(map[string]string{"AWS_EC2_METADATA_DISABLED": "true"})},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(opts); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestEnvironmentSource(t *testing.T) {
	creds, err := New(Options{Source: SourceEnv, Getenv: envOf(map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDENV", "AWS_SECRET_ACCESS_KEY": "s", "AWS_SESSION_TOKEN": "tok",
	})})
	if err != nil {
		t.Fatal(err)
	}
	got, err := creds.Retrieve(t.Context())
	if err != nil || got.AccessKeyID != "AKIDENV" || got.SessionToken != "tok" {
		t.Errorf("got %+v, %v", got, err)
	}
}

// TestChainSelectsByConfigurationAlone: which source the chain picks follows
// from configuration, in the SDKs' order, and nothing is asked over the
// network to decide.
func TestChainSelectsByConfigurationAlone(t *testing.T) {
	home := t.TempDir()
	withDefault := t.TempDir()
	writeFile(t, withDefault+"/.aws/credentials", "[default]\naws_access_key_id = AKID\naws_secret_access_key = s\n")

	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"AWS_PROFILE wins over keys": {map[string]string{"AWS_PROFILE": "dev",
			"AWS_ACCESS_KEY_ID": "AKID", "HOME": home}, SourceProfile},
		"keys in the environment": {map[string]string{"AWS_ACCESS_KEY_ID": "AKID",
			"AWS_WEB_IDENTITY_TOKEN_FILE": "/t", "HOME": home}, SourceEnv},
		"IRSA": {map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/t",
			"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
			"HOME":                               withDefault}, SourceWebIdentity},
		"a default profile": {map[string]string{"HOME": withDefault,
			"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x"}, SourceProfile},
		"Pod Identity": {map[string]string{"HOME": home,
			"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials"}, SourceContainer},
		"nothing configured": {map[string]string{"HOME": home}, SourceIMDS},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := chooseFromChain(&Options{Getenv: envOf(tc.env)})
			if err != nil || got != tc.want {
				t.Errorf("chose %q (%v), want %q", got, err, tc.want)
			}
		})
	}

	if _, err := chooseFromChain(&Options{Getenv: envOf(map[string]string{
		"HOME": home, "AWS_EC2_METADATA_DISABLED": "true",
	})}); err == nil {
		t.Error("with nothing configured and IMDS disabled, the chain chose something")
	}
}

// TestChainDoesNotFallThrough: once a source is chosen, its failure is the
// answer. The IRSA case: a token file that cannot be read must not lead to
// the instance role.
func TestChainDoesNotFallThrough(t *testing.T) {
	imdsAsked := atomic.Bool{}
	imds := newIMDSStub(t, &imdsAsked)
	creds, err := New(Options{Source: SourceChain, Getenv: envOf(map[string]string{
		"HOME":                              t.TempDir(),
		"AWS_WEB_IDENTITY_TOKEN_FILE":       "/nonexistent/token",
		"AWS_ROLE_ARN":                      "arn:aws:iam::1:role/r",
		"AWS_EC2_METADATA_SERVICE_ENDPOINT": imds.URL,
	})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(creds.Source(), "web identity") {
		t.Fatalf("the chain chose %q", creds.Source())
	}
	if _, err := creds.Retrieve(t.Context()); err == nil {
		t.Fatal("a broken web identity produced credentials")
	}
	if imdsAsked.Load() {
		t.Error("the chain fell through to the instance role")
	}
}
