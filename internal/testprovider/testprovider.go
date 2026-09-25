// Package testprovider says which S3 provider the integration tests run
// against.
//
// It lives on its own because two packages run integration tests, and a
// provider described in two places is a provider that will one day be
// described differently in each: the upstream tests read the region and the
// credentials from the environment long before the proxy tests did. Everything
// here defaults to the MinIO the compose file starts, so the only variable a
// local run needs is the endpoint.
//
// It deliberately does not import internal/upstream, whose own tests use it.
package testprovider

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The environment variables, all optional except EndpointEnv.
const (
	EndpointEnv  = "BLINDBUCKET_TEST_S3_ENDPOINT"
	RegionEnv    = "BLINDBUCKET_TEST_S3_REGION"
	AccessKeyEnv = "BLINDBUCKET_TEST_S3_ACCESS_KEY"
	SecretKeyEnv = "BLINDBUCKET_TEST_S3_SECRET_KEY"
	BucketEnv    = "BLINDBUCKET_TEST_S3_BUCKET"
	PathStyleEnv = "BLINDBUCKET_TEST_S3_PATH_STYLE"

	// What the provider is expected to do with the two conditional writes
	// rotation relies on: "enforced", "ignored" or "refused", as internal/probe
	// names them. They are stated rather than measured, so that a provider
	// changing its behaviour fails a test instead of quietly changing which
	// tests run.
	CopySourceIfMatchEnv = "BLINDBUCKET_TEST_S3_COPY_SOURCE_IF_MATCH"
	CompleteIfMatchEnv   = "BLINDBUCKET_TEST_S3_COMPLETE_IF_MATCH"

	// KeepEnv, set to anything, leaves a run's objects in the bucket instead of
	// sweeping them, for looking at what a failing test wrote.
	KeepEnv = "BLINDBUCKET_TEST_S3_KEEP"
)

// RunRoot is the common prefix of every run's objects. A bucket that the tests
// share with nothing else can carry a lifecycle rule on it, which catches
// whatever a crashed run could not sweep.
const RunRoot = "bbtest/"

var runPrefix = sync.OnceValue(func() string {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	return RunRoot + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(suffix) + "/"
})

// RunPrefix is where this test process keeps its objects: one prefix per
// process, so that two runs against the same bucket -- two CI jobs, say -- never
// touch each other's objects, and a run can be swept as a whole when it ends.
func RunPrefix() string { return runPrefix() }

// Keep reports whether the run's objects should be left in place.
func Keep() bool { return os.Getenv(KeepEnv) != "" }

// Provider is the upstream the tests write to. The bucket must already exist:
// creating one is a decision about cost and region that a test should not make
// on a real account.
type Provider struct {
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
	Bucket    string
	PathStyle bool

	// CopySourceIfMatch and CompleteIfMatch are the expected outcomes, both
	// "enforced" unless stated otherwise -- which is what MinIO does.
	CopySourceIfMatch string
	CompleteIfMatch   string
}

// Guarded reports whether the provider is expected to enforce both conditional
// writes, which is what a rotation without --allow-unconditional needs.
func (p Provider) Guarded() bool {
	return p.CopySourceIfMatch == "enforced" && p.CompleteIfMatch == "enforced"
}

// Bucket is the bucket the tests use, and is read without a provider being
// configured, because test code names it in places that run before any
// provider is needed.
func Bucket() string { return envOr(BucketEnv, "blindbucket-test") }

// Require returns the configured provider, or skips the test when there is
// none, so that `go test ./...` stays runnable without Docker.
func Require(t testing.TB) Provider {
	t.Helper()
	p, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoint == "" {
		t.Skipf("set %s to run these against a real provider (docker compose up -d)", EndpointEnv)
	}
	return p
}

// FromEnv returns the configured provider without skipping, for code outside a
// test -- a TestMain -- that has no test to skip. Its Endpoint is empty when no
// provider is configured.
func FromEnv() (Provider, error) {
	for _, name := range []string{CopySourceIfMatchEnv, CompleteIfMatchEnv} {
		switch v := os.Getenv(name); v {
		case "", "enforced", "ignored", "refused":
		default:
			return Provider{}, fmt.Errorf("%s=%q: want enforced, ignored or refused", name, v)
		}
	}
	pathStyle := true
	if v := os.Getenv(PathStyleEnv); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return Provider{}, fmt.Errorf("%s=%q: %w", PathStyleEnv, v, err)
		}
		pathStyle = parsed
	}
	return Provider{
		Endpoint:  os.Getenv(EndpointEnv),
		Region:    envOr(RegionEnv, "us-east-1"),
		AccessKey: envOr(AccessKeyEnv, "minioadmin"),
		SecretKey: envOr(SecretKeyEnv, "minioadmin"),
		Bucket:    Bucket(),
		PathStyle: pathStyle,

		CopySourceIfMatch: envOr(CopySourceIfMatchEnv, "enforced"),
		CompleteIfMatch:   envOr(CompleteIfMatchEnv, "enforced"),
	}, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
