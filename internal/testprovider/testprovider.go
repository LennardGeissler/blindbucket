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
	"fmt"
	"os"
	"strconv"
	"testing"
)

// The environment variables, all optional except EndpointEnv.
const (
	EndpointEnv  = "BLINDBUCKET_TEST_S3_ENDPOINT"
	RegionEnv    = "BLINDBUCKET_TEST_S3_REGION"
	AccessKeyEnv = "BLINDBUCKET_TEST_S3_ACCESS_KEY"
	SecretKeyEnv = "BLINDBUCKET_TEST_S3_SECRET_KEY"
	BucketEnv    = "BLINDBUCKET_TEST_S3_BUCKET"
	PathStyleEnv = "BLINDBUCKET_TEST_S3_PATH_STYLE"
)

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
}

// Bucket is the bucket the tests use, and is read without a provider being
// configured, because test code names it in places that run before any
// provider is needed.
func Bucket() string { return envOr(BucketEnv, "blindbucket-test") }

// Require returns the configured provider, or skips the test when there is
// none, so that `go test ./...` stays runnable without Docker.
func Require(t testing.TB) Provider {
	t.Helper()
	p, err := fromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoint == "" {
		t.Skipf("set %s to run these against a real provider (docker compose up -d)", EndpointEnv)
	}
	return p
}

func fromEnv() (Provider, error) {
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
	}, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
