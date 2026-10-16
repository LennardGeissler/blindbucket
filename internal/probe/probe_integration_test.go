package probe

import (
	"net/url"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The probe against a real provider, compared with what the provider is stated
// to do. The statement is the point: MinIO enforces all three conditions, Garage
// v2.4.1 ignores both on the completion, and a provider that changes either way
// should fail here rather than be noticed by a rotation or a migration.
//
//	docker compose up -d
//	BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/probe
func TestIntegrationConditionalWrites(t *testing.T) {
	p := testprovider.Require(t)
	client, err := upstream.New(upstream.Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey, SessionToken: p.SessionToken,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}

	got, err := ConditionalWrites(t.Context(), client, p.Bucket)
	if err != nil {
		t.Fatalf("ConditionalWrites: %v", err)
	}
	for _, c := range []struct {
		check Check
		want  string
		env   string
	}{
		{got.CopySourceIfMatch, p.CopySourceIfMatch, testprovider.CopySourceIfMatchEnv},
		{got.CompleteIfMatch, p.CompleteIfMatch, testprovider.CompleteIfMatchEnv},
		{got.CompleteIfNoneMatch, p.CompleteIfNoneMatch, testprovider.CompleteIfNoneMatchEnv},
	} {
		if c.check.Outcome.String() != c.want {
			t.Errorf("%s: %s (%s), but %s says %s",
				c.check.Name, c.check.Outcome, c.check.Detail, c.env, c.want)
		}
	}
	if got.SafeForRotation() != p.Guarded() {
		t.Errorf("SafeForRotation() = %v with %+v", got.SafeForRotation(), got)
	}
	if got.SafeForMigration() != p.MigrationGuarded() {
		t.Errorf("SafeForMigration() = %v with %+v", got.SafeForMigration(), got)
	}

	// Nothing left behind: no object, and no open upload. Under its own key,
	// not all of Prefix: doctor's tests probe the same bucket from another
	// package, and `go test ./...` runs packages at the same time.
	if !strings.HasPrefix(got.Key, Prefix) {
		t.Fatalf("the probe wrote %q, which is not under %s", got.Key, Prefix)
	}
	page, err := client.ListObjects(t.Context(), p.Bucket,
		url.Values{"list-type": {"2"}, "prefix": {got.Key}})
	if err != nil {
		t.Fatalf("listing %s: %v", got.Key, err)
	}
	if len(page.Contents) != 0 {
		t.Errorf("the probe left its object %s behind", got.Key)
	}
	uploads, err := client.ListMultipartUploads(t.Context(), p.Bucket, got.Key)
	if err != nil {
		t.Fatalf("listing uploads under %s: %v", got.Key, err)
	}
	if len(uploads) != 0 {
		t.Errorf("the probe left %d uploads open on %s", len(uploads), got.Key)
	}
}
