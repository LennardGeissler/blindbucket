package probe

import (
	"net/url"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The probe against a real provider, compared with what the provider is stated
// to do. The statement is the point: MinIO enforces both conditions, Garage
// v2.4.1 ignores the second, and a provider that changes either way should fail
// here rather than be noticed by a rotation.
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
	} {
		if c.check.Outcome.String() != c.want {
			t.Errorf("%s: %s (%s), but %s says %s",
				c.check.Name, c.check.Outcome, c.check.Detail, c.env, c.want)
		}
	}
	if got.Safe() != p.Guarded() {
		t.Errorf("Safe() = %v with %+v", got.Safe(), got)
	}

	// Nothing left behind: no object, and no open upload.
	page, err := client.ListObjects(t.Context(), p.Bucket,
		url.Values{"list-type": {"2"}, "prefix": {Prefix}})
	if err != nil {
		t.Fatalf("listing %s: %v", Prefix, err)
	}
	if len(page.Contents) != 0 {
		t.Errorf("the probe left %d objects under %s", len(page.Contents), Prefix)
	}
	uploads, err := client.ListMultipartUploads(t.Context(), p.Bucket, Prefix)
	if err != nil {
		t.Fatalf("listing uploads under %s: %v", Prefix, err)
	}
	if len(uploads) != 0 {
		t.Errorf("the probe left %d uploads open under %s", len(uploads), Prefix)
	}
}
