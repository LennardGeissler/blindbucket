package upstream

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// TestMain removes the run's objects and open uploads once the tests are done.
// This package cannot use internal/testprovider/sweep, which imports it, and
// does not need its manifest collection either: nothing here writes one.
func TestMain(m *testing.M) {
	code := m.Run()
	if p, err := testprovider.FromEnv(); err == nil && p.Endpoint != "" && !testprovider.Keep() {
		if err := sweepRun(p); err != nil {
			fmt.Fprintf(os.Stderr, "sweep of %s left objects behind: %v\n", testprovider.RunPrefix(), err)
		}
	}
	os.Exit(code)
}

func sweepRun(p testprovider.Provider) error {
	c, err := New(Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey, SessionToken: p.SessionToken,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	prefix := testprovider.RunPrefix()

	// The whole bucket, filtered here: MinIO answers a prefix that is not a
	// complete key with no uploads (see internal/testprovider/sweep).
	uploads, err := c.ListMultipartUploads(ctx, p.Bucket, "")
	if err != nil {
		return err
	}
	for _, u := range uploads {
		if !strings.HasPrefix(u.Key, prefix) {
			continue
		}
		if err := c.AbortMultipartUpload(ctx, p.Bucket, u.Key, u.UploadID); err != nil {
			return err
		}
	}
	query := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
	for {
		page, err := c.ListObjects(ctx, p.Bucket, query)
		if err != nil {
			return err
		}
		for _, entry := range page.Contents {
			if err := c.DeleteObject(ctx, p.Bucket, entry.Key); err != nil {
				return err
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}
}
