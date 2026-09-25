// Package sweep removes what an integration test run left in the provider's
// bucket.
//
// Against MinIO in a container that is housekeeping. Against a real provider it
// is cost: an incomplete multipart upload is billed for every part it holds
// until it is aborted, and the tests that check what the gateway refuses leave
// exactly those behind. So does every multipart object deleted behind the
// gateway's back, as an orphaned manifest under .blindbucket/m/ -- which is
// not under the run's prefix at all, because a manifest's path is a hash of the
// key it belongs to.
//
// It lives apart from internal/testprovider because it needs internal/upstream,
// whose own tests import testprovider.
package sweep

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/gc"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Result reports what a sweep removed.
type Result struct {
	UploadsAborted int
	ObjectsDeleted int
	// ManifestsDeleted is what gc collected for keys under the prefix.
	ManifestsDeleted int
}

// openUploads lists the uploads open under prefix.
//
// The listing is asked for the whole bucket and filtered here, because MinIO
// only honours a ListMultipartUploads prefix that is a complete object key: a
// real prefix answers with no uploads at all, measured against
// RELEASE.2026-09-22. That does not affect gc, which always asks about one
// exact key, but a sweep that trusted the prefix would abort nothing.
func openUploads(ctx context.Context, client *upstream.Client, bucket, prefix string) ([]upstream.MultipartUpload, error) {
	all, err := client.ListMultipartUploads(ctx, bucket, "")
	if err != nil {
		return nil, fmt.Errorf("sweep: listing uploads: %w", err)
	}
	var out []upstream.MultipartUpload
	for _, u := range all {
		if strings.HasPrefix(u.Key, prefix) {
			out = append(out, u)
		}
	}
	return out, nil
}

// Run removes every open upload and every object under prefix, then the
// manifests those objects leave orphaned.
//
// The order is the one gc needs: it passes over any key with an upload in
// flight (rule R4), so the uploads go first, and it keeps the manifest of any
// object still visible, so the objects go second. gc is then asked about this
// prefix only, and without its age guard, which is safe for the reason gc
// gives -- the ordering is what makes a deletion safe, the age is the second
// line behind it -- and because nothing writes under a finished run's prefix.
func Run(ctx context.Context, client *upstream.Client, bucket, prefix string) (Result, error) {
	var out Result
	if prefix == "" {
		// An empty prefix is the whole bucket, which is never what a test
		// run owns.
		return out, errors.New("sweep: refusing to sweep without a prefix")
	}

	uploads, err := openUploads(ctx, client, bucket, prefix)
	if err != nil {
		return out, err
	}
	for _, u := range uploads {
		if err := client.AbortMultipartUpload(ctx, bucket, u.Key, u.UploadID); err != nil {
			return out, fmt.Errorf("sweep: aborting the upload of %s: %w", u.Key, err)
		}
		out.UploadsAborted++
	}

	query := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
	for {
		page, err := client.ListObjects(ctx, bucket, query)
		if err != nil {
			return out, fmt.Errorf("sweep: listing objects: %w", err)
		}
		for _, entry := range page.Contents {
			if err := client.DeleteObject(ctx, bucket, entry.Key); err != nil {
				return out, fmt.Errorf("sweep: deleting %s: %w", entry.Key, err)
			}
			out.ObjectsDeleted++
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		query.Set("continuation-token", page.NextContinuationToken)
	}

	collected, err := gc.Run(ctx, gc.Config{
		Upstream: client, Bucket: bucket, Prefix: prefix, DisableMinAge: true,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return out, fmt.Errorf("sweep: collecting manifests: %w", err)
	}
	out.ManifestsDeleted = collected.Deleted
	return out, nil
}
