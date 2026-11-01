package census_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/census"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

func TestMatching(t *testing.T) {
	got := census.Matching([]string{"acme-a", "acme-b", "acmeco", "beta", "acme-"},
		[]string{"acme-", "be"})
	if want := []string{"acme-a", "acme-b", "beta", "acme-"}; !slices.Equal(got, want) {
		t.Errorf("Matching = %v, want %v", got, want)
	}
}

// What the default tenant's key wrote before the tenant was active is off the
// tenant, and named by its key; what the tenant's key wrote is on it.
func TestIntegrationCensus(t *testing.T) {
	tn := proxytest.NewTenancy(t)
	before := proxytest.New(t, proxytest.WithKeys(tn.Inactive))
	after := proxytest.New(t, proxytest.WithKeys(tn.Active))
	prefix := proxytest.TestKey(t, "census") + "/"
	before.Store(t, prefix+"old.bin", proxytest.RandomBytes(t, 1000))
	after.Store(t, prefix+"new.bin", proxytest.RandomBytes(t, 1000))
	after.MpuStore(t, prefix+"multi.bin", [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), []byte("tail")})

	result, err := census.Run(t.Context(), census.Config{
		Upstream: after.Upstream, Entries: []string{proxytest.Bucket, "no-such-bucket-for-the-census"},
		KIDs: []string{proxytest.TenantKID}, Prefix: prefix, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Buckets) != 2 {
		t.Fatalf("%d buckets, want 2", len(result.Buckets))
	}
	for _, b := range result.Buckets {
		switch b.Name {
		case proxytest.Bucket:
			if b.Scanned != 3 || b.OnTenant != 2 || b.OffTenant != 1 || b.OffKIDs[proxytest.DefaultKID] != 1 {
				t.Errorf("%s: %+v; want 3 scanned, 2 on the tenant, 1 off it under the default key", b.Name, b)
			}
		default:
			if !b.Missing {
				t.Errorf("%s does not exist and is not reported missing: %+v", b.Name, b)
			}
		}
	}
	if result.OffTenant() != 1 || result.Failed() != 0 {
		t.Errorf("totals: %d off, %d failed", result.OffTenant(), result.Failed())
	}
}

// versionedBucket creates a bucket of its own with versioning on, removed with
// every version when the test ends. It skips on a provider that does not
// version.
func versionedBucket(t *testing.T, up *upstream.Client) string {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("bb-census-%d", time.Now().UnixNano())
	if _, err := up.Passthrough(ctx, http.MethodPut, name, nil, nil); err != nil {
		t.Skipf("cannot create a bucket here: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if list, err := up.ListObjectVersions(ctx, name, nil); err == nil {
			var specs []upstream.DeleteObjectSpec
			for _, v := range list.Versions {
				specs = append(specs, upstream.DeleteObjectSpec{Key: v.Key, VersionID: v.VersionID})
			}
			for _, m := range list.DeleteMarkers {
				specs = append(specs, upstream.DeleteObjectSpec{Key: m.Key, VersionID: m.VersionID})
			}
			if len(specs) > 0 {
				_, _ = up.DeleteObjects(ctx, name, upstream.DeleteRequest{Quiet: true, Objects: specs})
			}
		}
		_, _ = up.Passthrough(ctx, http.MethodDelete, name, nil, nil)
	})
	body := []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	if _, err := up.Passthrough(ctx, http.MethodPut, name, url.Values{"versioning": {""}}, body); err != nil {
		t.Skipf("the provider does not version: %v", err)
	}
	return name
}

// An earlier version under the default tenant's keys survives its object
// being replaced or deleted, and the census counts it apart from current
// objects, which rotate could move and it cannot.
func TestIntegrationCensusCountsEarlierVersions(t *testing.T) {
	tn := proxytest.NewTenancy(t)
	before := proxytest.New(t, proxytest.WithKeys(tn.Inactive))
	after := proxytest.New(t, proxytest.WithKeys(tn.Active))
	up := after.Upstream
	bucket := versionedBucket(t, up)

	prefix := proxytest.TestKey(t, "versions") + "/"
	before.Store(t, prefix+"old.bin", proxytest.RandomBytes(t, 100))
	after.Store(t, prefix+"new.bin", proxytest.RandomBytes(t, 100))
	// Census reads metadata alone, so a copy of each object's stored form
	// stands in for one written to the versioned bucket through the gateway.
	copyAs := func(src, dst string) {
		t.Helper()
		head, err := up.HeadObject(t.Context(), proxytest.Bucket, src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := up.CopyObject(t.Context(), upstream.CopyObjectInput{
			SourceBucket: proxytest.Bucket, SourceKey: src, Bucket: bucket, Key: dst, Metadata: head.Metadata,
		}); err != nil {
			t.Fatal(err)
		}
	}
	copyAs(prefix+"old.bin", "doc")
	copyAs(prefix+"new.bin", "doc") // replaced: the old version is noncurrent
	copyAs(prefix+"old.bin", "gone")
	if err := up.DeleteObject(t.Context(), bucket, "gone"); err != nil { // a delete marker on top
		t.Fatal(err)
	}

	result, err := census.Run(t.Context(), census.Config{
		Upstream: up, Entries: []string{bucket}, KIDs: []string{proxytest.TenantKID}, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := result.Buckets[0]
	if !b.Versioned || b.Scanned != 3 || b.Noncurrent != 2 || b.OnTenant != 1 || b.OffTenant != 0 ||
		b.NoncurrentOff != 2 || b.NoncurrentKIDs[proxytest.DefaultKID] != 2 {
		t.Errorf("%+v; want 3 versions read, 2 noncurrent, both off the tenant under the default key", b)
	}
	if result.NoncurrentOff() != 2 || result.OffTenant() != 0 {
		t.Errorf("totals: %d current off, %d noncurrent off", result.OffTenant(), result.NoncurrentOff())
	}
}

// A provider that does not list versions keeps none, and the census lists
// its objects instead and says so.
func TestCensusWithoutVersionListing(t *testing.T) {
	var listed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Has("versions"):
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(`<Error><Code>NotImplemented</Code><Message>Unimplemented action: ListObjectVersions</Message></Error>`))
		case r.Method == http.MethodHead:
			w.Header().Set("Content-Length", "3")
		default:
			listed = true
			_, _ = w.Write([]byte(`<ListBucketResult><Name>b</Name><Contents><Key>plain.txt</Key><Size>3</Size></Contents></ListBucketResult>`))
		}
	}))
	defer srv.Close()
	up, err := upstream.New(upstream.Config{
		Endpoint: srv.URL, Region: "us-east-1", PathStyle: true, AccessKeyID: "a", SecretAccessKey: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := census.Run(t.Context(), census.Config{
		Upstream: up, Entries: []string{"bucket"}, KIDs: []string{"acme-1"}, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := result.Buckets[0]
	if !listed || b.Versioned || b.Scanned != 1 || b.Foreign != 1 {
		t.Errorf("listed %v, %+v; want the object listed as one, not versioned", listed, b)
	}
}
