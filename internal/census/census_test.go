package census_test

import (
	"slices"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/census"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
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
