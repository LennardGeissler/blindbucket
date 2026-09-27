package obs

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// metricContract is every metric the gateway exports, with its type and the
// names of its labels. From 1.0 these are a stable interface (ADR-021): an
// alert selects a series by exactly this, so renaming a metric, changing its
// type, or adding a label to it breaks the alert as surely as deleting it.
//
// A new metric belongs here too, and adding it is the moment to decide that it
// will not change either. New label *values* are not in the contract.
var metricContract = map[string]struct {
	kind   dto.MetricType
	labels string
}{
	"blindbucket_build_info":                            {dto.MetricType_GAUGE, "go_version,version"},
	"blindbucket_requests_total":                        {dto.MetricType_COUNTER, "op,status"},
	"blindbucket_request_duration_seconds":              {dto.MetricType_HISTOGRAM, "op"},
	"blindbucket_upstream_duration_seconds":             {dto.MetricType_HISTOGRAM, "op"},
	"blindbucket_bytes_total":                           {dto.MetricType_COUNTER, "direction"},
	"blindbucket_active_streams":                        {dto.MetricType_GAUGE, "direction"},
	"blindbucket_integrity_failures_total":              {dto.MetricType_COUNTER, "kind"},
	"blindbucket_auth_failures_total":                   {dto.MetricType_COUNTER, "reason"},
	"blindbucket_checksum_mismatches_total":             {dto.MetricType_COUNTER, "algorithm"},
	"blindbucket_audit_failures_total":                  {dto.MetricType_COUNTER, ""},
	"blindbucket_audit_broken":                          {dto.MetricType_GAUGE, ""},
	"blindbucket_keyring_keys":                          {dto.MetricType_GAUGE, ""},
	"blindbucket_keyring_key_created_timestamp_seconds": {dto.MetricType_GAUGE, "active,kid"},
}

type contractRing struct{}

func (contractRing) KIDs() []string    { return []string{"2026-09"} }
func (contractRing) ActiveKID() string { return "2026-09" }
func (contractRing) Created(string) (time.Time, bool) {
	return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), true
}

// TestMetricsAreAContract gathers what the gateway actually exports and holds
// it against metricContract, in both directions: nothing missing, nothing
// changed, and nothing new that has not been written down.
func TestMetricsAreAContract(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := NewMetrics(registry, MetricsConfig{Version: "1.0.0"})

	// A vector exports nothing until it has a series, so every one is given
	// one here; a metric this misses would show up as missing, not pass.
	m.Request("GetObject", 200, time.Millisecond)
	m.Upstream("HeadObject", time.Millisecond)
	m.Bytes(InPlain, 1)
	m.StreamStarted(Upload)
	m.IntegrityFailure(KindChunk)
	m.AuthFailure("SignatureDoesNotMatch")
	m.ChecksumMismatch("CRC32")
	m.AuditFailure()
	m.KeyringLoaded(contractRing{})

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	seen := map[string]bool{}
	for _, family := range families {
		name := family.GetName()
		seen[name] = true
		want, ok := metricContract[name]
		if !ok {
			t.Errorf("%s is exported but not in the contract; adding it there is "+
				"deciding it stays (ADR-021)", name)
			continue
		}
		if family.GetType() != want.kind {
			t.Errorf("%s is a %v, the contract says %v", name, family.GetType(), want.kind)
		}
		for _, metric := range family.GetMetric() {
			var labels []string
			for _, pair := range metric.GetLabel() {
				labels = append(labels, pair.GetName())
			}
			sort.Strings(labels)
			if got := strings.Join(labels, ","); got != want.labels {
				t.Errorf("%s has labels %q, the contract says %q", name, got, want.labels)
			}
		}
	}
	for name := range metricContract {
		if !seen[name] {
			t.Errorf("%s is in the contract but no longer exported", name)
		}
	}
}
