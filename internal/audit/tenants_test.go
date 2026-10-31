package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeTenants is acme owning acme-*, globex destroyed owning globex-*, and the
// deployment owning every other bucket.
type fakeTenants struct {
	mu    sync.Mutex
	asked map[string]int
}

var acmeAuditKey = bytes.Repeat([]byte{0xac}, 32)

func (f *fakeTenants) AuditTenant(bucket string) (string, bool) {
	switch {
	case strings.HasPrefix(bucket, "acme-"):
		return "acme", true
	case strings.HasPrefix(bucket, "globex-"):
		return "globex", false
	}
	return "", true
}

func (f *fakeTenants) AuditNameKey(tenant string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[tenant]++
	return bytes.Clone(acmeAuditKey), nil
}

// An entry about a tenant's bucket is readable with the tenant's key and with
// no other; one about a bucket whose tenant's key is not held records digests;
// and the chain verifies without any key either way.
func TestNamesPerTenant(t *testing.T) {
	key := testKey(t, 7)
	tenants := &fakeTenants{asked: map[string]int{}}
	cfg := testConfig(t, key, filepath.Join(t.TempDir(), "audit.log"))
	cfg.Tenants = tenants
	w, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []Event{
		event("PutObject", "photos", "beach.jpg"),
		event("PutObject", "acme-data", "q3/report.pdf"),
		event("GetObject", "acme-data", "q3/report.pdf"),
		event("GetObject", "globex-data", "secret-plan.txt"),
		event("ListBuckets", "", ""),
	} {
		if err := w.Append(ev); err != nil {
			t.Fatalf("Append %s %s: %v", ev.Op, ev.Bucket, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if tenants.asked["acme"] != 1 || len(tenants.asked) != 1 {
		t.Errorf("tenant keys asked for: %v, want acme's once", tenants.asked)
	}

	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"acme-data", "report", "globex", "secret-plan", "photos"} {
		if bytes.Contains(data, []byte(plain)) {
			t.Errorf("the log holds %q in clear", plain)
		}
	}
	var entries []Entry
	if _, err := Verify(bytes.NewReader(data), VerifyOptions{
		PublicKey: testPublic(t, key),
		OnEntry:   func(e *Entry) error { entries = append(entries, *e); return nil },
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("%d entries", len(entries))
	}

	deployment, err := newNameCoder(cfg.NameKey)
	if err != nil {
		t.Fatal(err)
	}
	acme, err := newNameCoder(acmeAuditKey)
	if err != nil {
		t.Fatal(err)
	}
	decodes := func(c *nameCoder, e Entry, bucket, key string) bool {
		b, okB := c.decode(e.Bucket)
		k, okK := c.decode(e.Key)
		return okB && okK && b == bucket && k == key
	}

	if !decodes(deployment, entries[0], "photos", "beach.jpg") {
		t.Error("the deployment's entry does not decode with the deployment's key")
	}
	for _, e := range entries[1:3] {
		if !decodes(acme, e, "acme-data", "q3/report.pdf") {
			t.Errorf("acme's entry %d does not decode with acme's key", e.Seq)
		}
		if _, ok := deployment.decode(e.Bucket); ok {
			t.Errorf("acme's entry %d decodes with the deployment's key", e.Seq)
		}
	}
	if entries[1].Key != entries[2].Key {
		t.Error("one name of acme's is recorded two ways")
	}

	globex := entries[3]
	if globex.Bucket != deployment.digest("globex-data") || globex.Key != deployment.digest("secret-plan.txt") {
		t.Errorf("a destroyed tenant's entry is not recorded as digests: %q %q", globex.Bucket, globex.Key)
	}
	if entries[4].Bucket != "" || entries[4].Key != "" {
		t.Errorf("an entry about no bucket: %q %q", entries[4].Bucket, entries[4].Key)
	}
}
