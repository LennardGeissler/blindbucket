package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// Every write to a bucket wraps under its tenant's key once the tenant is
// active, and under the default tenant's before; a read goes by the key the
// object names, so what was written before activation stays readable
// (ADR-038).
func TestIntegrationWritesUseTheBucketsTenantKey(t *testing.T) {
	tn := proxytest.NewTenancy(t)
	before := proxytest.New(t, proxytest.WithKeys(tn.Inactive))
	after := proxytest.New(t, proxytest.WithKeys(tn.Active))

	old := proxytest.TestKey(t, "before.bin")
	before.Store(t, old, []byte("written before acme was active"))
	if kid := storedMeta(t, before, old).KeyID; kid != proxytest.DefaultKID {
		t.Errorf("an inactive tenant's bucket was written under %q, want the default tenant's", kid)
	}

	put := proxytest.TestKey(t, "put.bin")
	after.Store(t, put, []byte("written while acme is active"))
	mpu := proxytest.TestKey(t, "multipart.bin")
	after.MpuStore(t, mpu, [][]byte{proxytest.RandomBytes(t, 5<<20), []byte("tail")})
	copied := proxytest.TestKey(t, "copied.bin")
	copyOK(t, after, old, copied, nil)
	for _, key := range []string{put, mpu, copied} {
		if kid := storedMeta(t, after, key).KeyID; kid != proxytest.TenantKID {
			t.Errorf("%s was written under %q, want acme's key", key, kid)
		}
	}

	if got := getOK(t, after, old); got != "written before acme was active" {
		t.Errorf("an object from before activation reads back as %q", got)
	}
}

// A destroyed tenant's buckets are refused, and an unopened tenant's answer
// 503: neither falls back to the default tenant's keys.
func TestIntegrationWritesToAnUnservedTenantAreRefused(t *testing.T) {
	tn := proxytest.NewTenancy(t)
	for name, c := range map[string]struct {
		h      *proxytest.Harness
		status int
		code   string
	}{
		"destroyed": {proxytest.New(t, proxytest.WithKeys(tn.Destroyed)), http.StatusForbidden, "AccessDenied"},
		"unopened":  {proxytest.New(t, proxytest.WithKeys(tn.Unopened)), http.StatusServiceUnavailable, "ServiceUnavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := c.h.Put(t, proxytest.TestKey(t, "refused.bin"), []byte("x"), nil)
			body := proxytest.ReadBody(t, resp)
			_ = resp.Body.Close()
			if resp.StatusCode != c.status || !strings.Contains(body, c.code) {
				t.Errorf("PUT answered %d: %s; want %d %s", resp.StatusCode, body, c.status, c.code)
			}
		})
	}
}

// With names encrypted, a bucket's names follow its tenant: the default
// tenant's name key until the tenant is active, the tenant's after. The two
// do not see each other's objects; migrate-names moves the first kind across
// (ADR-038).
func TestIntegrationNamesFollowTheBucketsTenant(t *testing.T) {
	tn := proxytest.NewTenancy(t)
	option, defaultNames := proxytest.WithEncryptedNames(t)
	before := proxytest.New(t, option, proxytest.WithKeys(tn.Inactive))
	after := proxytest.New(t, option, proxytest.WithKeys(tn.Active))

	acmeKey, ok := tn.Active.Tenants()[0].Ring.NameKey()
	if !ok {
		t.Fatal("acme has no name key")
	}
	secret := acmeKey.Secret()
	acmeNames, err := names.New(secret)
	clear(secret)
	if err != nil {
		t.Fatal(err)
	}

	key := "tenant-names/" + proxytest.TestKey(t, "doc.txt")
	underDefault, _ := defaultNames.EncryptKey(key)
	underAcme, _ := acmeNames.EncryptKey(key)
	before.CleanupStored(t, underDefault)
	after.CleanupStored(t, underAcme)

	before.Store(t, key, []byte("named under the default tenant's key"))
	if _, err := before.Upstream.HeadObject(t.Context(), proxytest.Bucket, underDefault); err != nil {
		t.Fatalf("before activation the object is not under the default name key: %v", err)
	}
	resp := after.Do(t, http.MethodHead, key)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("after activation a name under the default key is found (%d); it should not be", resp.StatusCode)
	}

	after.Store(t, key, []byte("named under acme's key"))
	if _, err := after.Upstream.HeadObject(t.Context(), proxytest.Bucket, underAcme); err != nil {
		t.Fatalf("after activation the object is not under acme's name key: %v", err)
	}
	if got := getOK(t, after, key); got != "named under acme's key" {
		t.Errorf("read back %q", got)
	}
}
