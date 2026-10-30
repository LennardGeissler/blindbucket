package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/auth"
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
// 503, for reads, listings and deletes as much as for writes: neither falls
// back to the default tenant's keys (ADR-038).
func TestIntegrationRequestsToAnUnservedTenantAreRefused(t *testing.T) {
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
			key := proxytest.TestKey(t, "refused.bin")
			put := c.h.Put(t, key, []byte("x"), nil)
			defer func() { _ = put.Body.Close() }()
			check(t, "PUT", put, c.status, c.code)
			for _, method := range []string{http.MethodGet, http.MethodDelete} {
				resp := c.h.Do(t, method, key)
				defer func() { _ = resp.Body.Close() }()
				check(t, method, resp, c.status, c.code)
			}
			list, err := c.h.Client.Get(c.h.Server.URL + "/" + proxytest.Bucket + "?list-type=2")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = list.Body.Close() }()
			check(t, "a listing", list, c.status, c.code)
		})
	}
}

// A copy reads its source, so a destroyed tenant's bucket is no source for a
// bucket that is served.
func TestIntegrationCopiesFromAnUnservedTenantAreRefused(t *testing.T) {
	tn := proxytest.NewTenancyFor(t, "gone-bucket")
	h := proxytest.New(t, proxytest.WithKeys(tn.Destroyed), func(c *auth.Config) {
		c.Clients[0].Buckets = []string{auth.AllBuckets}
	})
	copyFrom := func(target string) *http.Response {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = 0
		req.Header.Set("X-Amz-Copy-Source", "/gone-bucket/anything")
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	key := proxytest.TestKey(t, "copy.bin")
	whole := copyFrom(h.URL(key))
	defer func() { _ = whole.Body.Close() }()
	check(t, "CopyObject", whole, http.StatusForbidden, "AccessDenied")

	token := h.MpuStart(t, key, nil)
	part := copyFrom(fmt.Sprintf("%s?partNumber=1&uploadId=%s", h.URL(key), proxytest.URLQueryEscape(token)))
	defer func() { _ = part.Body.Close() }()
	check(t, "UploadPartCopy", part, http.StatusForbidden, "AccessDenied")
}

// check requires a refusal with status and code.
func check(t *testing.T, what string, resp *http.Response, status int, code string) {
	t.Helper()
	body := proxytest.ReadBody(t, resp)
	if resp.StatusCode != status || !strings.Contains(body, code) {
		t.Errorf("%s answered %d: %s; want %d %s", what, resp.StatusCode, body, status, code)
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
