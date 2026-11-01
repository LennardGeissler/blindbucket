package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/census"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// A tenant under the deployment's lock is created, given buckets and
// activated through the commands, each a generation of its own.
func TestTenantsLifecycle(t *testing.T) {
	path := setupKeyring(t, "2026-09")

	_, stderr, err := runCLI(t, "tenants", "create", "--keyring", path, "--deployment-lock",
		"--kid", "acme-1", "acme", "acme-*")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.Contains(stderr, "not active") || !strings.Contains(stderr, "no lock of its own") {
		t.Errorf("create does not say the tenant is inactive and without a lock of its own:\n%s", stderr)
	}
	acme := openWhole(t, path).Tenant("acme")
	if acme == nil || acme.Ring == nil || acme.ActiveKID != "" || acme.Lock().Source != keys.LockDeployment {
		t.Fatalf("after create: %+v", acme)
	}

	if _, _, err := runCLI(t, "tenants", "assign", "--keyring", path, "acme", "shared-reports"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if _, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "acme"); err != nil {
		t.Fatalf("activate: %v", err)
	}

	f := openWhole(t, path)
	acme = f.Tenant("acme")
	if acme.ActiveKID != "acme-1" || !slices.Equal(acme.Buckets, []string{"acme-*", "shared-reports"}) {
		t.Errorf("after assign and activate: %+v", acme)
	}
	if f.Generation != 3 {
		t.Errorf("generation %d after three changes, want 3", f.Generation)
	}
	if name, _ := f.Directory().Tenant("acme-photos"); name != "acme" {
		t.Errorf("acme-photos is %q's", name)
	}

	stdout, _, err := runCLI(t, "tenants", "list", "--keyring", path, "--json")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var list struct {
		Generation uint64 `json:"generation"`
		Tenants    []struct {
			Name      string   `json:"name"`
			Buckets   []string `json:"buckets"`
			ActiveKID string   `json:"active_kid"`
			Opened    bool     `json:"opened"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		t.Fatalf("list --json: %v\n%s", err, stdout)
	}
	if list.Generation != 3 || len(list.Tenants) != 1 || list.Tenants[0].Name != "acme" ||
		list.Tenants[0].ActiveKID != "acme-1" || !list.Tenants[0].Opened {
		t.Errorf("list --json: %s", stdout)
	}
}

// A tenant with a lock of its own opens with that lock and nothing else, and
// is activated only where it opens.
func TestTenantsWithAPassphraseLock(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	conf := tenantPassphraseConfig(t, "acme", writePassphraseFile(t, "acme's passphrase"))

	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--config", conf, "acme", "acme-*"); err != nil {
		t.Fatalf("create: %v", err)
	}
	acme := openWithTenantPassphrase(t, path, "acme's passphrase").Tenant("acme")
	if acme.Ring == nil || acme.Lock().Source != keys.SourcePassphrase {
		t.Fatalf("acme under its passphrase: %+v", acme)
	}
	if !strings.HasPrefix(acme.KIDs[0], "acme-") {
		t.Errorf("acme's first key is %q, want acme-<year>-<month>", acme.KIDs[0])
	}
	if openWhole(t, path).Tenant("acme").Ring != nil {
		t.Error("acme opens without its passphrase")
	}

	_, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "acme")
	if err == nil || !strings.Contains(err.Error(), "did not open") {
		t.Errorf("activate without acme's lock: %v", err)
	}
	if _, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "--config", conf, "acme"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	// Assigning needs no tenant's lock, only the deployment's.
	if _, _, err := runCLI(t, "tenants", "assign", "--keyring", path, "acme", "acme2-*"); err != nil {
		t.Fatalf("assign without acme's lock: %v", err)
	}
	acme = openWithTenantPassphrase(t, path, "acme's passphrase").Tenant("acme")
	if acme.Ring == nil || acme.ActiveKID == "" || len(acme.Buckets) != 2 {
		t.Errorf("after activate and assign: %+v", acme)
	}

	stdout, stderr, err := runCLI(t, "tenants", "list", "--keyring", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "not opened") || !strings.Contains(stderr, "keys.tenants.acme is not configured") {
		t.Errorf("list without acme's lock:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

func TestTenantsMistakes(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--deployment-lock", "acme", "acme-*"); err != nil {
		t.Fatal(err)
	}
	conf := tenantPassphraseConfig(t, "beta", writePassphraseFile(t, "beta's passphrase"))

	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no lock chosen": {[]string{"create", "beta"}, "--deployment-lock"},
		"a lock and --deployment-lock": {[]string{"create", "--config", conf, "--deployment-lock", "beta"},
			"choose one"},
		"the default tenant": {[]string{"create", "--deployment-lock", "default"}, "default tenant"},
		"a name taken":       {[]string{"create", "--deployment-lock", "acme"}, "exists"},
		"another tenant's bucket": {[]string{"create", "--deployment-lock", "beta", "acme-photos"},
			"overlaps"},
		"an unquoted glob that matched files": {[]string{"assign", "acme", "Notes.txt"}, "bucket name"},
		"buckets for no tenant":               {[]string{"assign", "zeta", "zeta-1"}, "no tenant"},
		"assign without buckets":              {[]string{"assign", "acme"}, "usage"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"tenants", c.args[0], "--keyring", path}, c.args[1:]...)
			_, _, err := runCLI(t, args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
	if _, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "acme"); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "acme")
	if err == nil || !strings.Contains(err.Error(), "nothing would change") {
		t.Errorf("activating an active tenant: %v", err)
	}
	if f := openWhole(t, path); len(f.Tenants) != 1 {
		t.Errorf("a refused change left %d tenants", len(f.Tenants))
	}
}

func TestTenantsListWithoutTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	stdout, stderr, err := runCLI(t, "tenants", "list", "--keyring", path)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" || !strings.Contains(stderr, "no tenants") {
		t.Errorf("stdout %q, stderr %q", stdout, stderr)
	}
}

// A tenant under a key service: created under Vault, activated, and moved to
// KMS, each step opening what it sealed before it writes. The deployment stays
// under its passphrase throughout.
func TestTenantsWithAServiceLock(t *testing.T) {
	underVault := keysConfigFile(t, "  tenants:\n    acme: { provider: vault, "+serviceSettings(t, "vault")+" }")
	underKMS := keysConfigFile(t, "  tenants:\n    acme: { provider: awskms, "+serviceSettings(t, "awskms")+" }")
	path := setupKeyring(t, "2026-09")

	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--config", underVault, "acme", "acme-*"); err != nil {
		t.Fatalf("create under Vault: %v", err)
	}
	if _, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "--config", underVault, "acme"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	before := openWhole(t, path).Tenant("acme")
	if before.Ring != nil || before.Lock() != (keys.Lock{Source: keys.SourceVaultTransit, KeyName: "blindbucket"}) {
		t.Fatalf("acme under Vault: %+v", before)
	}

	if _, _, err := runCLI(t, "reseal", "--keyring", path, "--config", underVault, "--to-config", underKMS,
		"--tenant", "acme"); err != nil {
		t.Fatalf("reseal --tenant to KMS: %v", err)
	}
	stdout, _, err := runCLI(t, "tenants", "list", "--keyring", path, "--config", underKMS, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Tenants []struct {
			ActiveKID string      `json:"active_kid"`
			Locks     []keys.Lock `json:"locks"`
			Opened    bool        `json:"opened"`
		} `json:"tenants"`
	}
	if err := json.Unmarshal([]byte(stdout), &list); err != nil {
		t.Fatal(err)
	}
	acme := list.Tenants[0]
	if !acme.Opened || acme.ActiveKID == "" || len(acme.Locks) != 2 ||
		acme.Locks[0].Source != keys.SourceVaultTransit || acme.Locks[1].Source != keys.SourceAWSKMS {
		t.Errorf("acme after the move to KMS: %s", stdout)
	}
	// The old lock no longer opens the current file.
	stdout, _, err = runCLI(t, "tenants", "list", "--keyring", path, "--config", underVault, "--json")
	if err != nil || !strings.Contains(stdout, `"opened":false`) {
		t.Errorf("Vault still opens acme after the move: %v %s", err, stdout)
	}
}

// The gateway serves a keyring with tenants. A tenant whose lock it cannot
// open does not stop it: it says so and starts, and the tenant's buckets are
// refused while every other bucket is served (ADR-038).
func TestServeOpensAKeyringWithTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	acmeConf := tenantPassphraseConfig(t, "acme", writePassphraseFile(t, "acme's passphrase"))
	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--config", acmeConf, "acme", "acme-*"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--deployment-lock", "beta", "beta-*"); err != nil {
		t.Fatal(err)
	}
	provider, _ := stubProvider(t)
	adminAddr := freeAddr(t)

	var (
		stopErr error
		metrics string
	)
	logs := captureStderr(t, func() {
		// keys.tenants names no lock for acme, so acme does not open here.
		stop := startServe(t, fmt.Sprintf(`
server: { listen: %q }
admin: { listen: %q }
upstream: { endpoint: %q, region: us-east-1, path_style: true, access_key_id: a, secret_access_key: b }
keys:
  provider: file
  keyring: %q
  tenants:
    gamma: { provider: file, passphrase_file: /nonexistent }
clients: [{ name: tester, access_key_id: TESTCLIENT, secret_access_key: s, buckets: ["*"] }]
`, freeAddr(t), adminAddr, provider.URL, path))
		_ = waitFor(t, &http.Client{Timeout: time.Second}, "http://"+adminAddr+"/healthz", http.StatusOK).Body.Close()
		resp := waitFor(t, &http.Client{Timeout: time.Second}, "http://"+adminAddr+"/metrics", http.StatusOK)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		metrics = string(body)
		stopErr = stop()
	})
	if stopErr != nil {
		t.Fatalf("serve: %v", stopErr)
	}
	for _, want := range []string{
		"blindbucket_keyring_generation 2",
		`blindbucket_tenant_open{tenant="acme"} 0`,
		`blindbucket_tenant_open{tenant="beta"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("missing from /metrics: %s", want)
		}
	}
	for _, want := range []string{
		`"msg":"keyring has tenants","generation":2,"tenants":2`,
		`a tenant's keys did not open`, `"tenant":"acme"`,
		`sealed under the deployment's lock`, `"tenant":"beta"`,
		`keys.tenants names a tenant the keyring does not have","tenant":"gamma"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no log line containing %s in:\n%s", want, logs)
		}
	}
}

// bucketCommandConfig is a configuration for the commands that work on a
// bucket, pointing at keyring, with keysYAML under keys. The provider is not
// reached by the refusals tested with it.
func bucketCommandConfig(t *testing.T, keyring, keysYAML string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	body := fmt.Sprintf(`
upstream: { endpoint: "http://127.0.0.1:1", region: us-east-1, access_key_id: a, secret_access_key: b }
clients: [{ name: c, access_key_id: k, secret_access_key: s, buckets: ["*"] }]
keys:
  provider: file
  keyring: %q
%s
`, keyring, keysYAML)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The object commands open a keyring with tenants, and refuse a bucket whose
// tenant is destroyed or does not open before they reach the provider.
func TestBucketCommandsAndTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addPassphraseTenant(t, path, "acme", "acme-1", "acme's passphrase", "acme-*")
	f := openWhole(t, path)
	f.Tombstones = []keys.Tombstone{{Name: "globex", Buckets: []string{"globex-*"}, KIDs: []string{"globex-1"},
		Locks: []keys.Lock{{Source: keys.LockDeployment}}, Destroyed: time.Now().UTC()}}
	data, err := f.Marshal([]byte(testPassphrase), keys.DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	withAcme := bucketCommandConfig(t, path, fmt.Sprintf("  tenants:\n    acme: { provider: file, passphrase_file: %q }",
		writePassphraseFile(t, "acme's passphrase")))
	withoutAcme := bucketCommandConfig(t, path, "")

	commands := [][]string{
		{"rotate", "--dry-run"}, {"scrub"}, {"encrypt-existing", "--dry-run"}, {"migrate-names", "--dry-run"},
	}
	for _, c := range []struct {
		name, conf, bucket, want string
	}{
		{"a destroyed tenant's bucket", withAcme, "globex-data", "destroyed"},
		{"a tenant whose lock does not open", withoutAcme, "acme-data", "whose lock did not open"},
	} {
		for _, command := range commands {
			t.Run(c.name+"/"+command[0], func(t *testing.T) {
				args := append(append([]string{}, command...), "--config", c.conf, "s3://"+c.bucket)
				_, _, err := runCLI(t, args...)
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("got %v, want an error saying %q", err, c.want)
				}
			})
		}
	}

	// rotate onto anything but the bucket's tenant's keys is refused before
	// the provider is reached; acme is not active, so a target has to be named.
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "not active yet"},
		{[]string{"--to-kid", "2026-09"}, "tenant default's"},
		{[]string{"--to-kid", "no-such-key"}, "holds no key"},
	} {
		args := append(append([]string{"rotate", "--dry-run", "--config", withAcme}, c.args...), "s3://acme-data")
		if _, _, err := runCLI(t, args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("rotate %v: %v, want an error saying %q", c.args, err, c.want)
		}
	}
}

// A keyring with tenants does not stop the object commands on the default
// tenant's buckets.
func TestBucketCommandsServeTheDefaultTenantsBuckets(t *testing.T) {
	p := testprovider.Require(t)
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")
	cfg := providerConfig(t, p, path)
	target := "s3://" + p.Bucket + "/" + testprovider.RunPrefix() + "default-tenant/"

	for _, command := range [][]string{
		{"rotate", "--dry-run", "--allow-unconditional"}, {"scrub"},
		{"encrypt-existing", "--dry-run", "--allow-unconditional"}, {"migrate-names", "--dry-run", "--allow-unconditional"},
	} {
		args := append(append([]string{}, command...), "--config", cfg, target)
		if _, _, err := runCLI(t, args...); err != nil {
			t.Errorf("%s on the default tenant's bucket: %v", command[0], err)
		}
	}
}

// A census refuses what it cannot count meaningfully before it reaches the
// provider: a tenant that is not active, one that was destroyed, one that
// does not exist.
func TestTenantsCensusRefusals(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")
	f := openWhole(t, path)
	f.Tombstones = []keys.Tombstone{{Name: "globex", Buckets: []string{"globex-*"}, KIDs: []string{"globex-1"},
		Locks: []keys.Lock{{Source: keys.LockDeployment}}, Destroyed: time.Now().UTC()}}
	data, err := f.Marshal([]byte(testPassphrase), keys.DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	conf := bucketCommandConfig(t, path, "")
	for tenant, want := range map[string]string{
		"acme": "not active", "globex": "destroyed", "zeta": "no tenant",
	} {
		if _, _, err := runCLI(t, "tenants", "census", "--config", conf, tenant); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Errorf("census of %s: %v, want an error saying %q", tenant, err, want)
		}
	}
}

func TestMarshalCensusJSON(t *testing.T) {
	data, err := marshalCensusJSON("acme", 4, &census.Result{Buckets: []*census.Bucket{
		{Name: "acme-a", Versioned: true, Scanned: 4, Noncurrent: 1, OnTenant: 2, OffTenant: 1, NoncurrentOff: 1,
			OffKIDs: map[string]int64{"2026-10": 1}, NoncurrentKIDs: map[string]int64{"2026-09": 1}},
		{Name: "acme-gone", Missing: true, OffKIDs: map[string]int64{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"tenant":"acme","generation":4,"off_tenant":1,"noncurrent_off_tenant":1,"failed":0,"buckets":[` +
		`{"bucket":"acme-a","missing":false,"versioned":true,"scanned":4,"noncurrent":1,"on_tenant":2,"off_tenant":1,` +
		`"noncurrent_off_tenant":1,"foreign":0,"failed":0,"off_kids":{"2026-10":1},"noncurrent_off_kids":{"2026-09":1}},` +
		`{"bucket":"acme-gone","missing":true,"versioned":false,"scanned":0,"noncurrent":0,"on_tenant":0,"off_tenant":0,` +
		`"noncurrent_off_tenant":0,"foreign":0,"failed":0,"off_kids":{},"noncurrent_off_kids":{}}]}` + "\n"
	if string(data) != want {
		t.Errorf("got\n%s\nwant\n%s", data, want)
	}
}

// A tenant is destroyed after a clean census, without its lock: what is left
// is a tombstone that keeps its buckets refused. The tenant here was never
// active and its only bucket does not exist, so the census is clean.
func TestTenantsDestroy(t *testing.T) {
	p := testprovider.Require(t)
	path := setupKeyring(t, "2026-09")
	bucket := fmt.Sprintf("bb-destroy-%d", time.Now().UnixNano())
	addPassphraseTenant(t, path, "acme", "acme-1", "acme's passphrase", bucket)
	conf := providerConfig(t, p, path)

	_, stderr, err := runCLI(t, "tenants", "destroy", "--dry-run", "--config", conf, "acme")
	if err != nil {
		t.Fatalf("destroy --dry-run: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "would destroy tenant acme") || !strings.Contains(stderr, "never active") {
		t.Errorf("destroy --dry-run says:\n%s", stderr)
	}
	if f := openWhole(t, path); f.Generation != 1 || f.Tenant("acme") == nil {
		t.Fatalf("a dry run changed the keyring: generation %d", f.Generation)
	}

	// No keys.tenants in the configuration: acme's passphrase is not needed.
	stdout, stderr, err := runCLI(t, "tenants", "destroy", "--config", conf, "acme")
	if err != nil {
		t.Fatalf("destroy: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, bucket) || !strings.Contains(stdout, "(does not exist)") {
		t.Errorf("destroy does not show its census:\n%s", stdout)
	}
	for _, want := range []string{"destroyed tenant acme", "generation 2", "a passphrase (salt", "forget it"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("destroy does not say %q:\n%s", want, stderr)
		}
	}
	f := openWhole(t, path)
	if f.Generation != 2 || f.Tenant("acme") != nil || len(f.Tombstones) != 1 {
		t.Fatalf("after destroy: generation %d, tenants %d, tombstones %d",
			f.Generation, len(f.Tenants), len(f.Tombstones))
	}
	if name, destroyed := f.Directory().Tenant(bucket); name != "acme" || !destroyed {
		t.Errorf("%s resolves to %q, destroyed %v", bucket, name, destroyed)
	}

	if _, _, err := runCLI(t, "tenants", "destroy", "--config", conf, "acme"); err == nil ||
		!strings.Contains(err.Error(), "destroyed on") {
		t.Errorf("destroying acme twice: %v", err)
	}
}

// What cannot be destroyed is refused, and a census that does not complete
// destroys nothing.
func TestTenantsDestroyRefusals(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")
	conf := bucketCommandConfig(t, path, "")
	for tenant, want := range map[string]string{
		"default": "cannot be destroyed", "zeta": "no tenant",
		// The provider in conf cannot be reached.
		"acme": "listing buckets",
	} {
		if _, _, err := runCLI(t, "tenants", "destroy", "--config", conf, tenant); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Errorf("destroying %s: %v, want an error saying %q", tenant, err, want)
		}
	}
	if f := openWhole(t, path); f.Tenant("acme") == nil || len(f.Tombstones) != 0 {
		t.Error("a refused destruction changed the keyring")
	}
}

func TestDestroyVerdict(t *testing.T) {
	result := func(off, failed int64) *census.Result {
		return &census.Result{Buckets: []*census.Bucket{{Name: "acme-a", OffTenant: off, Failed: failed}}}
	}
	if err := destroyVerdict("acme", result(0, 0), false); err != nil {
		t.Errorf("a clean census: %v", err)
	}
	for _, r := range []*census.Result{result(2, 0), result(0, 1)} {
		err := destroyVerdict("acme", r, false)
		if err == nil || !strings.Contains(err.Error(), "not destroying") || !strings.Contains(err.Error(), "--force") {
			t.Errorf("off %d, failed %d: %v", r.OffTenant(), r.Failed(), err)
		}
		if err := destroyVerdict("acme", r, true); err != nil {
			t.Errorf("off %d, failed %d with --force: %v", r.OffTenant(), r.Failed(), err)
		}
	}
}

// Each lock is named with what destroys it, and a key that also seals the
// deployment or a live tenant is called out rather than offered for deletion.
func TestLockInstructions(t *testing.T) {
	deployment := keys.RootKeyRef{Source: keys.SourceAWSKMS, KeyName: "alias/bb"}
	shared := keys.Lock{Source: keys.SourceVaultTransit, KeyName: "bb-shared"}
	f := &keys.File{Tenants: []*keys.Tenant{{Name: "beta", Locks: []keys.Lock{shared, {Source: keys.LockDeployment}}}}}
	tomb := keys.Tombstone{Name: "acme", Locks: []keys.Lock{
		{Source: keys.LockDeployment},
		{Source: keys.SourcePassphrase, Salt: "c2FsdA=="},
		{Source: keys.SourceAWSKMS, KeyName: "alias/bb-acme"},
		{Source: keys.SourceVaultTransit, KeyName: "bb-acme"},
		{Source: keys.SourceAWSKMS, KeyName: "alias/bb"},
		shared,
	}}
	tc := config.Keys{Provider: "vault", Vault: config.VaultKeys{Mount: "tenants", KeyName: "bb-acme"}}
	got := strings.Join(lockInstructions(f, deployment, tc, tomb), "\n")

	for _, want := range []string{
		"the deployment's lock: every copy of the keyring",
		"a passphrase (salt c2FsdA==): forget it",
		"aws kms describe-key --key-id alias/bb-acme",
		"aws kms schedule-key-deletion --key-id <that key id> --pending-window-in-days 7",
		"vault write tenants/keys/bb-acme/config deletion_allowed=true",
		"vault delete tenants/keys/bb-acme",
		"AWS KMS key alias/bb: DO NOT DESTROY. It also seals the deployment",
		"Vault Transit key bb-shared: DO NOT DESTROY. It also seals tenant beta",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the instructions do not say %q", want)
		}
	}
	for _, never := range []string{"--key-id alias/bb ", "keys/bb-shared"} {
		if strings.Contains(got, never) {
			t.Errorf("the instructions offer a shared key for deletion: %q", never)
		}
	}
}
