package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
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
