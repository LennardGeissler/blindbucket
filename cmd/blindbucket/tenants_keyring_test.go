package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// openWhole opens a passphrase keyring whole, tenants under the deployment's
// lock included.
func openWhole(t *testing.T, path string) *keys.File {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // a test's own file.
	if err != nil {
		t.Fatal(err)
	}
	f, err := keys.OpenFileWithPassphrase(data, []byte(testPassphrase), nil)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// addTenantDirectly gives a passphrase keyring a tenant under the
// deployment's lock, through the keys package rather than a command, so the
// commands that only have to keep tenants can be tested on their own.
func addTenantDirectly(t *testing.T, path, name, kid string, buckets ...string) {
	t.Helper()
	f := openWhole(t, path)
	ring := keys.NewKeyring()
	if err := ring.Generate(kid); err != nil {
		t.Fatal(err)
	}
	nk, err := keys.NewNameKey()
	if err != nil {
		t.Fatal(err)
	}
	ring.SetNameKey(nk)
	if err := f.AddTenant(name, buckets, ring, keys.DeploymentLock()); err != nil {
		t.Fatal(err)
	}
	data, err := f.Marshal([]byte(testPassphrase), keys.DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// keygen --add and keys remove change the default tenant; a tenant in the
// same file has to come out of either exactly as it went in.
func TestKeyringCommandsKeepTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")
	before := openWhole(t, path).Tenant("acme")

	if _, _, err := runCLI(t, "keygen", "--out", path, "--add", "--kid", "2026-10"); err != nil {
		t.Fatalf("keygen --add: %v", err)
	}
	if _, _, err := runCLI(t, "keys", "remove", "--keyring", path, "--force", "2026-09"); err != nil {
		t.Fatalf("keys remove: %v", err)
	}

	f := openWhole(t, path)
	acme := f.Tenant("acme")
	if acme == nil || acme.Ring == nil || !acme.Ring.Equal(before.Ring) {
		t.Fatalf("acme did not survive: %+v", acme)
	}
	if got := f.Default.KIDs(); len(got) != 1 || got[0] != "2026-10" {
		t.Errorf("default tenant's keys are %v", got)
	}
	if f.Generation != 3 {
		t.Errorf("generation %d after two writes, want 3", f.Generation)
	}
}

func TestATenantsKeyIDStaysItsOwn(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")

	_, _, err := runCLI(t, "keygen", "--out", path, "--add", "--kid", "acme-1")
	if err == nil || !strings.Contains(err.Error(), "unique") {
		t.Errorf("keygen --add with a tenant's key id: %v", err)
	}
	_, _, err = runCLI(t, "keys", "remove", "--keyring", path, "--force", "acme-1")
	if err == nil || !strings.Contains(err.Error(), "tenant acme's") {
		t.Errorf("keys remove of a tenant's key: %v", err)
	}
}

// Until the object commands route a bucket to its tenant, they must not open
// a keyring with tenants at all.
func TestObjectCommandsRefuseAKeyringWithTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")
	in := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(in, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "encrypt", "--keyring", path, "-i", in, "-o", in+".bb")
	if !errors.Is(err, keys.ErrKeyringHasTenants) {
		t.Errorf("encrypt with a keyring with tenants: %v, want ErrKeyringHasTenants", err)
	}
}

func TestKeysListShowsTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")

	stdout, _, err := runCLI(t, "keys", "list", "--keyring", path)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(rows) != 3 {
		t.Fatalf("want a header and two keys:\n%s", stdout)
	}
	// acme is not active yet, so its row carries no marker.
	if f := strings.Fields(rows[2]); len(f) != 4 || f[0] != "acme" || f[1] != "acme-1" {
		t.Errorf("acme's row is %q", rows[2])
	}

	stdout, _, err = runCLI(t, "keys", "list", "--keyring", path, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `"tenant":"acme","kid":"acme-1"`) {
		t.Errorf("the JSON does not name acme's key's tenant: %s", stdout)
	}
}

// A tenant under the deployment's lock moves with the deployment: after a
// reseal it opens with the new passphrase and with nothing else.
func TestResealMovesTenantsUnderTheDeploymentsLock(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addTenantDirectly(t, path, "acme", "acme-1", "acme-*")
	before := openWhole(t, path).Tenant("acme")

	newPass := writePassphraseFile(t, "a different passphrase")
	if _, _, err := runCLI(t, "reseal", "--keyring", path, "--new-passphrase-file", newPass); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // a test's own file.
	if err != nil {
		t.Fatal(err)
	}
	f, err := keys.OpenFileWithPassphrase(data, []byte("a different passphrase"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if acme := f.Tenant("acme"); acme == nil || acme.Ring == nil || !acme.Ring.Equal(before.Ring) {
		t.Fatalf("acme did not follow the deployment: %+v", acme)
	}
	if _, err := keys.OpenFileWithPassphrase(data, []byte(testPassphrase), nil); err == nil {
		t.Error("the old passphrase still opens the resealed keyring")
	}
}
