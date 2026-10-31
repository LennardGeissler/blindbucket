package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/envelope"
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

// encrypt and decrypt open a keyring with tenants: encrypt under the default
// tenant's key, decrypt under whichever tenant holds the key a file names,
// and say whose a key is that did not open or was destroyed.
func TestCryptWithTenants(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addPassphraseTenant(t, path, "acme", "acme-1", "acme's passphrase", "acme-*")
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("a ledger"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := runCLI(t, "encrypt", "--keyring", path, "-i", plain, "-o", plain+".bb"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, _, err := runCLI(t, "decrypt", "--keyring", path, "-i", plain+".bb", "-o", plain+".out"); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got, _ := os.ReadFile(plain + ".out"); string(got) != "a ledger" { //nolint:gosec // a test's own file.
		t.Errorf("round trip: %q", got)
	}

	// A file under acme's key, as an object in acme's bucket would be.
	f := openWithTenantPassphrase(t, path, "acme's passphrase")
	if err := f.Activate("acme", ""); err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	if err := envelope.Encrypt(t.Context(), &sealed, strings.NewReader("acme's ledger"),
		f.Tenant("acme").Ring, 16); err != nil {
		t.Fatal(err)
	}
	acmeFile := filepath.Join(dir, "acme.bb")
	if err := os.WriteFile(acmeFile, sealed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI(t, "decrypt", "--keyring", path, "-i", acmeFile, "-o", acmeFile+".out")
	if err == nil || !strings.Contains(err.Error(), "tenant acme's, which did not open here") {
		t.Errorf("decrypt without acme's lock: %v", err)
	}
	conf := tenantPassphraseConfig(t, "acme", writePassphraseFile(t, "acme's passphrase"))
	if _, _, err := runCLI(t, "decrypt", "--keyring", path, "--config", conf,
		"-i", acmeFile, "-o", acmeFile+".out"); err != nil {
		t.Fatalf("decrypt with acme's lock: %v", err)
	}
	if got, _ := os.ReadFile(acmeFile + ".out"); string(got) != "acme's ledger" { //nolint:gosec // a test's own file.
		t.Errorf("acme's file decrypted to %q", got)
	}

	if _, err := f.Destroy("acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := f.Marshal([]byte(testPassphrase), keys.DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = runCLI(t, "decrypt", "--keyring", path, "-i", acmeFile, "-o", acmeFile+".gone")
	if err == nil || !strings.Contains(err.Error(), "tenant acme's, which is destroyed") {
		t.Errorf("decrypt after acme's destruction: %v", err)
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

// addPassphraseTenant gives a keyring a tenant sealed by a passphrase of its
// own.
func addPassphraseTenant(t *testing.T, path, name, kid, phrase string, buckets ...string) {
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
	lock, err := keys.PassphraseLock([]byte(phrase), keys.DefaultKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AddTenant(name, buckets, ring, lock); err != nil {
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

// tenantPassphraseConfig is a configuration whose keys.tenants opens name
// with the passphrase in phraseFile.
func tenantPassphraseConfig(t *testing.T, name, phraseFile string) string {
	t.Helper()
	return keysConfigFile(t, fmt.Sprintf("  tenants:\n    %s: { provider: file, passphrase_file: %q }", name, phraseFile))
}

func openWithTenantPassphrase(t *testing.T, path, phrase string) *keys.File {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // a test's own file.
	if err != nil {
		t.Fatal(err)
	}
	f, err := keys.OpenFileWithPassphrase(data, []byte(testPassphrase),
		func(_ string, _ keys.RootKeyRef, kdf *keys.KDFParams) ([]byte, error) {
			return kdf.DeriveRootKey([]byte(phrase))
		})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// reseal --tenant moves one tenant's lock and keeps the old one in its
// history, which is what a destruction will have to name
// (MCTenantsResealedLock).
func TestResealATenant(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addPassphraseTenant(t, path, "acme", "acme-1", "acme's old passphrase", "acme-*")
	addTenantDirectly(t, path, "beta", "beta-1", "beta-*")
	before := openWithTenantPassphrase(t, path, "acme's old passphrase")

	from := tenantPassphraseConfig(t, "acme", writePassphraseFile(t, "acme's old passphrase"))
	to := tenantPassphraseConfig(t, "acme", writePassphraseFile(t, "acme's new passphrase"))
	if _, _, err := runCLI(t, "reseal", "--keyring", path, "--config", from, "--to-config", to,
		"--tenant", "acme"); err != nil {
		t.Fatalf("reseal --tenant: %v", err)
	}

	after := openWithTenantPassphrase(t, path, "acme's new passphrase")
	acme := after.Tenant("acme")
	if acme.Ring == nil || !acme.Ring.Equal(before.Tenant("acme").Ring) {
		t.Fatalf("acme does not open with its new passphrase to the same keys: %v", acme.Err)
	}
	if len(acme.Locks) != 2 || acme.Locks[0].Source != keys.SourcePassphrase || acme.Locks[0] == acme.Locks[1] {
		t.Errorf("acme's lock history is %+v, want the old passphrase and the new", acme.Locks)
	}
	if beta := after.Tenant("beta"); beta.Ring == nil || !beta.Ring.Equal(before.Tenant("beta").Ring) {
		t.Errorf("beta changed in acme's reseal: %v", beta.Err)
	}
	if openWithTenantPassphrase(t, path, "acme's old passphrase").Tenant("acme").Ring != nil {
		t.Error("acme's old passphrase still opens the new file")
	}
}

func TestResealATenantMistakes(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	addPassphraseTenant(t, path, "acme", "acme-1", "acme's passphrase", "acme-*")
	same := writePassphraseFile(t, "acme's passphrase")
	from := tenantPassphraseConfig(t, "acme", same)

	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no --to-config": {[]string{"--config", from}, "--to-config"},
		"the deployment's new passphrase": {[]string{"--config", from, "--to-config", from,
			"--new-passphrase-file", same}, "deployment's new passphrase"},
		"the same passphrase": {[]string{"--config", from, "--to-config", from}, "already has"},
		"a tenant that does not exist": {[]string{"--config", from, "--to-config", from, "--tenant", "zeta"},
			"no tenant"},
		"no lock configured to open it": {[]string{"--to-config", from}, "keys.tenants.acme is not configured"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"reseal", "--keyring", path}, c.args...)
			if !slices.Contains(args, "--tenant") {
				args = append(args, "--tenant", "acme")
			}
			_, _, err := runCLI(t, args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}
