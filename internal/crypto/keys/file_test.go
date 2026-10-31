package keys

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	fileRoot  = vkey("file/deployment")
	fileRef   = RootKeyRef{Source: SourceAWSKMS, Ciphertext: "AQICAHdeployment", KeyName: "alias/bb"}
	acmeRoot  = vkey("file/acme")
	acmeRef   = RootKeyRef{Source: SourceAWSKMS, Ciphertext: "AQICAHacme", KeyName: "alias/bb-acme"}
	acmeRoots = map[string][]byte{"acme": acmeRoot}
)

// v1File is a version 1 keyring with one KEK, as keygen writes it.
func v1File(t *testing.T) []byte {
	t.Helper()
	def := vring(t, "file/default", "2026-10")
	data, err := def.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func openV(t *testing.T, data, root []byte, roots map[string][]byte) *File {
	t.Helper()
	f, err := OpenFile(data, root, rootsFunc(roots))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func serviceLock(t *testing.T, root []byte, ref RootKeyRef) TenantLock {
	t.Helper()
	l, err := ServiceLock(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// withTenants is a version 2 keyring at generation 1: acme under a KMS key of
// its own owning acme-*, and beta under the deployment's lock owning beta-1.
func withTenants(t *testing.T) []byte {
	t.Helper()
	f := openV(t, v1File(t), fileRoot, nil)
	if err := f.AddTenant("acme", []string{"acme-*"}, vring(t, "file/acme", "acme-2026-10"),
		serviceLock(t, acmeRoot, acmeRef)); err != nil {
		t.Fatal(err)
	}
	if err := f.AddTenant("beta", []string{"beta-1"}, vring(t, "file/beta", "beta-2026-10"), DeploymentLock()); err != nil {
		t.Fatal(err)
	}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Without tenants, a rewrite is a version 1 file that today's loader opens: a
// deployment that never adds a tenant can still downgrade (ADR-038).
func TestAFileWithoutTenantsStaysVersion1(t *testing.T) {
	f := openV(t, v1File(t), fileRoot, nil)
	if err := f.Default.Generate("2026-11"); err != nil {
		t.Fatal(err)
	}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := LoadKeyringWithRootKey(data, fileRoot)
	if err != nil {
		t.Fatalf("a rewritten file without tenants does not load as version 1: %v", err)
	}
	if !ring.Equal(f.Default) {
		t.Error("the rewritten version 1 file holds other keys")
	}
}

func TestAddedTenantsOpenInactive(t *testing.T) {
	data := withTenants(t)
	f := openV(t, data, fileRoot, acmeRoots)
	if f.Generation != 1 {
		t.Errorf("generation %d, want 1", f.Generation)
	}
	for _, name := range []string{"acme", "beta"} {
		tn := f.Tenant(name)
		if tn == nil || tn.Ring == nil {
			t.Fatalf("tenant %s did not open: %+v", name, tn)
		}
		if tn.ActiveKID != "" || tn.Ring.ActiveKID() != "" {
			t.Errorf("%s is active after being added; it must wait for the rollout", name)
		}
	}
	if got := f.Tenant("acme").Lock(); got != (Lock{Source: SourceAWSKMS, KeyName: "alias/bb-acme"}) {
		t.Errorf("acme's lock is %+v", got)
	}
	if got := f.Tenant("beta").Lock(); got != (Lock{Source: LockDeployment}) {
		t.Errorf("beta's lock is %+v", got)
	}
	if name, _ := f.Directory().Tenant("acme-photos"); name != "acme" {
		t.Errorf("acme-photos is in %q", name)
	}
	if _, err := LoadKeyringWithRootKey(data, fileRoot); !errors.Is(err, ErrKeyringHasTenants) {
		t.Errorf("LoadKeyringWithRootKey: %v, want ErrKeyringHasTenants", err)
	}
	if ref, err := ReadRootKeyRef(data); err != nil || ref.KeyName != fileRef.KeyName {
		t.Errorf("ReadRootKeyRef on version 2: %+v, %v", ref, err)
	}
}

// A command that changes the directory needs only the deployment's root key:
// a tenant it cannot open is written back exactly as it was read, and still
// opens afterwards with its own root key.
func TestARewriteCarriesAnUnopenedTenantOver(t *testing.T) {
	data := withTenants(t)
	before := openV(t, data, fileRoot, acmeRoots)
	f := openV(t, data, fileRoot, nil)
	if f.Tenant("acme").Ring != nil {
		t.Fatal("acme opened without its root key")
	}
	if err := f.Assign("acme", []string{"shared-reports"}); err != nil {
		t.Fatal(err)
	}
	newRoot := vkey("file/deployment-2")
	data, err := f.MarshalWithRootKey(newRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	after := openV(t, data, newRoot, acmeRoots)
	acme := after.Tenant("acme")
	if acme.Ring == nil || !acme.Ring.Equal(before.Tenant("acme").Ring) {
		t.Fatalf("acme lost its keys in the rewrite: %v", acme.Err)
	}
	if !slices.Equal(acme.Buckets, []string{"acme-*", "shared-reports"}) {
		t.Errorf("acme's buckets are %v", acme.Buckets)
	}
	// beta is under the deployment's lock, so the new root key opens it.
	if beta := after.Tenant("beta"); beta.Ring == nil || !beta.Ring.Equal(before.Tenant("beta").Ring) {
		t.Errorf("beta did not follow the deployment to its new root key: %v", beta.Err)
	}
	if after.Generation != 2 {
		t.Errorf("generation %d, want 2", after.Generation)
	}
}

func TestActivate(t *testing.T) {
	f := openV(t, withTenants(t), fileRoot, nil)
	if err := f.Activate("acme", ""); err == nil {
		t.Error("activated a tenant that did not open")
	}
	if err := f.Activate("beta", "acme-2026-10"); err == nil {
		t.Error("activated beta with acme's key")
	}
	if err := f.Activate("beta", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.Activate("beta", ""); err == nil {
		t.Error("activating an active tenant again changed something")
	}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	beta := openV(t, data, fileRoot, nil).Tenant("beta")
	if beta.ActiveKID != "beta-2026-10" || beta.Ring.ActiveKID() != "beta-2026-10" {
		t.Errorf("beta's active key is %q / %q", beta.ActiveKID, beta.Ring.ActiveKID())
	}
}

// A reseal keeps the keys and the old lock: every copy of the file from before
// still opens with it, so a destruction has to know it (MCTenantsResealedLock).
func TestResealKeepsTheLockHistory(t *testing.T) {
	old := withTenants(t)
	f := openV(t, old, fileRoot, acmeRoots)
	newRoot := vkey("file/acme-2")
	newRef := RootKeyRef{Source: SourceVaultTransit, Ciphertext: "vault:v1:acme", KeyName: "bb-acme"}
	if err := f.Reseal("acme", serviceLock(t, newRoot, newRef)); err != nil {
		t.Fatal(err)
	}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	after := openV(t, data, fileRoot, map[string][]byte{"acme": newRoot})
	acme := after.Tenant("acme")
	if acme.Ring == nil || !acme.Ring.Equal(f.Tenant("acme").Ring) {
		t.Fatalf("acme did not open under its new lock: %v", acme.Err)
	}
	want := []Lock{{Source: SourceAWSKMS, KeyName: "alias/bb-acme"}, {Source: SourceVaultTransit, KeyName: "bb-acme"}}
	if !slices.Equal(acme.Locks, want) {
		t.Errorf("locks %+v, want %+v", acme.Locks, want)
	}
	if openV(t, data, fileRoot, acmeRoots).Tenant("acme").Ring != nil {
		t.Error("the new file opens acme with the old lock")
	}
	if openV(t, old, fileRoot, acmeRoots).Tenant("acme").Ring == nil {
		t.Error("the old file stopped opening with the old lock; the test is not testing anything")
	}
	if err := f.Reseal("acme", serviceLock(t, newRoot, newRef)); err == nil {
		t.Error("resealed acme under the lock it already has")
	}
}

func TestPassphraseLock(t *testing.T) {
	f := openV(t, v1File(t), fileRoot, nil)
	lock, err := PassphraseLock([]byte("acme's passphrase"), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AddTenant("acme", []string{"acme-*"}, vring(t, "file/acme", "acme-1"), lock); err != nil {
		t.Fatal(err)
	}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	var gotRef RootKeyRef
	opened, err := OpenFile(data, fileRoot, func(_ string, ref RootKeyRef, kdf *KDFParams) ([]byte, error) {
		gotRef = ref
		return kdf.DeriveRootKey([]byte("acme's passphrase"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotRef.Source != SourcePassphrase {
		t.Errorf("tenantRoot was asked for a %q root", gotRef.Source)
	}
	if acme := opened.Tenant("acme"); acme.Ring == nil || acme.Lock().Source != SourcePassphrase {
		t.Errorf("acme under a passphrase: %+v", acme)
	}
}

func TestTenantChangesAreChecked(t *testing.T) {
	tomb := Tombstone{Name: "globex", Buckets: []string{"globex-*"}, KIDs: []string{"globex-1"},
		Locks: []Lock{{Source: LockDeployment}}}
	fresh := func() *File {
		f := openV(t, withTenants(t), fileRoot, acmeRoots)
		f.Tombstones = []Tombstone{tomb}
		return f
	}
	for _, c := range []struct {
		name, want string
		change     func(f *File) error
	}{
		{"the default tenant's name", "default tenant", func(f *File) error {
			return f.AddTenant("default", nil, vring(t, "x", "x-1"), DeploymentLock())
		}},
		{"a tenant's name taken", "exists", func(f *File) error {
			return f.AddTenant("acme", nil, vring(t, "x", "x-1"), DeploymentLock())
		}},
		{"a destroyed tenant's name", "destroyed", func(f *File) error {
			return f.AddTenant("globex", nil, vring(t, "x", "x-1"), DeploymentLock())
		}},
		{"the default tenant's key id", "unique", func(f *File) error {
			return f.AddTenant("gamma", nil, vring(t, "x", "2026-10"), DeploymentLock())
		}},
		{"a destroyed tenant's key id", "unique", func(f *File) error {
			return f.AddTenant("gamma", nil, vring(t, "x", "globex-1"), DeploymentLock())
		}},
		{"a bucket of another tenant", "overlaps", func(f *File) error {
			return f.AddTenant("gamma", []string{"acme-photos"}, vring(t, "x", "x-1"), DeploymentLock())
		}},
		{"a bucket of a destroyed tenant", "destroyed", func(f *File) error {
			return f.Assign("beta", []string{"globex-old"})
		}},
		{"overlapping entries in one change", "overlap", func(f *File) error {
			return f.Assign("beta", []string{"beta-x*", "beta-xy"})
		}},
		{"a malformed entry", "bucket name", func(f *File) error {
			return f.Assign("beta", []string{"Beta"})
		}},
		{"buckets for a destroyed tenant", "destroyed", func(f *File) error {
			return f.Assign("globex", []string{"globex2"})
		}},
		{"buckets for the default tenant", "default tenant", func(f *File) error {
			return f.Assign("default", []string{"some-bucket"})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := fresh()
			err := c.change(f)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
			if len(f.Tenants) != 2 || len(f.Tenant("beta").Buckets) != 1 {
				t.Error("a refused change changed the file")
			}
		})
	}
}

// A tenant under the deployment's lock has to be sealed again under every new
// deployment root key, so a file whose such tenant did not open cannot be
// written: it would be written with a section nothing opens.
func TestAnUnopenedDeploymentTenantBlocksTheWrite(t *testing.T) {
	f := openV(t, withTenants(t), fileRoot, nil)
	beta := f.Tenant("beta")
	beta.Ring, beta.Err = nil, errors.New("corrupt")
	if _, err := f.MarshalWithRootKey(fileRoot, fileRef); err == nil {
		t.Fatal("wrote a file with a deployment-locked tenant it could not seal")
	}
}

func TestFileEqual(t *testing.T) {
	data := withTenants(t)
	a, b := openV(t, data, fileRoot, acmeRoots), openV(t, data, fileRoot, acmeRoots)
	if !a.Equal(b) {
		t.Fatal("one file opened twice is not Equal to itself")
	}
	if c := openV(t, data, fileRoot, nil); a.Equal(c) {
		t.Error("a file with acme open is Equal to one without")
	}
	if err := b.Assign("beta", []string{"beta-2"}); err != nil {
		t.Fatal(err)
	}
	if a.Equal(b) {
		t.Error("files with different buckets are Equal")
	}
}

func TestOpenFileWipesTenantRoots(t *testing.T) {
	given := bytes.Clone(acmeRoot)
	if _, err := OpenFile(withTenants(t), fileRoot, func(string, RootKeyRef, *KDFParams) ([]byte, error) {
		return given, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(given, make([]byte, len(given))) {
		t.Error("the tenant's root key was left in memory")
	}
}

// A tenant opened after the file opens to what it would have opened to with
// it, and one that cannot open says why and stays unopened.
func TestOpenTenantLater(t *testing.T) {
	data := withTenants(t)
	atOnce := openV(t, data, fileRoot, acmeRoots)

	f := openV(t, data, fileRoot, nil)
	if err := f.OpenTenant("acme", rootsFunc(map[string][]byte{"acme": vkey("not acme's")})); err == nil {
		t.Error("acme opened with another root key")
	}
	if f.Tenant("acme").Ring != nil {
		t.Error("a failed OpenTenant left acme open")
	}
	if err := f.OpenTenant("acme", rootsFunc(acmeRoots)); err != nil {
		t.Fatal(err)
	}
	if !f.Equal(atOnce) {
		t.Error("acme opened later holds other keys than acme opened with the file")
	}
	if err := f.OpenTenant("beta", nil); err != nil {
		t.Errorf("beta, under the deployment's lock, was open already: %v", err)
	}
	if err := f.OpenTenant("zeta", rootsFunc(acmeRoots)); err == nil {
		t.Error("opened a tenant the file does not have")
	}
}

// A destroyed tenant leaves the file and stays in its tombstone: its buckets
// are refused rather than falling back to the default tenant, its name and key
// ids are never issued again, and every lock it had is recorded for the
// operator to destroy.
func TestDestroyTenant(t *testing.T) {
	f := openV(t, withTenants(t), fileRoot, acmeRoots)
	if err := f.Reseal("acme", serviceLock(t, vkey("file/acme-2"),
		RootKeyRef{Source: SourceAWSKMS, Ciphertext: "AQICAHacme2", KeyName: "alias/bb-acme-2"})); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 2, 10, 0, 0, 123, time.FixedZone("CET", 3600))
	tomb, err := f.Destroy("acme", at)
	if err != nil {
		t.Fatal(err)
	}
	want := Tombstone{
		Name: "acme", Buckets: []string{"acme-*"}, KIDs: []string{"acme-2026-10"},
		Locks: []Lock{
			{Source: SourceAWSKMS, KeyName: "alias/bb-acme"},
			{Source: SourceAWSKMS, KeyName: "alias/bb-acme-2"},
		},
		Destroyed: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC),
	}
	if !reflect.DeepEqual(tomb, want) {
		t.Errorf("tombstone\n got %+v\nwant %+v", tomb, want)
	}

	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing of acme's is needed any more: the file opens without its root.
	back := openV(t, data, fileRoot, nil)
	if back.Generation != 2 || back.Tenant("acme") != nil || len(back.Tenants) != 1 {
		t.Fatalf("after the destruction: generation %d, tenants %v", back.Generation, back.Directory().Tenants)
	}
	if len(back.Tombstones) != 1 || !reflect.DeepEqual(back.Tombstones[0], want) {
		t.Errorf("tombstone read back: %+v", back.Tombstones)
	}
	if bytes.Contains(data, []byte("AQICAHacme")) {
		t.Error("the destroyed tenant's section is still in the file")
	}
	if name, destroyed := back.Directory().Tenant("acme-photos"); name != "acme" || !destroyed {
		t.Errorf("acme-photos resolves to %q, destroyed %v", name, destroyed)
	}
	if owner, ok := back.KIDOwner("acme-2026-10"); !ok || owner != "acme" {
		t.Errorf("acme's key id is owned by %q, %v", owner, ok)
	}
	if _, err := back.Destroy("acme", at); err == nil || !strings.Contains(err.Error(), "destroyed on 2026-11-02") {
		t.Errorf("destroying acme twice: %v", err)
	}
}

func TestDestroyIsChecked(t *testing.T) {
	f := openV(t, withTenants(t), fileRoot, nil)
	for name, want := range map[string]string{"default": "default tenant", "zeta": "no tenant"} {
		if _, err := f.Destroy(name, time.Now()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("destroying %s: %v, want an error saying %q", name, err, want)
		}
	}
	if len(f.Tenants) != 2 || len(f.Tombstones) != 0 {
		t.Error("a refused destruction changed the file")
	}
	// A tenant that did not open here is destroyed all the same: nothing of
	// its section is read.
	if acme := f.Tenant("acme"); acme.Ring != nil {
		t.Fatal("acme opened without its root")
	}
	if _, err := f.Destroy("acme", time.Now()); err != nil {
		t.Errorf("destroying an unopened tenant: %v", err)
	}
}

// The last tenant destroyed leaves a version 2 file with no tenants: the
// tombstone keeps the buckets refused, which a version 1 file cannot say.
func TestDestroyTheLastTenantKeepsVersion2(t *testing.T) {
	f := openV(t, withTenants(t), fileRoot, acmeRoots)
	for _, name := range []string{"acme", "beta"} {
		if _, err := f.Destroy(name, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	data, err := f.MarshalWithRootKey(fileRoot, fileRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyringWithRootKey(data, fileRoot); !errors.Is(err, ErrKeyringHasTenants) {
		t.Errorf("the file read as version 1: %v", err)
	}
	back := openV(t, data, fileRoot, nil)
	if len(back.Tenants) != 0 || len(back.Tombstones) != 2 {
		t.Errorf("tenants %d, tombstones %d", len(back.Tenants), len(back.Tombstones))
	}
}
