package proxy

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/migrate"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The integration tests of `blindbucket migrate-names` (ADR-022). Each of the
// four counterexamples of spec/tla/Migrate.tla has one, named in the README
// next to it: the abort the model was written for, the client write the
// If-None-Match guard keeps, and the two limits the design accepts -- a write
// through an instance still serving names in clear, and a delete of an object
// not yet migrated -- pinned so the documentation cannot stop being true.

// migration is a bucket before and after the switch: one gateway serving names
// in clear, one serving them encrypted, with one keyring between them, as a
// deployment has across the restart that turns names.encrypt on.
type migration struct {
	clear *harness
	enc   *harness
	names *names.Encrypter
}

func newMigration(t *testing.T, options ...any) migration {
	t.Helper()
	before := newHarness(t, options...)
	option, enc := withEncryptedNames(t)
	sameKeyring := func(c *Config) { c.Keys = before.keyring }
	after := newHarness(t, append([]any{option, sameKeyring}, options...)...)
	after.keyring = before.keyring
	return migration{clear: before, enc: after, names: enc}
}

// stored is where key lives once migrated, and registers its cleanup: the
// encrypted key is not under the run's prefix, so the sweep cannot find it.
func (m migration) stored(t *testing.T, key string) string {
	t.Helper()
	s, err := m.names.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey(%q): %v", key, err)
	}
	m.enc.cleanupStored(t, s)
	return s
}

// config builds a guarded run, skipping on a provider that would refuse it.
// What the refusal looks like is TestIntegrationMigrateRefusedWithoutTheGuard.
func (m migration) config(t *testing.T, prefix string) migrate.Config {
	t.Helper()
	if p := testprovider.Require(t); !p.MigrationGuarded() {
		t.Skipf("the provider does not enforce If-None-Match on the completion (%s), "+
			"so a guarded migration is refused", p.CompleteIfNoneMatch)
	}
	return m.anyConfig(t, prefix)
}

// anyConfig runs on every provider: guarded where the provider allows it, and
// under --allow-unconditional where it does not. For the tests about something
// other than the guard.
func (m migration) anyConfig(t *testing.T, prefix string) migrate.Config {
	t.Helper()
	return migrate.Config{
		Upstream: m.clear.upstream, Keys: m.clear.keyring, Names: m.names,
		Bucket: testBucket, Prefix: prefix, Log2ChunkSize: stream.MinLog2ChunkSize,
		Concurrency: 4, Log: discardLogger(),
		AllowUnconditional: !testprovider.Require(t).MigrationGuarded(),
	}
}

func (m migration) mustRun(t *testing.T, cfg migrate.Config) *migrate.Result {
	t.Helper()
	result, err := migrate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return result
}

// exists reports whether the provider holds anything at a stored key.
func (h *harness) exists(t *testing.T, stored string) bool {
	t.Helper()
	_, err := h.upstream.HeadObject(t.Context(), testBucket, stored)
	if err != nil && !upstream.NotFound(err) {
		t.Fatalf("HEAD %q: %v", stored, err)
	}
	return err == nil
}

func (h *harness) status(t *testing.T, method, key string) int {
	t.Helper()
	resp := h.do(t, method, key)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestIntegrationMigrateMovesObjectsAcross is the command's whole purpose: an
// object written before the switch is out of sight after it, and back in sight
// once migrated -- the same bytes, the same headers, the same KEK, the same
// part boundaries, and nothing left in clear.
func TestIntegrationMigrateMovesObjectsAcross(t *testing.T) {
	m := newMigration(t)
	prefix := testKey(t, "move")
	small, multi := prefix+"/small.bin", prefix+"/multi.bin"

	smallBody := randomBytes(t, 5000)
	resp := m.clear.put(t, small, smallBody, map[string]string{
		"Content-Type":        "application/x-test",
		"Content-Disposition": `attachment; filename="small.bin"`,
		"Content-Language":    "de",
		"X-Amz-Meta-Owner":    "lennard",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}
	multiBody := m.clear.mpuStore(t, multi, [][]byte{randomBytes(t, testPart), randomBytes(t, 321)})
	oldManifest, _ := m.clear.manifestKeyOf(t, multi)
	kid := m.clear.objectKID(t, small)

	// The switch: what was written before it is out of sight.
	if got := m.enc.status(t, http.MethodHead, small); got != http.StatusNotFound {
		t.Fatalf("before the migration, the switched gateway answers %d for an object in clear", got)
	}

	// A dry run says what it would do and does none of it. Guarded where the
	// provider allows it; on Garage this is the unconditional path, where the
	// small object goes through CopyObject.
	cfg := m.anyConfig(t, prefix+"/")
	cfg.DryRun = true
	if dry := m.mustRun(t, cfg); dry.Migrated != 2 || dry.Incomplete() {
		t.Fatalf("dry run: %+v, want two to migrate", *dry)
	}
	smallStored, multiStored := m.stored(t, small), m.stored(t, multi)
	if m.clear.exists(t, smallStored) || !m.clear.exists(t, small) {
		t.Fatal("the dry run moved an object")
	}

	cfg.DryRun = false
	if got := m.mustRun(t, cfg); got.Migrated != 2 || got.Scanned != 2 || got.Incomplete() {
		t.Fatalf("got %+v, want two migrated and nothing left", *got)
	}

	for key, want := range map[string][]byte{small: smallBody, multi: multiBody} {
		if got := m.enc.mustRead(t, key, "after the migration"); !bytes.Equal(got, want) {
			t.Errorf("%s: the migrated object reads differently", key)
		}
		if m.clear.exists(t, key) {
			t.Errorf("%s is still stored in clear", key)
		}
	}
	if m.clear.exists(t, oldManifest) {
		t.Error("the manifest under the key in clear is still there")
	}

	// Rotation is a separate command: the KEK is the one the object had.
	if got := m.clear.objectKID(t, smallStored); got != kid {
		t.Errorf("the migrated object is wrapped under %q, want %q", got, kid)
	}
	// What the client stored with the object came along.
	head := m.enc.do(t, http.MethodHead, small)
	_ = head.Body.Close()
	for name, want := range map[string]string{
		"Content-Type": "application/x-test", "Content-Disposition": `attachment; filename="small.bin"`,
		"Content-Language": "de", "X-Amz-Meta-Owner": "lennard",
	} {
		if got := head.Header.Get(name); got != want {
			t.Errorf("%s = %q after the migration, want %q", name, got, want)
		}
	}
	// A multipart object keeps its parts, which the size arithmetic reads.
	info, err := m.clear.upstream.HeadObject(t.Context(), testBucket, multiStored)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	if !strings.HasSuffix(strings.Trim(info.ETag, `"`), "-2") {
		t.Errorf("ETag %q does not report two parts", info.ETag)
	}

	// And a second run has nothing to do.
	if again := m.mustRun(t, cfg); again.Scanned != 0 {
		t.Errorf("the second run scanned %d keys in clear, want 0", again.Scanned)
	}
}

// TestIntegrationMigrateFinishesAnAbortedRun is MCMigrateLeaveOnResume: the
// case spec/tla/Migrate.tla was written for. A run publishes the copy and stops
// before deleting the key in clear; the next run finds the copy, recognises it
// by its data key, and finishes.
func TestIntegrationMigrateFinishesAnAbortedRun(t *testing.T) {
	m := newMigration(t)
	key := testKey(t, "aborted.bin")
	whole := m.clear.mpuStore(t, key, [][]byte{randomBytes(t, testPart), randomBytes(t, 1000)})
	oldManifest, _ := m.clear.manifestKeyOf(t, key)
	stored := m.stored(t, key)

	// The run dies the moment its copy lands: its context goes, so the delete
	// that would come next fails, as it would for a killed process.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := m.anyConfig(t, key)
	cfg.Hook = func(point, _ string) {
		if point == migrate.HookComplete {
			cancel()
		}
	}
	first, _ := migrate.Run(ctx, cfg)
	if first != nil && first.Migrated != 0 {
		t.Fatalf("the interrupted run reports %+v", *first)
	}
	if !m.clear.exists(t, stored) || !m.clear.exists(t, key) {
		t.Fatal("the run did not stop between the copy and the delete; the test proves nothing")
	}

	cfg.Hook = nil
	second := m.mustRun(t, cfg)
	if second.Resumed != 1 || second.Migrated != 0 || second.Incomplete() {
		t.Fatalf("the second run reports %+v, want one resumed", *second)
	}
	if m.clear.exists(t, key) || m.clear.exists(t, oldManifest) {
		t.Error("the key in clear or its manifest survived the second run")
	}
	if got := m.enc.mustRead(t, key, "after the second run"); !bytes.Equal(got, whole) {
		t.Error("the object reads differently after the abort and the resume")
	}
}

// TestIntegrationMigrateKeepsAClientWrite is MCMigrateNoCreateGuard: a client
// writes an object's encrypted key while the run is on its way there, and the
// client's write is what remains.
func TestIntegrationMigrateKeepsAClientWrite(t *testing.T) {
	m := newMigration(t)
	key := testKey(t, "contested.bin")
	original, clientWrote := randomBytes(t, 4096), randomBytes(t, 8192)
	m.clear.store(t, key, original)
	m.stored(t, key)
	// A run tells a client's write from an older object by the provider's
	// Last-Modified, which has a resolution of a second. A real switch takes
	// longer than that; a test has to wait for it.
	time.Sleep(1100 * time.Millisecond)

	held := newGate()
	cfg := m.config(t, key)
	var once sync.Once
	cfg.Hook = func(point, _ string) {
		if point == migrate.HookHeadEnc {
			once.Do(held.wait)
		}
	}
	done := make(chan *migrate.Result, 1)
	errs := make(chan error, 1)
	go func() {
		result, err := migrate.Run(t.Context(), cfg)
		done <- result
		errs <- err
	}()
	held.await(t, "the run to find nothing at the encrypted key")

	resp := m.enc.put(t, key, clientWrote, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the client's PUT returned %d", resp.StatusCode)
	}

	held.open()
	if err := <-errs; err != nil {
		t.Fatalf("migrate: %v", err)
	}
	result := <-done

	got := m.enc.mustRead(t, key, "after the migration raced a client write")
	if bytes.Equal(got, original) {
		t.Fatal("the client's write was replaced by the object in clear: NoLostWrite violated")
	}
	if !bytes.Equal(got, clientWrote) {
		t.Fatalf("the object is neither version: %d bytes", len(got))
	}
	if result.Superseded != 1 || result.Migrated != 0 || result.Incomplete() {
		t.Errorf("got %+v, want one superseded", *result)
	}
	if m.clear.exists(t, key) {
		t.Error("the older object is still stored in clear")
	}
}

// TestIntegrationMigrateLosesAWriteInClear is MCMigrateStaleWriter, and pins a
// limit rather than a fix. A gateway instance still serving names in clear
// writes the key in clear while a run is between its copy and its delete; the
// write is gone afterwards. ADR-022 makes "every instance switched" a
// precondition because no condition on any request prevents this.
func TestIntegrationMigrateLosesAWriteInClear(t *testing.T) {
	m := newMigration(t)
	key := testKey(t, "stale.bin")
	original, stale := randomBytes(t, 4096), randomBytes(t, 4096)
	m.clear.store(t, key, original)
	m.stored(t, key)

	held := newGate()
	cfg := m.anyConfig(t, key)
	var once sync.Once
	cfg.Hook = func(point, _ string) {
		if point == migrate.HookComplete {
			once.Do(held.wait)
		}
	}
	errs := make(chan error, 1)
	go func() {
		_, err := migrate.Run(t.Context(), cfg)
		errs <- err
	}()
	held.await(t, "the run to publish its copy")
	m.clear.store(t, key, stale) // through the instance that was not restarted
	held.open()
	if err := <-errs; err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if m.clear.exists(t, key) {
		t.Fatal("the write in clear survived; if that is now true, ADR-022's precondition " +
			"and this test are out of date")
	}
	if got := m.enc.mustRead(t, key, "after the migration"); !bytes.Equal(got, original) {
		t.Fatal("the migrated object is not the one the run copied")
	}
	t.Log("as documented: a write through an instance serving names in clear during the run is lost")
}

// TestIntegrationMigrateBringsBackAnUnmigratedDelete is MCMigrateClientDelete:
// the price of migrating without a transitional mode in the gateway, pinned. A
// delete of an object not yet migrated reaches only its encrypted key, where
// nothing is, and the migration then brings the object back.
func TestIntegrationMigrateBringsBackAnUnmigratedDelete(t *testing.T) {
	m := newMigration(t)
	key := testKey(t, "deleted.bin")
	body := randomBytes(t, 4096)
	m.clear.store(t, key, body)
	m.stored(t, key)

	if got := m.enc.status(t, http.MethodDelete, key); got != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", got)
	}
	m.mustRun(t, m.anyConfig(t, key))

	if got := m.enc.mustRead(t, key, "after the migration"); !bytes.Equal(got, body) {
		t.Fatal("the object came back different")
	}
	t.Log("as documented: a delete of an object not yet migrated is undone by the migration")
}

// TestIntegrationMigrateLeavesWhatItMayNotMove: an object the gateway did not
// write, a key too long to encrypt, and an older object at the encrypted key
// than the one in clear are each reported and left exactly where they are, and
// make the run incomplete -- exit 1 in the command.
func TestIntegrationMigrateLeavesWhatItMayNotMove(t *testing.T) {
	m := newMigration(t)
	prefix := testKey(t, "leave")

	foreign := prefix + "/foreign.txt"
	if _, err := m.clear.upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: testBucket, Key: foreign, Body: strings.NewReader("not ours"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	t.Cleanup(func() { _ = m.clear.upstream.DeleteObject(context.Background(), testBucket, foreign) })

	// Legal in clear, far past 1024 bytes once every one-letter segment carries
	// its synthetic IV.
	long := prefix + "/" + strings.Repeat("a/", 200) + "x"
	m.clear.store(t, long, randomBytes(t, 100))

	// An object at the encrypted key that is older than the one in clear: a
	// bucket that had names encrypted once before. Deleting the one in clear in
	// its favour would lose the newer object.
	older := prefix + "/older.bin"
	resp := m.enc.put(t, older, randomBytes(t, 100), nil)
	_ = resp.Body.Close()
	olderStored := m.stored(t, older)
	time.Sleep(1100 * time.Millisecond) // Last-Modified has a resolution of a second
	m.clear.store(t, older, randomBytes(t, 100))

	got := m.mustRun(t, m.anyConfig(t, prefix+"/"))
	if got.Foreign != 1 || got.TooLong != 1 || got.Conflicted != 1 || got.Migrated != 0 {
		t.Fatalf("got %+v, want one each of foreign, too long and conflicted", *got)
	}
	if !got.Incomplete() {
		t.Error("a run that left objects in clear says it is complete")
	}
	for _, key := range []string{foreign, long, older, olderStored} {
		if !m.clear.exists(t, key) {
			t.Errorf("%s was removed", key)
		}
	}
}

// TestIntegrationMigrateRefusedWithoutTheGuard: on a provider that ignores
// If-None-Match, a guarded run does not start, names the condition, and has
// touched nothing (ADR-022, as ADR-020 does for rotation).
func TestIntegrationMigrateRefusedWithoutTheGuard(t *testing.T) {
	if testprovider.Require(t).MigrationGuarded() {
		t.Skip("the provider enforces If-None-Match on the completion; nothing to refuse")
	}
	m := newMigration(t)
	key := testKey(t, "unguarded.bin")
	m.clear.store(t, key, randomBytes(t, 100))

	cfg := m.anyConfig(t, key)
	cfg.AllowUnconditional = false
	_, err := migrate.Run(t.Context(), cfg)
	var refusal *migrate.UnguardedError
	if !errors.As(err, &refusal) {
		t.Fatalf("migrate.Run returned %v, want an UnguardedError", err)
	}
	if refusal.Conditions.SafeForMigration() {
		t.Error("the refusal carries conditions that say it is safe")
	}
	for _, want := range []string{"If-None-Match on CompleteMultipartUpload", "--allow-unconditional"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if !m.clear.exists(t, key) {
		t.Error("the refused run moved the object")
	}
}

// TestIntegrationMigrateMovesNoData: a migration is a rename at the provider.
// Megabytes of objects must cost kilobytes on the wire.
func TestIntegrationMigrateMovesNoData(t *testing.T) {
	m := newMigration(t)
	prefix := testKey(t, "nodata")
	var stored int64
	for i, size := range []int{200_000, 300_000, 500_000} {
		key := prefix + "/" + string(rune('a'+i)) + ".bin"
		m.clear.store(t, key, randomBytes(t, size))
		m.stored(t, key)
		stored += int64(size)
	}

	counter := &countingTransport{base: http.DefaultTransport}
	meteredCfg := upstreamConfig(t)
	meteredCfg.HTTPClient = &http.Client{Transport: counter}
	metered, err := upstream.New(meteredCfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	cfg := m.anyConfig(t, prefix+"/")
	cfg.Upstream = metered
	if got := m.mustRun(t, cfg); got.Migrated != 3 {
		t.Fatalf("got %+v, want three migrated", *got)
	}

	moved := counter.bytes.Load()
	if moved > stored/50 {
		t.Errorf("the migration moved %d bytes for %d bytes of objects; it is copying data",
			moved, stored)
	}
	t.Logf("migrated %d bytes of objects while moving %d bytes over the wire", stored, moved)
}

// TestIntegrationMigrateKeepsObjectsFresh: rollback detection keys an object by
// the name the client uses and tags it by its segment salts, and a migration
// changes neither, so a migrated object is not mistaken for a rolled-back one
// (ADR-018).
func TestIntegrationMigrateKeepsObjectsFresh(t *testing.T) {
	m := newMigration(t, withFreshness(t))
	key := testKey(t, "fresh.bin")
	body := randomBytes(t, 4096)
	m.clear.store(t, key, body)
	m.stored(t, key)

	m.mustRun(t, m.anyConfig(t, key))
	if got := m.enc.mustRead(t, key, "a migrated object, with rollback detection on"); !bytes.Equal(got, body) {
		t.Error("the migrated object reads differently")
	}
}

// TestIntegrationMigrateTwoRunsAtOnce: two operators starting the command at
// the same time is the other thing the model's second run stands for. Every
// object ends up migrated exactly once, and neither run fails over the other.
func TestIntegrationMigrateTwoRunsAtOnce(t *testing.T) {
	m := newMigration(t)
	prefix := testKey(t, "twice")
	bodies := map[string][]byte{}
	for i := range 6 {
		key := prefix + "/" + string(rune('a'+i)) + ".bin"
		bodies[key] = randomBytes(t, 2000)
		m.clear.store(t, key, bodies[key])
		m.stored(t, key)
	}

	cfg := m.config(t, prefix+"/")
	results := make(chan *migrate.Result, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := migrate.Run(t.Context(), cfg)
			results <- result
			errs <- err
		}()
	}
	var moved int64
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("migrate: %v", err)
		}
		r := <-results
		if r.Incomplete() {
			t.Errorf("a run reports %+v", *r)
		}
		moved += r.Migrated
	}
	// If-None-Match lets exactly one copy of each object be published, and the
	// run that published it is the one that counts it as migrated; the other
	// finds it gone, or finds the copy and counts it resumed.
	if moved != int64(len(bodies)) {
		t.Errorf("the two runs migrated %d objects between them, want %d", moved, len(bodies))
	}
	for key, want := range bodies {
		if got := m.enc.mustRead(t, key, "after two concurrent runs"); !bytes.Equal(got, want) {
			t.Errorf("%s reads differently", key)
		}
		if m.clear.exists(t, key) {
			t.Errorf("%s is still in clear", key)
		}
	}
}
