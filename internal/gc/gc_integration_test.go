package gc_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/gc"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// A single-part PUT over a multipart object leaves the old manifest behind on
// purpose -- it saves a HEAD on the most common write path (ADR-010) --
// and gc is what eventually removes it.
func TestIntegrationGcCollectsOrphanFromOverwrite(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "overwritten.bin")

	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 64)})
	orphan, _ := h.ManifestKeyOf(t, key)

	payload := proxytest.RandomBytes(t, 4096)
	h.Store(t, key, payload) // the PUT orphans the manifest

	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, orphan); err != nil {
		t.Fatalf("the manifest was removed by the PUT, which 10.8 says it must not be: %v", err)
	}

	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Deleted != 1 {
		t.Errorf("gc deleted %d manifests, want 1", result.Deleted)
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, orphan); err == nil {
		t.Error("the orphaned manifest is still there")
	}

	// The object itself is untouched.
	if got := h.MustRead(t, key, "after gc"); !bytes.Equal(got, payload) {
		t.Error("gc changed the object")
	}
}

// The manifest a visible object is using must survive any number of passes.
func TestIntegrationGcKeepsTheCurrentManifest(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "live.bin")

	part := proxytest.RandomBytes(t, proxytest.TestPart)
	h.MpuStore(t, key, [][]byte{part, proxytest.RandomBytes(t, 64)})
	current, _ := h.ManifestKeyOf(t, key)

	for range 3 {
		result, err := gc.Run(t.Context(), gc.Config{
			Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
			DisableMinAge: true, Log: proxytest.DiscardLogger(),
		})
		if err != nil {
			t.Fatalf("gc: %v", err)
		}
		if result.Deleted != 0 {
			t.Fatalf("gc deleted %d manifests of a live object", result.Deleted)
		}
		if result.KeptCurrent == 0 {
			t.Error("gc did not recognise the current manifest")
		}
	}

	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, current); err != nil {
		t.Errorf("the live manifest is gone: %v", err)
	}
	h.MustRead(t, key, "after three gc passes")
}

// The minimum age is the second line of defence behind the ordering rules. A
// freshly orphaned manifest must survive a default pass.
func TestIntegrationGcRespectsTheMinimumAge(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "young-orphan.bin")

	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 64)})
	orphan, _ := h.ManifestKeyOf(t, key)
	h.Store(t, key, proxytest.RandomBytes(t, 1000))

	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
		MinAge: time.Hour, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Deleted != 0 {
		t.Errorf("gc deleted %d manifests younger than the minimum age", result.Deleted)
	}
	if result.KeptTooYoung == 0 {
		t.Error("gc did not report the orphan as too young")
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, orphan); err != nil {
		t.Errorf("a manifest under the minimum age was removed: %v", err)
	}
}

// gc has to read the object key out of a manifest it cannot authenticate: it has
// no data key. What makes that safe is that a manifest lives under a directory
// named for the hash of its object key, so a manifest naming some other object
// does not belong there. Without the check, planting one would point a gc pass at
// an object of the attacker's choosing.
func TestIntegrationGcIgnoresAMisplacedManifest(t *testing.T) {
	h := proxytest.New(t)
	victim := proxytest.TestKey(t, "victim.bin")
	decoy := proxytest.TestKey(t, "decoy.bin")

	// A live multipart object whose manifest must survive.
	h.MpuStore(t, victim, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 64)})
	victimManifest, _ := h.ManifestKeyOf(t, victim)

	// A syntactically valid manifest that names the victim, planted under the
	// decoy's hash directory. gc cannot check its MAC, only its location.
	id, err := manifest.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	forged := &manifest.Manifest{
		Bucket: proxytest.Bucket, Key: victim, ID: id,
		Parts: []manifest.Part{{Number: 1, PlainSize: 1024}},
	}
	body, err := forged.Marshal(make([]byte, stream.KeySize))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	planted := id.ObjectKey(decoy)
	if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: planted,
		Body: bytes.NewReader(body), ContentLength: int64(len(body)),
	}); err != nil {
		t.Fatalf("planting the manifest: %v", err)
	}
	// context.Background, not t.Context: the test's context is already cancelled
	// by the time cleanups run.
	t.Cleanup(func() {
		_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, planted)
	})

	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.KeptUnreadable == 0 {
		t.Error("gc did not report the misplaced manifest as unreadable")
	}

	// The victim's own manifest is untouched and the object still reads.
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, victimManifest); err != nil {
		t.Errorf("the victim's manifest was removed: %v", err)
	}
	h.MustRead(t, victim, "after a misplaced manifest was planted")
}

// A dry run reports what it would do and changes nothing.
func TestIntegrationGcDryRun(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "dry-run.bin")

	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 64)})
	orphan, _ := h.ManifestKeyOf(t, key)
	h.Store(t, key, proxytest.RandomBytes(t, 1000))

	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: key,
		DisableMinAge: true, DryRun: true, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if result.Deleted != 1 {
		t.Errorf("the dry run reported %d deletions, want 1", result.Deleted)
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, orphan); err != nil {
		t.Errorf("the dry run deleted the manifest: %v", err)
	}
}

// gc must not touch objects that are not manifests, including ones this gateway
// never wrote.
func TestIntegrationGcLeavesForeignObjectsAlone(t *testing.T) {
	h := proxytest.New(t)
	foreign := ".blindbucket/not-a-manifest.txt"

	if _, err := h.Upstream.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: foreign,
		Body: bytes.NewReader([]byte("hello")), ContentLength: 5,
	}); err != nil {
		t.Fatalf("writing the foreign object: %v", err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, foreign) })

	if _, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
	}); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, foreign); err != nil {
		t.Errorf("gc removed an object that is not a manifest: %v", err)
	}

	// And a client still cannot see it.
	resp := h.Do(t, http.MethodGet, foreign)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET on the reserved prefix returned %d, want 403", resp.StatusCode)
	}
}
