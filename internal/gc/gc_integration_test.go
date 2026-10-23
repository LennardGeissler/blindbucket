package gc_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
	"github.com/LennardGeissler/blindbucket/internal/crypto/tags"
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

// failingHead answers a HEAD of one object key with a 503 and passes every
// other request on, manifests included.
type failingHead struct {
	key  string
	base http.RoundTripper
	hits int
}

func (f *failingHead) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/"+f.key) {
		f.hits++
		body := `<?xml version="1.0" encoding="UTF-8"?><Error><Code>ServiceUnavailable</Code><Message>injected</Message></Error>`
		return &http.Response{
			Status: "503 Service Unavailable", StatusCode: http.StatusServiceUnavailable,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"Content-Type": {"application/xml"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)), Request: r,
		}, nil
	}
	return f.base.RoundTrip(r)
}

// TestIntegrationGcKeepsManifestsWhenTheHeadFails: a HEAD that fails says
// nothing about whether the object is there. Taken for "gone", it made gc
// delete the manifest of a visible multipart object, which then could not be
// read (invariant I1). Only a 404 means gone.
func TestIntegrationGcKeepsManifestsWhenTheHeadFails(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "live.bin")
	h.MpuStore(t, key, [][]byte{proxytest.RandomBytes(t, proxytest.TestPart), proxytest.RandomBytes(t, 64)})
	current, _ := h.ManifestKeyOf(t, key)

	transport := &failingHead{key: key, base: http.DefaultTransport}
	cfg := proxytest.UpstreamConfig(t)
	cfg.HTTPClient = &http.Client{Transport: transport}
	cfg.MaxRetries = 1
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: client, Bucket: proxytest.Bucket, Prefix: key,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if transport.hits == 0 {
		t.Fatal("the failing HEAD was never sent")
	}
	if result.Deleted != 0 || result.Errors == 0 {
		t.Fatalf("gc with a failing HEAD: %+v, want nothing deleted and an error counted", *result)
	}
	if _, err := h.Upstream.HeadObject(t.Context(), proxytest.Bucket, current); err != nil {
		t.Fatalf("the live manifest is gone: %v", err)
	}
	h.MustRead(t, key, "after a gc pass whose HEAD failed")
}

// sidecarsOf lists the tag sidecars of a stored key at the provider.
func sidecarsOf(t *testing.T, h *proxytest.Harness, stored string) []string {
	t.Helper()
	page, err := h.Upstream.ListObjects(context.Background(), proxytest.Bucket,
		url.Values{"list-type": {"2"}, "prefix": {tags.PrefixFor(stored)}})
	if err != nil {
		t.Fatalf("listing sidecars: %v", err)
	}
	var out []string
	for _, entry := range page.Contents {
		out = append(out, entry.Key)
	}
	t.Cleanup(func() {
		for _, k := range out {
			_ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, k)
		}
	})
	return out
}

func gcSidecars(t *testing.T, h *proxytest.Harness, prefix string, minAgeOff bool) *gc.Result {
	t.Helper()
	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: h.Upstream, Bucket: proxytest.Bucket, Prefix: prefix,
		DisableMinAge: minAgeOff, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	return result
}

// TestIntegrationGcCollectsOrphanedTagSidecars: an overwrite and a delete
// leave sidecars behind; gc removes them and keeps the visible version's.
func TestIntegrationGcCollectsOrphanedTagSidecars(t *testing.T) {
	h := proxytest.New(t)
	key, gone := proxytest.TestKey(t, "kept.bin"), proxytest.TestKey(t, "gone.bin")
	h.CleanupStored(t, key)
	for _, tag := range []string{"v=1", "v=2"} {
		resp := h.Put(t, key, []byte("version "+tag), map[string]string{"X-Amz-Tagging": tag})
		_ = resp.Body.Close()
	}
	resp := h.Put(t, gone, []byte("deleted next"), map[string]string{"X-Amz-Tagging": "doomed=yes"})
	_ = resp.Body.Close()
	del := h.Do(t, http.MethodDelete, gone)
	_ = del.Body.Close()

	if n := len(sidecarsOf(t, h, key)); n != 2 {
		t.Fatalf("%d sidecars for two tagged versions, want 2", n)
	}
	result := gcSidecars(t, h, key, true)
	if result.SidecarsDeleted != 1 || result.SidecarsKeptCurrent != 1 {
		t.Fatalf("gc of an overwritten key: %+v", *result)
	}
	if got := strings.Join(h.Tags(t, key), "&"); got != "v=2" {
		t.Fatalf("the visible version's tags are %q after gc", got)
	}
	if result := gcSidecars(t, h, gone, true); result.SidecarsDeleted != 1 {
		t.Fatalf("gc of a deleted key: %+v", *result)
	}
	if n := len(sidecarsOf(t, h, gone)); n != 0 {
		t.Fatalf("%d sidecars left of a deleted object", n)
	}
}

// TestIntegrationGcLeavesYoungAndInFlightSidecars: a sidecar is written before
// its version is visible. The minimum age keeps a PUT's; an open upload keeps
// a multipart upload's, whatever its age (spec/tla, MCTags and MCTagsNoAge).
func TestIntegrationGcLeavesYoungAndInFlightSidecars(t *testing.T) {
	h := proxytest.New(t)
	young := proxytest.TestKey(t, "young.bin")
	h.CleanupStored(t, young)
	resp := h.Put(t, young, []byte("v1"), map[string]string{"X-Amz-Tagging": "v=1"})
	_ = resp.Body.Close()
	resp = h.Put(t, young, []byte("v2"), nil)
	_ = resp.Body.Close()
	if result := gcSidecars(t, h, young, false); result.SidecarsDeleted != 0 || result.SidecarsKeptTooYoung != 1 {
		t.Fatalf("gc with the minimum age, a fresh orphan: %+v", *result)
	}

	inflight := proxytest.TestKey(t, "inflight.bin")
	token := h.MpuStart(t, inflight, map[string]string{"X-Amz-Tagging": "kind=backup"})
	t.Cleanup(func() {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
			h.URL(inflight)+"?uploadId="+proxytest.URLQueryEscape(token), nil)
		if err == nil {
			if resp, err := h.Client.Do(r); err == nil {
				_ = resp.Body.Close()
			}
		}
	})
	if n := len(sidecarsOf(t, h, inflight)); n != 1 {
		t.Fatalf("%d sidecars for an open tagged upload, want 1", n)
	}
	if result := gcSidecars(t, h, inflight, true); result.SidecarsDeleted != 0 || result.KeysSkipped != 1 {
		t.Fatalf("gc of a key with an open upload: %+v", *result)
	}
}

// TestIntegrationGcIgnoresASidecarThatNamesAnotherKey: bb-key is not
// authenticated, so a sidecar naming a key that does not hash to its place is
// left alone rather than acted on.
func TestIntegrationGcIgnoresASidecarThatNamesAnotherKey(t *testing.T) {
	h := proxytest.New(t)
	victim := proxytest.TestKey(t, "victim.bin")
	h.Store(t, victim, []byte("must not be looked at through a forged sidecar"))
	forged := tags.PrefixFor(proxytest.TestKey(t, "elsewhere")) + "AAAAAAAAAAAAAAAAAAAAAA"
	md := tags.Metadata(victim)
	if _, err := h.Upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: forged, Body: strings.NewReader("x"), ContentLength: 1, Metadata: md,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, forged) })
	// Limited to the victim's key, so that a pass with the age off touches no
	// other test's objects; the forged sidecar is set aside before the prefix
	// is applied, because its key does not resolve.
	result := gcSidecars(t, h, victim, true)
	if result.SidecarsKeptUnreadable == 0 {
		t.Fatalf("a sidecar naming another key was not set aside: %+v", *result)
	}
	if _, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, forged); err != nil {
		t.Fatalf("the forged sidecar was deleted: %v", err)
	}
}

// TestIntegrationGcKeepsSidecarsWhenTheHeadFails: as for manifests, a failed
// HEAD is not a missing object.
func TestIntegrationGcKeepsSidecarsWhenTheHeadFails(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "tagged.bin")
	h.CleanupStored(t, key)
	resp := h.Put(t, key, []byte("tagged"), map[string]string{"X-Amz-Tagging": "keep=me"})
	_ = resp.Body.Close()

	transport := &failingHead{key: key, base: http.DefaultTransport}
	cfg := proxytest.UpstreamConfig(t)
	cfg.HTTPClient = &http.Client{Transport: transport}
	cfg.MaxRetries = 1
	client, err := upstream.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := gc.Run(t.Context(), gc.Config{
		Upstream: client, Bucket: proxytest.Bucket, Prefix: key,
		DisableMinAge: true, Log: proxytest.DiscardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if transport.hits == 0 || result.SidecarsDeleted != 0 || result.Errors == 0 {
		t.Fatalf("gc with a failing HEAD: %+v", *result)
	}
	if got := strings.Join(h.Tags(t, key), "&"); got != "keep=me" {
		t.Fatalf("the tags are %q", got)
	}
}
