package integration

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/tags"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// Object tags, sealed in a sidecar per object version (ADR-037). The provider
// is the adversary these tests play: it may read, move, alter, replay or drop a
// sidecar, and only dropping one, or replaying an earlier tag set of the same
// version, may go unnoticed, which the ADR states as accepted.

// tagsOf asks the gateway for an object's tags and returns them as key=value,
// sorted, or fails with the status.
func tagsOf(t *testing.T, h *proxytest.Harness, key string) (int, []string) {
	t.Helper()
	resp := h.Do(t, http.MethodGet, key+"?tagging")
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var doc struct {
		TagSet struct {
			Tags []struct{ Key, Value string } `xml:"Tag"`
		} `xml:"TagSet"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the Tagging answer does not parse: %v (%s)", err, raw)
	}
	if !bytes.Contains(raw, []byte("<TagSet>")) {
		t.Fatalf("the answer carries no TagSet: %s", raw)
	}
	out := []string{}
	for _, tg := range doc.TagSet.Tags {
		out = append(out, tg.Key+"="+tg.Value)
	}
	sort.Strings(out)
	return resp.StatusCode, out
}

// putTags replaces an object's tags through the gateway.
func putTags(t *testing.T, h *proxytest.Harness, key string, pairs ...string) (int, string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>`)
	for _, p := range pairs {
		k, v, _ := strings.Cut(p, "=")
		b.WriteString("<Tag><Key>" + k + "</Key><Value>" + v + "</Value></Tag>")
	}
	b.WriteString("</TagSet></Tagging>")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.URL(key)+"?tagging", strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.ContentLength = int64(b.Len())
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatalf("PutObjectTagging: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, proxytest.ReadBody(t, resp)
}

// sidecarPath is where the provider holds the sidecar of key's current version.
func sidecarPath(t *testing.T, h *proxytest.Harness, stored string) string {
	t.Helper()
	info, err := h.Upstream.HeadObject(context.Background(), proxytest.Bucket, stored)
	if err != nil {
		t.Fatalf("HEAD at the provider: %v", err)
	}
	return tags.Path(stored, objectmeta.StoredDEK(info.Metadata))
}

func readAtProvider(t *testing.T, h *proxytest.Harness, key string) []byte {
	t.Helper()
	out, err := h.Upstream.GetObject(context.Background(), upstream.GetObjectInput{Bucket: proxytest.Bucket, Key: key})
	if err != nil {
		t.Fatalf("reading %s at the provider: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeAtProvider(t *testing.T, h *proxytest.Harness, key string, body []byte) {
	t.Helper()
	if _, err := h.Upstream.PutObject(context.Background(), upstream.PutObjectInput{
		Bucket: proxytest.Bucket, Key: key, Body: bytes.NewReader(body), ContentLength: int64(len(body)),
	}); err != nil {
		t.Fatalf("writing %s at the provider: %v", key, err)
	}
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, key) })
}

func wantTags(t *testing.T, h *proxytest.Harness, key string, want ...string) {
	t.Helper()
	code, got := tagsOf(t, h, key)
	if code != http.StatusOK {
		t.Fatalf("GetObjectTagging %s: %d", key, code)
	}
	if want == nil {
		want = []string{}
	}
	sort.Strings(want)
	if strings.Join(got, "&") != strings.Join(want, "&") {
		t.Fatalf("the tags of %s are %v, want %v", key, got, want)
	}
}

func TestTagsRoundTripSealed(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "names in clear", true: "names encrypted"}[encrypted], func(t *testing.T) {
			key := proxytest.TestKey(t, "tagged")
			h := proxytest.New(t)
			stored := key
			if encrypted {
				option, enc := proxytest.WithEncryptedNames(t)
				h = proxytest.New(t, option)
				s, err := enc.EncryptKey(key)
				if err != nil {
					t.Fatal(err)
				}
				stored = s
			}
			h.CleanupStored(t, stored)
			h.Store(t, key, []byte("an object with tags"))
			wantTags(t, h, key)

			if code, msg := putTags(t, h, key, "project=blue", "owner=alice"); code != http.StatusOK {
				t.Fatalf("PutObjectTagging: %d %s", code, msg)
			}
			wantTags(t, h, key, "owner=alice", "project=blue")

			path := sidecarPath(t, h, stored)
			t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, path) })
			if sealed := readAtProvider(t, h, path); bytes.Contains(sealed, []byte("alice")) ||
				bytes.Contains(sealed, []byte("project")) {
				t.Fatal("the provider holds a tag in the clear")
			}

			resp := h.Do(t, http.MethodDelete, key+"?tagging")
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("DeleteObjectTagging: %d", resp.StatusCode)
			}
			wantTags(t, h, key)
		})
	}
}

func TestTagsGivenWithTheUpload(t *testing.T) {
	h := proxytest.New(t, withPresign(), withUploads(uploadLimit))

	single := proxytest.TestKey(t, "single")
	h.CleanupStored(t, single)
	put := h.Put(t, single, []byte("tagged at upload"), map[string]string{"X-Amz-Tagging": "team=platform&tier=gold"})
	_ = put.Body.Close()
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PUT with x-amz-tagging: %d", put.StatusCode)
	}
	wantTags(t, h, single, "team=platform", "tier=gold")

	parts := proxytest.TestKey(t, "parts")
	h.CleanupStored(t, parts)
	token := h.MpuStart(t, parts, map[string]string{"X-Amz-Tagging": "kind=backup"})
	etag, resp := h.MpuPart(t, parts, token, 1, []byte("one part"))
	_ = resp.Body.Close()
	done := h.MpuComplete(t, parts, token, []proxytest.CompletedPart{{PartNumber: 1, ETag: etag}})
	_ = done.Body.Close()
	if done.StatusCode != http.StatusOK {
		t.Fatalf("completion: %d", done.StatusCode)
	}
	wantTags(t, h, parts, "kind=backup")

	// A presigned upload carries x-amz-tagging in its query, as JavaScript v3
	// puts it there (ADR-036).
	presigned := proxytest.TestKey(t, "presigned")
	h.CleanupStored(t, presigned)
	signed := presignPut(t, h.URL(presigned), 15*time.Minute, time.Now(), 0, nil,
		url.Values{"x-amz-tagging": {"source=browser"}})
	if code, msg := sendUpload(t, h, http.MethodPut, signed, []byte("from a browser"), nil); code != http.StatusOK {
		t.Fatalf("presigned PUT with tags: %d %s", code, msg)
	}
	wantTags(t, h, presigned, "source=browser")
}

// TestTagsBelongToOneVersion: an overwrite has no tags unless it brings its
// own, as on S3. The old version's sidecar is an orphan for gc.
func TestTagsBelongToOneVersion(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "versions")
	h.CleanupStored(t, key)
	put := h.Put(t, key, []byte("version one"), map[string]string{"X-Amz-Tagging": "v=1"})
	_ = put.Body.Close()
	wantTags(t, h, key, "v=1")
	put = h.Put(t, key, []byte("version two"), nil)
	_ = put.Body.Close()
	wantTags(t, h, key)
}

func TestInvalidTagsAreRefused(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "obj")
	h.Store(t, key, []byte("an object"))
	eleven := make([]string, 11)
	for i := range eleven {
		eleven[i] = string(rune('a'+i)) + "=v"
	}
	for name, pairs := range map[string][]string{
		"eleven tags":        eleven,
		"the aws: prefix":    {"aws:owner=me"},
		"a character not in": {"k=a*b"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, msg := putTags(t, h, key, pairs...); code != http.StatusBadRequest || !strings.Contains(msg, "InvalidTag") {
				t.Fatalf("PutObjectTagging: %d %s, want 400 InvalidTag", code, msg)
			}
		})
	}
	wantTags(t, h, key)

	refused := proxytest.TestKey(t, "refused")
	put := h.Put(t, refused, []byte("never stored"), map[string]string{"X-Amz-Tagging": "aws:x=1"})
	_ = put.Body.Close()
	if put.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT with invalid x-amz-tagging: %d, want 400", put.StatusCode)
	}
	wantAbsent(t, h, refused)
}

// TestAProviderCannotMoveAlterOrReplayASidecar: a sidecar opens only for the
// version it was sealed for, so each of these is refused as tampering.
func TestAProviderCannotMoveAlterOrReplayASidecar(t *testing.T) {
	h := proxytest.New(t)
	a, b := proxytest.TestKey(t, "a"), proxytest.TestKey(t, "b")
	h.CleanupStored(t, a)
	h.CleanupStored(t, b)
	for key, tag := range map[string]string{a: "who=a", b: "who=b"} {
		put := h.Put(t, key, []byte("object "+key), map[string]string{"X-Amz-Tagging": tag})
		_ = put.Body.Close()
	}
	pathA, pathB := sidecarPath(t, h, a), sidecarPath(t, h, b)
	sealedA, sealedB := readAtProvider(t, h, pathA), readAtProvider(t, h, pathB)

	t.Run("moved to another object", func(t *testing.T) {
		writeAtProvider(t, h, pathB, sealedA)
		if code, _ := tagsOf(t, h, b); code != http.StatusBadGateway {
			t.Fatalf("a's sidecar under b: %d, want 502", code)
		}
		writeAtProvider(t, h, pathB, sealedB)
		wantTags(t, h, b, "who=b")
	})

	t.Run("altered", func(t *testing.T) {
		altered := bytes.Clone(sealedB)
		altered[len(altered)-1] ^= 1
		writeAtProvider(t, h, pathB, altered)
		if code, _ := tagsOf(t, h, b); code != http.StatusBadGateway {
			t.Fatalf("an altered sidecar: %d, want 502", code)
		}
		writeAtProvider(t, h, pathB, sealedB)
	})

	t.Run("replayed from an earlier version", func(t *testing.T) {
		put := h.Put(t, b, []byte("b, version two"), map[string]string{"X-Amz-Tagging": "who=b2"})
		_ = put.Body.Close()
		path2 := sidecarPath(t, h, b)
		t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, path2) })
		writeAtProvider(t, h, path2, sealedB)
		if code, _ := tagsOf(t, h, b); code != http.StatusBadGateway {
			t.Fatalf("version one's sidecar under version two: %d, want 502", code)
		}
	})

	t.Run("dropped, which goes unnoticed as ADR-037 states", func(t *testing.T) {
		if err := h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, pathA); err != nil {
			t.Fatal(err)
		}
		wantTags(t, h, a)
	})
}

// TestAnEarlierTagSetOfTheSameVersionIsNotDetected pins the limit ADR-037
// accepts: a provider that serves an earlier tag set of the same version is
// served as if the client had set it back. Rollback detection does not cover
// sidecars. When it does, this test changes.
func TestAnEarlierTagSetOfTheSameVersionIsNotDetected(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "replay")
	h.CleanupStored(t, key)
	h.Store(t, key, []byte("one version"))
	if code, msg := putTags(t, h, key, "state=draft"); code != http.StatusOK {
		t.Fatalf("PutObjectTagging: %d %s", code, msg)
	}
	path := sidecarPath(t, h, key)
	t.Cleanup(func() { _ = h.Upstream.DeleteObject(context.Background(), proxytest.Bucket, path) })
	draft := readAtProvider(t, h, path)
	if code, msg := putTags(t, h, key, "state=final"); code != http.StatusOK {
		t.Fatalf("PutObjectTagging: %d %s", code, msg)
	}
	writeAtProvider(t, h, path, draft)
	wantTags(t, h, key, "state=draft")
}

// TestACopyDoesNotDropTags: until objcopy carries the sidecar (ADR-037, step
// 4), a copy that would arrive without the source's tags, or set new ones, is
// refused rather than made.
func TestACopyDoesNotDropTags(t *testing.T) {
	h := proxytest.New(t)
	tagged, plain := proxytest.TestKey(t, "tagged"), proxytest.TestKey(t, "plain")
	h.CleanupStored(t, tagged)
	put := h.Put(t, tagged, []byte("tagged source"), map[string]string{"X-Amz-Tagging": "keep=me"})
	_ = put.Body.Close()
	h.Store(t, plain, []byte("untagged source"))

	resp := copyTo(t, h, tagged, proxytest.TestKey(t, "dst1"), nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("a copy of a tagged source: %d, want 501", resp.StatusCode)
	}
	resp = copyTo(t, h, plain, proxytest.TestKey(t, "dst2"), map[string]string{"X-Amz-Tagging": "new=tag"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("a copy that sets tags: %d, want 501", resp.StatusCode)
	}
	resp = copyTo(t, h, plain, proxytest.TestKey(t, "dst3"), nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a copy of an untagged source: %d", resp.StatusCode)
	}
}

// TestAnObjectTheGatewayDidNotWriteTakesNoSealedTags: it has no data key of the
// gateway's to seal them under.
func TestAnObjectTheGatewayDidNotWriteTakesNoSealedTags(t *testing.T) {
	h := proxytest.New(t)
	key := proxytest.TestKey(t, "foreign")
	writeAtProvider(t, h, key, []byte("written before the gateway"))
	if code, msg := putTags(t, h, key, "a=b"); code != http.StatusBadGateway || !strings.Contains(msg, "ObjectNotEncrypted") {
		t.Fatalf("PutObjectTagging on a foreign object: %d %s", code, msg)
	}
	if code, _ := tagsOf(t, h, key); code != http.StatusOK {
		t.Fatalf("GetObjectTagging on a foreign object, forwarded: %d", code)
	}
}
