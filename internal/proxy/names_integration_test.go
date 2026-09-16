package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/manifest"
	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// withEncryptedNames turns object-name encryption on for a harness, and hands
// back the encrypter so a test can check what the provider was addressed with.
func withEncryptedNames(t *testing.T) (func(*Config), *names.Encrypter) {
	t.Helper()
	key := make([]byte, names.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	enc, err := names.New(key)
	if err != nil {
		t.Fatalf("names.New: %v", err)
	}
	return func(cfg *Config) { cfg.Names = enc }, enc
}

// TestEncryptedNamesRoundTripThroughTheGateway is the whole point of the slice:
// a client uses ordinary keys, and the provider never sees one.
func TestEncryptedNamesRoundTripThroughTheGateway(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	const key = "photos/2026/03/holiday.jpg"
	body := bytes.Repeat([]byte("blindbucket"), 4096)

	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })

	resp := h.put(t, key, body, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	// The provider holds it under the encrypted name, and under nothing else.
	if _, err := h.upstream.HeadObject(ctx, testBucket, stored); err != nil {
		t.Fatalf("the object is not at its encrypted key upstream: %v", err)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, key); err == nil {
		t.Error("the object is also stored under its plaintext key")
	}
	for _, segment := range strings.Split(key, "/") {
		if strings.Contains(stored, segment) {
			t.Errorf("the stored key %q leaks the plaintext segment %q", stored, segment)
		}
	}

	// GET, HEAD and DELETE all reach it by the plaintext key.
	get := h.do(t, http.MethodGet, key)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, body) {
		t.Errorf("GET returned %d bytes, want %d", len(got), len(body))
	}

	head := h.do(t, http.MethodHead, key)
	_ = head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD returned %d", head.StatusCode)
	}

	del := h.do(t, http.MethodDelete, key)
	_ = del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", del.StatusCode)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, stored); err == nil {
		t.Error("DELETE left the object at its encrypted key")
	}
}

// TestEncryptedNamesServeRanges: a range read makes a HEAD and one or two GETs,
// and every one of them has to address the same encrypted key.
func TestEncryptedNamesServeRanges(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)

	const key = "logs/2026/app.log"
	body := make([]byte, 200_000)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, stored) })

	resp := h.put(t, key, body, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}

	// Deliberately far enough in that the header is not adjacent to the range,
	// which is the two-request path.
	const start, end = 150_000, 150_999
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Range", "bytes=150000-150999")
	get, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusPartialContent {
		t.Fatalf("ranged GET returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, body[start:end+1]) {
		t.Errorf("the ranged read returned the wrong %d bytes", len(got))
	}
}

// TestPlaintextNamesAreUnchanged guards the default. With the feature off the
// provider must see exactly the key the client used, or every existing
// deployment would lose its objects on upgrade.
func TestPlaintextNamesAreUnchanged(t *testing.T) {
	h := newHarness(t)
	const key = "photos/2026/03/holiday.jpg"
	h.store(t, key, []byte("hello"))

	if _, err := h.upstream.HeadObject(context.Background(), testBucket, key); err != nil {
		t.Fatalf("with names off the object is not at its plaintext key: %v", err)
	}
}

func readBodyBytes(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return buf.Bytes()
}

// listQuery sends a raw listing query and returns the status, the raw body and
// the parsed result. It closes the response itself, so that a test asserting on
// a refusal has nothing left to leak.
func (h *harness) listQuery(t *testing.T, query string) (int, string, upstream.ListBucketResult) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		h.proxy.URL+"/"+testBucket+"?"+query, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET listing: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readBodyBytes(t, resp)

	var out upstream.ListBucketResult
	if resp.StatusCode == http.StatusOK {
		if err := xml.Unmarshal(body, &out); err != nil {
			t.Fatalf("parsing listing: %v\n%s", err, body)
		}
	}
	return resp.StatusCode, string(body), out
}

// TestEncryptedListingIsInTheClientsOrder is the bug ADR-017 exists for. The
// provider sorts by the encrypted key; the client must still get its own order,
// because a listing out of order makes `aws s3 sync --delete` delete objects
// that exist.
func TestEncryptedListingIsInTheClientsOrder(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	// Enough keys that agreement between the two orders would be a coincidence.
	plain := []string{
		"docs/a.txt", "docs/b.txt", "docs/c.txt", "docs/d.txt",
		"docs/e.txt", "docs/f.txt", "docs/g.txt", "docs/h.txt",
	}
	var stored []string
	for _, key := range plain {
		s, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		stored = append(stored, s)
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s returned %d", key, resp.StatusCode)
		}
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, s) })
	}

	status, body, got := h.listQuery(t, "list-type=2&prefix=docs/")
	if status != http.StatusOK {
		t.Fatalf("listing returned %d: %s", status, body)
	}
	var keys []string
	for _, e := range got.Contents {
		keys = append(keys, e.Key)
	}
	if !slices.Equal(keys, plain) {
		t.Errorf("listing order:\n got %v\nwant %v", keys, plain)
	}
	if got.Prefix != "docs/" {
		t.Errorf("Prefix = %q, want the client's own prefix", got.Prefix)
	}

	// And the sort was actually load-bearing: the provider's own order differs.
	sortedStored := slices.Clone(stored)
	slices.Sort(sortedStored)
	if slices.Equal(sortedStored, stored) {
		t.Skip("the encrypted keys happened to sort the same way; the sort is untested here")
	}
}

// TestEncryptedListingGroupsOnDelimiter: the '/' separators survive encryption,
// so the provider's own grouping lines up with the plaintext one.
func TestEncryptedListingGroupsOnDelimiter(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	for _, key := range []string{"tree/a/1.txt", "tree/b/1.txt", "tree/top.txt"} {
		s, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, s) })
	}

	status, body, got := h.listQuery(t, "list-type=2&prefix=tree/&delimiter=/")
	if status != http.StatusOK {
		t.Fatalf("listing returned %d: %s", status, body)
	}
	var prefixes []string
	for _, cp := range got.CommonPrefixes {
		prefixes = append(prefixes, cp.Prefix)
	}
	if want := []string{"tree/a/", "tree/b/"}; !slices.Equal(prefixes, want) {
		t.Errorf("common prefixes = %v, want %v", prefixes, want)
	}
	if len(got.Contents) != 1 || got.Contents[0].Key != "tree/top.txt" {
		t.Errorf("contents = %+v, want just tree/top.txt", got.Contents)
	}
}

// TestEncryptedListingRefusesWhatItCannotSort covers the two shapes that stay
// refused, because they are the ones no amount of buffering answers.
func TestEncryptedListingRefusesWhatItCannotSort(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	for _, key := range []string{"many/a.txt", "many/b.txt", "many/c.txt"} {
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	for _, tc := range []struct{ name, query, wants string }{
		// The substrings avoid apostrophes on purpose: the message is XML-escaped
		// by the time it reaches the client.
		{"a partial segment", "list-type=2&prefix=man", "does not end on a"},
		{"another delimiter", "list-type=2&delimiter=-", "one separator that survives"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := h.listQuery(t, tc.query)
			if status != http.StatusNotImplemented {
				t.Fatalf("returned %d, want 501: %s", status, body)
			}
			if !strings.Contains(body, tc.wants) {
				t.Errorf("the refusal does not explain itself (want %q): %s", tc.wants, body)
			}
		})
	}
}

// TestEncryptedListingRefusesAPrefixPastTheBound: past the bound the answer is
// an error naming the limit, never a listing in an order the client cannot use.
func TestEncryptedListingRefusesAPrefixPastTheBound(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option, func(cfg *Config) { cfg.MaxListingKeys = 3 })
	ctx := context.Background()

	for i := range 5 {
		key := fmt.Sprintf("bounded/%02d.txt", i)
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	status, body, _ := h.listQuery(t, "list-type=2&prefix=bounded/")
	if status != http.StatusNotImplemented {
		t.Fatalf("returned %d, want 501: %s", status, body)
	}
	if !strings.Contains(body, "more than 3 keys") {
		t.Errorf("the refusal does not name the bound: %s", body)
	}
}

// TestEncryptedListingPaginates walks a prefix in small pages and checks that
// what comes back is the whole prefix, once each, in the client's order.
//
// ADR-017 in one test: the provider orders by the encrypted
// key, so every page is cut out of a prefix that was read and sorted whole. The
// resume point is the last key served, which the client hands back -- as a
// continuation token for v2, as a marker for v1.
func TestEncryptedListingPaginates(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	var want []string
	for i := range 11 {
		key := fmt.Sprintf("paged/%02d.txt", i)
		want = append(want, key)
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	t.Run("v2 continuation token", func(t *testing.T) {
		var got []string
		query := "list-type=2&prefix=paged/&max-keys=3"
		for page := 0; ; page++ {
			if page > 20 {
				t.Fatal("the listing did not terminate")
			}
			status, body, result := h.listQuery(t, query)
			if status != http.StatusOK {
				t.Fatalf("page %d returned %d: %s", page, status, body)
			}
			for _, e := range result.Contents {
				got = append(got, e.Key)
			}
			if !result.IsTruncated {
				if result.NextContinuationToken != "" {
					t.Error("a final page carries a continuation token")
				}
				break
			}
			if result.NextContinuationToken == "" {
				t.Fatalf("page %d is truncated but names no continuation token", page)
			}
			query = "list-type=2&prefix=paged/&max-keys=3&continuation-token=" +
				url.QueryEscape(result.NextContinuationToken)
		}
		if !slices.Equal(got, want) {
			t.Errorf("paged listing:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("v1 marker", func(t *testing.T) {
		var got []string
		query := "prefix=paged/&max-keys=4"
		for page := 0; ; page++ {
			if page > 20 {
				t.Fatal("the listing did not terminate")
			}
			status, body, result := h.listQuery(t, query)
			if status != http.StatusOK {
				t.Fatalf("page %d returned %d: %s", page, status, body)
			}
			for _, e := range result.Contents {
				got = append(got, e.Key)
			}
			if !result.IsTruncated {
				break
			}
			if result.NextMarker == "" {
				t.Fatalf("page %d is truncated but names no marker", page)
			}
			query = "prefix=paged/&max-keys=4&marker=" + url.QueryEscape(result.NextMarker)
		}
		if !slices.Equal(got, want) {
			t.Errorf("paged listing:\n got %v\nwant %v", got, want)
		}
	})

	// start-after is a plaintext key, and it is the cursor spelled the way a
	// client spells it when it picks its own resume point.
	t.Run("start-after", func(t *testing.T) {
		status, body, result := h.listQuery(t,
			"list-type=2&prefix=paged/&start-after="+url.QueryEscape("paged/08.txt"))
		if status != http.StatusOK {
			t.Fatalf("returned %d: %s", status, body)
		}
		var got []string
		for _, e := range result.Contents {
			got = append(got, e.Key)
		}
		if w := []string{"paged/09.txt", "paged/10.txt"}; !slices.Equal(got, w) {
			t.Errorf("start-after gave %v, want %v", got, w)
		}
	})
}

// TestEncryptedNamesRotate is a regression test for a real defect: a rotation
// finds its work by listing the *provider*, so every key it sees is a stored
// one -- but the data key it re-wraps is bound to the key the *client* names.
// Rotating with the stored key as associated data produced an object no read
// could open. The unwrap of the old key failed first, so nothing was written and
// the failure was loud rather than silent, but key rotation could not run at all
// against a bucket with encrypted names.
func TestEncryptedNamesRotate(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	const key = "rotate/me/please.bin"
	body := bytes.Repeat([]byte("rotate"), 900)
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })

	resp := h.put(t, key, body, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT returned %d", resp.StatusCode)
	}
	before := h.objectKID(t, stored)

	// The rotation is given the same encrypter the gateway serves with, and a
	// prefix in the client's namespace -- both of which it has to map itself.
	cfg := h.rotateConfig(t, "rotate/me/")
	cfg.Names = enc
	result, err := rotate.Run(t.Context(), cfg)
	if err != nil {
		t.Fatalf("rotate.Run: %v", err)
	}
	if result.Rotated != 1 || result.Failed != 0 {
		t.Fatalf("rotated %d, failed %d, scanned %d; want exactly one rotation",
			result.Rotated, result.Failed, result.Scanned)
	}

	if after := h.objectKID(t, stored); after == before {
		t.Errorf("the object is still wrapped under %q", after)
	}

	// The point of the test: it still reads back through the gateway, which
	// unwraps with the plaintext key as associated data.
	get := h.do(t, http.MethodGet, key)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET after rotation returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, body) {
		t.Errorf("the rotated object came back as %d bytes, want %d", len(got), len(body))
	}
}

// TestEncryptedNamesRotateRefusesAPartialPrefix: a rotation prefix lives in the
// client's namespace and has to map, so it carries the same '/' boundary rule a
// listing does.
func TestEncryptedNamesRotateRefusesAPartialPrefix(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)

	cfg := h.rotateConfig(t, "rotate/me")
	cfg.Names = enc
	if _, err := rotate.Run(t.Context(), cfg); err == nil {
		t.Fatal("a prefix not ending on a '/' boundary was accepted")
	} else if !strings.Contains(err.Error(), "boundary") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// TestEncryptedNamesMultipartRoundTrip: an object above the client's multipart
// threshold is where "works with real S3 clients" is decided, and it is the path
// with the most places for the two key forms to be confused -- the upload token
// is sealed against the key the client named, the provider is addressed with the
// key it stores, and the manifest is bound to the stored key and lives at the
// hash of it.
func TestEncryptedNamesMultipartRoundTrip(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	const key = "big/2026/archive.tar"
	parts := [][]byte{randomBytes(t, testPart), randomBytes(t, testPart), randomBytes(t, 4321)}
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })

	whole := h.mpuStore(t, key, parts)

	// Stored where the mapping says, and nowhere else.
	if _, err := h.upstream.HeadObject(ctx, testBucket, stored); err != nil {
		t.Fatalf("the object is not at its encrypted key upstream: %v", err)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, key); err == nil {
		t.Error("the object is also stored under its plaintext key")
	}

	// The manifest hangs off the stored key, which is what keeps gc free of the
	// name key. Reading it by the plaintext key must find nothing.
	if _, id := h.manifestKeyOf(t, stored); id == (manifest.ID{}) {
		t.Error("no manifest was written for the multipart object")
	}

	get := h.do(t, http.MethodGet, key)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, whole) {
		t.Errorf("GET returned %d bytes, want %d", len(got), len(whole))
	}
}

// TestEncryptedNamesMultipartRange reads across a part boundary, which is the
// path that loads the manifest and then fetches byte ranges of the object --
// two different addresses derived from one client key.
func TestEncryptedNamesMultipartRange(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)

	const key = "big/ranged.bin"
	parts := [][]byte{randomBytes(t, testPart), randomBytes(t, testPart)}
	stored, err := enc.EncryptKey(key)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	t.Cleanup(func() { _ = h.upstream.DeleteObject(context.Background(), testBucket, stored) })

	whole := h.mpuStore(t, key, parts)

	// Straddling the boundary between part one and part two.
	start, end := testPart-500, testPart+499
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url(key), nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	get, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusPartialContent {
		t.Fatalf("ranged GET returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, whole[start:end+1]) {
		t.Errorf("the ranged read returned the wrong %d bytes", len(got))
	}
}

// TestEncryptedNamesCopyObject covers CopyObject, where objcopy copies the
// ciphertext inside the provider and only re-wraps the data key.
func TestEncryptedNamesCopyObject(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	const src, dst = "copy/src/small.bin", "copy/dst/small.bin"
	for _, key := range []string{src, dst} {
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	want := randomBytes(t, 4096)
	h.store(t, src, want)

	resp := h.copyTo(t, src, dst, nil)
	body := readBody(t, resp)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("copy returned %d: %s", resp.StatusCode, body)
	}

	get := h.do(t, http.MethodGet, dst)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET of the copy returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, want) {
		t.Errorf("the copy is %d bytes, want %d", len(got), len(want))
	}

	storedDst, err := enc.EncryptKey(dst)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, storedDst); err != nil {
		t.Errorf("the copy is not at its encrypted key: %v", err)
	}
	if _, err := h.upstream.HeadObject(ctx, testBucket, dst); err == nil {
		t.Error("the copy is also stored under its plaintext key")
	}
}

// TestEncryptedNamesUploadPartCopy is a regression test, and it is the one the
// suite was missing. This is what `aws s3 cp s3://a s3://b` does above the
// client's multipart threshold: the client drives the copy itself, and the
// gateway reads the source's byte ranges and re-encrypts them into a part.
//
// That read went to the key the *client* named rather than the one the provider
// stores it under, and every part came back NoSuchKey. A sweep for the wrong
// variable name missed it, and no test went through this path with names on --
// it was found by copying a 40 MiB object with the AWS CLI.
//
// The source is itself multipart, so the read crosses a segment boundary the
// manifest describes and exercises the manifest lookup as well.
func TestEncryptedNamesUploadPartCopy(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	const src, dst = "copy/src/big.bin", "copy/dst/big.bin"
	for _, key := range []string{src, dst} {
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	whole := h.mpuStore(t, src, [][]byte{
		randomBytes(t, testPart), randomBytes(t, testPart), randomBytes(t, 2048),
	})

	// A range starting inside the source's first segment and ending inside its
	// second, which is where the separate-header fetch happens too.
	const first, last = 1000, testPart + 5000
	token := h.mpuStart(t, dst, nil)
	etag := h.copyPartETag(t, dst, token, 1, src, fmt.Sprintf("bytes=%d-%d", first, last))

	resp := h.mpuComplete(t, dst, token, []completeReqPart{{PartNumber: 1, ETag: etag}})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completion returned %d", resp.StatusCode)
	}

	get := h.do(t, http.MethodGet, dst)
	defer func() { _ = get.Body.Close() }()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET of the copy returned %d: %s", get.StatusCode, readBody(t, get))
	}
	if got := readBodyBytes(t, get); !bytes.Equal(got, whole[first:last+1]) {
		t.Errorf("the copied range is %d bytes, want %d", len(got), last-first+1)
	}
}

// TestEncryptedListingIsReadAfterWriteConsistent is a regression test for the
// listing cache, and for the reason a first page is never served from it.
//
// `aws s3 sync` lists the destination before it uploads anything. When that
// empty listing was cached and served again afterwards, the next sync saw an
// empty prefix and uploaded everything a second time. S3 has been strongly
// read-after-write consistent since 2020 and clients lean on it, so a listing
// that a write has overtaken is a wrong answer, not a stale one.
func TestEncryptedListingIsReadAfterWriteConsistent(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	// The listing that populates the cache: the prefix is empty.
	status, body, first := h.listQuery(t, "list-type=2&prefix=rw/")
	if status != http.StatusOK {
		t.Fatalf("the first listing returned %d: %s", status, body)
	}
	if len(first.Contents) != 0 {
		t.Fatalf("the prefix is not empty to begin with: %d keys", len(first.Contents))
	}

	for _, key := range []string{"rw/a.txt", "rw/b.txt"} {
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s returned %d", key, resp.StatusCode)
		}
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	status, body, second := h.listQuery(t, "list-type=2&prefix=rw/")
	if status != http.StatusOK {
		t.Fatalf("the second listing returned %d: %s", status, body)
	}
	var got []string
	for _, e := range second.Contents {
		got = append(got, e.Key)
	}
	if want := []string{"rw/a.txt", "rw/b.txt"}; !slices.Equal(got, want) {
		t.Errorf("a listing taken after the writes returned %v, want %v", got, want)
	}
}

// TestEncryptedListingContinuationUsesOneSnapshot is the other half: within one
// walk, a page is cut out of the prefix as it was when the walk began. S3 makes
// no promise that keys written during a paginated listing turn up in it, and
// serving every page from one snapshot is what a client expects.
func TestEncryptedListingContinuationUsesOneSnapshot(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	var want []string
	for i := range 6 {
		key := fmt.Sprintf("snap/%d.txt", i)
		want = append(want, key)
		stored, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })
	}

	status, body, page1 := h.listQuery(t, "list-type=2&prefix=snap/&max-keys=3")
	if status != http.StatusOK {
		t.Fatalf("page 1 returned %d: %s", status, body)
	}
	if !page1.IsTruncated || page1.NextContinuationToken == "" {
		t.Fatal("page 1 should be truncated and carry a token")
	}

	// A key that sorts inside the first page's range, written mid-walk. It must
	// not appear in page two, because page two continues the snapshot.
	intruder := "snap/0a.txt"
	stored, err := enc.EncryptKey(intruder)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	resp := h.put(t, intruder, []byte("x"), nil)
	_ = resp.Body.Close()
	t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, stored) })

	var got []string
	for _, e := range page1.Contents {
		got = append(got, e.Key)
	}
	status, body, page2 := h.listQuery(t,
		"list-type=2&prefix=snap/&max-keys=3&continuation-token="+
			url.QueryEscape(page1.NextContinuationToken))
	if status != http.StatusOK {
		t.Fatalf("page 2 returned %d: %s", status, body)
	}
	for _, e := range page2.Contents {
		got = append(got, e.Key)
	}
	if !slices.Equal(got, want) {
		t.Errorf("the walk returned %v, want the six keys it began with: %v", got, want)
	}
}
