package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/xml"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
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

// TestEncryptedNamesRefuseUnwiredOperations: the gate has to be reachable
// through the real handler, not only as a unit.
func TestEncryptedNamesRefuseUnwiredOperations(t *testing.T) {
	option, _ := withEncryptedNames(t)
	h := newHarness(t, option)

	// Tagging, not listing: listing is wired now, and this test is about the
	// gate still holding for what is not.
	resp := h.do(t, http.MethodGet, "some/object?tagging")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("tagging returned %d, want 501: %s", resp.StatusCode, readBody(t, resp))
	}
	if body := readBody(t, resp); !strings.Contains(body, "object-name encryption") {
		t.Errorf("the refusal does not explain itself: %s", body)
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

// TestEncryptedListingRefusesWhatItCannotSort covers the shapes this tier hands
// back an error for instead of an answer the client cannot use.
func TestEncryptedListingRefusesWhatItCannotSort(t *testing.T) {
	option, enc := withEncryptedNames(t)
	h := newHarness(t, option)
	ctx := context.Background()

	for _, key := range []string{"many/a.txt", "many/b.txt", "many/c.txt"} {
		s, err := enc.EncryptKey(key)
		if err != nil {
			t.Fatalf("EncryptKey: %v", err)
		}
		resp := h.put(t, key, []byte("x"), nil)
		_ = resp.Body.Close()
		t.Cleanup(func() { _ = h.upstream.DeleteObject(ctx, testBucket, s) })
	}

	for _, tc := range []struct {
		name, query, wants string
	}{
		{"a truncated prefix", "list-type=2&prefix=many/&max-keys=2", "larger than one page"},
		// The substrings avoid apostrophes on purpose: the message is XML-escaped
		// by the time it reaches the client.
		{"a partial segment", "list-type=2&prefix=man", "does not end on a"},
		{"another delimiter", "list-type=2&delimiter=-", "one separator that survives"},
		{"a continuation token", "list-type=2&continuation-token=abc", "continuation-token"},
		{"a start-after", "list-type=2&start-after=many/a.txt", "start-after"},
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
