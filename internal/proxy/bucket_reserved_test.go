package proxy

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// TestTouchesReservedPrefix covers both directions a common prefix can reveal
// the gateway's own objects: a prefix under the reserved one, and a shorter one
// that a delimiter other than "/" groups them under.
func TestTouchesReservedPrefix(t *testing.T) {
	reserved := s3api.ReservedPrefix
	for prefix, want := range map[string]bool{
		"":                         false,
		reserved:                   true,
		reserved + "manifests/":    true,
		reserved[:1]:               true, // "." with delimiter "b" groups them
		reserved[:len(reserved)-1]: true,
		"backups/":                 false,
		".config/":                 false, // a dot-directory of the client's own
		strings.ToUpper(reserved):  false, // keys are case-sensitive
		reserved[:3] + "x":         false,
	} {
		if got := touchesReservedPrefix(prefix); got != want {
			t.Errorf("touchesReservedPrefix(%q) = %t, want %t", prefix, got, want)
		}
	}
}

// TestIntegrationListingHidesTheReservedPrefix: a multipart object leaves a
// manifest under the reserved prefix, and no listing a client can ask for may
// show it -- as an entry, or as a common prefix that groups it.
func TestIntegrationListingHidesTheReservedPrefix(t *testing.T) {
	h := newHarness(t)
	key := testKey(t, "multipart.bin")
	h.mpuStore(t, key, [][]byte{randomBytes(t, testPart), randomBytes(t, 1000)})
	if _, ok := h.manifestKeyOfQuiet(key); !ok {
		t.Fatal("the multipart object left no manifest to hide")
	}

	for _, query := range []string{
		"list-type=2&delimiter=%2F",
		"delimiter=%2F",
		"list-type=2&delimiter=b",
		"list-type=2&delimiter=l",
		"list-type=2&prefix=" + url.QueryEscape(s3api.ReservedPrefix),
		"list-type=2&prefix=.",
		"list-type=2&prefix=.b",
	} {
		t.Run(query, func(t *testing.T) {
			status, body, out := h.listQuery(t, query)
			if query == "list-type=2&prefix=." {
				// MinIO rejects this client prefix; providers that accept it still
				// have to hide the reserved entries below.
				values, _ := url.ParseQuery(query)
				_, err := h.upstream.ListObjects(t.Context(), testBucket, values)
				if apiErr, ok := upstream.AsAPIError(err); ok && apiErr.StatusCode == http.StatusBadRequest {
					var result struct{ Code, Message string }
					if err := xml.Unmarshal([]byte(body), &result); err != nil {
						t.Fatalf("error document: %v", err)
					}
					if status != http.StatusBadRequest || result.Code != apiErr.Code || result.Message != apiErr.Message {
						t.Fatalf("listing returned %d: %s; want provider's 400 %s: %s", status, body, apiErr.Code, apiErr.Message)
					}
					return
				}
				if err != nil {
					t.Fatalf("direct provider listing: %v", err)
				}
			}
			if status != 200 {
				t.Fatalf("listing returned %d: %s", status, body)
			}
			for _, entry := range out.Contents {
				if strings.HasPrefix(entry.Key, s3api.ReservedPrefix) {
					t.Errorf("the listing shows %q", entry.Key)
				}
			}
			for _, cp := range out.CommonPrefixes {
				if touchesReservedPrefix(cp.Prefix) {
					t.Errorf("the listing groups the gateway's objects under %q", cp.Prefix)
				}
			}
			// The response echoes the requested prefix, so only a reserved name
			// the client did not send itself would be a leak.
			if !strings.Contains(query, url.QueryEscape(s3api.ReservedPrefix)) &&
				strings.Contains(body, s3api.ReservedPrefix) {
				t.Errorf("the reserved prefix appears in the response:\n%s", body)
			}
		})
	}
}
