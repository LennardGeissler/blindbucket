package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// clientMetadata is the one place that refuses a client's attempt to write
// blindbucket's own object metadata, and three write paths go through it:
// PutObject, CopyObject with x-amz-metadata-directive: REPLACE, and
// CreateMultipartUpload. A presigned PUT reaches it too, through
// hoistUploadHeaders, which turns x-amz-meta-* in the query into headers first.
//
// Until #91 the refusal was covered only by an integration test that skips
// without a provider, so a plain `go test ./...` asserted nothing about it.
// These cases need no provider and no network.

// lowerMeta re-keys what clientMetadata returned in lower case.
//
// clientMetadata keeps the case the header arrived in, and only Header.Set
// canonicalises a name, so the same metadata reaches it as "Origin" through Set
// and as "origin" through an http.Header literal. Neither case survives the
// round trip -- S3 and the providers behind this gateway lower-case metadata
// keys, and copyResponseHeaders hands them back lower-cased -- so the contract
// worth asserting is the set of lower-cased keys and their values. Pinning
// "Origin" would pin net/http's canonicalisation rather than this function.
func lowerMeta(t *testing.T, in map[string]string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(in))
	for key, value := range in {
		lower := strings.ToLower(key)
		if _, dup := out[lower]; dup {
			t.Fatalf("two metadata keys differ only in case: %q", lower)
		}
		out[lower] = value
	}
	return out
}

// TestClientMetadataKeepsUserMetadataAndDropsEverythingElse: what a client is
// allowed to set arrives keyed without the x-amz-meta- prefix, and nothing that
// is not metadata comes along with it.
func TestClientMetadataKeepsUserMetadataAndDropsEverythingElse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header http.Header
		want   map[string]string
	}{
		{
			name: "metadata set through Set, which canonicalises the name",
			header: func() http.Header {
				h := http.Header{}
				h.Set("X-Amz-Meta-Origin", "integration-test")
				h.Set("x-amz-meta-owner", "alice")
				return h
			}(),
			want: map[string]string{"origin": "integration-test", "owner": "alice"},
		},
		{
			name:   "metadata as a literal, which does not canonicalise",
			header: http.Header{"x-amz-meta-origin": {"integration-test"}},
			want:   map[string]string{"origin": "integration-test"},
		},
		{
			name: "headers that are not metadata are ignored",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Content-Type", "text/plain")
				h.Set("Cache-Control", "max-age=60")
				h.Set("Authorization", "AWS4-HMAC-SHA256 ...")
				h.Set("X-Amz-Date", "20261022T000000Z")
				h.Set("X-Amz-Copy-Source", "/bucket/key")
				h.Set("X-Amz-Metadata-Directive", "REPLACE")
				return h
			}(),
			want: map[string]string{},
		},
		{
			name:   "no headers at all",
			header: http.Header{},
			want:   map[string]string{},
		},
		{
			name:   "a metadata header carrying no value is skipped",
			header: http.Header{"X-Amz-Meta-Origin": {}},
			want:   map[string]string{},
		},
		{
			name:   "the first value wins when a key is given twice",
			header: http.Header{"X-Amz-Meta-Origin": {"first", "second"}},
			want:   map[string]string{"origin": "first"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := clientMetadata(tc.header)
			if err != nil {
				t.Fatalf("clientMetadata returned %v, want it accepted", err)
			}
			lowered := lowerMeta(t, got)
			if len(lowered) != len(tc.want) {
				t.Fatalf("got %d metadata entries %v, want %d %v",
					len(lowered), lowered, len(tc.want), tc.want)
			}
			for key, want := range tc.want {
				if lowered[key] != want {
					t.Errorf("metadata[%q] = %q, want %q", key, lowered[key], want)
				}
			}
		})
	}
}

// TestClientMetadataRefusesTheReservedPrefix is the security property: a client
// must not be able to write the bb-* fields the gateway reads back to decrypt an
// object (docs/FORMAT.md section 6.3). Letting a client set bb-dek would let it
// swap the wrapped key of an object it may write for one from an object it may
// not.
//
// The case of the header name must not matter. HTTP header names are
// case-insensitive, and a client chooses the case it sends, so each key is given
// both through Set, which canonicalises, and as an http.Header literal, which
// does not -- a check that happened to depend on canonicalisation would pass the
// first and fail the second.
func TestClientMetadataRefusesTheReservedPrefix(t *testing.T) {
	t.Parallel()

	reserved := []string{
		"X-Amz-Meta-Bb-Dek",
		"x-amz-meta-BB-kid",
		"X-AMZ-META-bb-v",
		"x-amz-meta-bb-c",
		"X-Amz-Meta-BB-DEK",
		// The bare prefix: reserved on its own, not only with a field after it.
		"x-amz-meta-bb-",
	}

	for _, name := range reserved {
		t.Run("through Set: "+name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			h.Set(name, "forged")
			h.Set("X-Amz-Meta-Origin", "alice")
			assertReserved(t, h)
		})
		t.Run("as a literal: "+name, func(t *testing.T) {
			t.Parallel()
			assertReserved(t, http.Header{
				name:                {"forged"},
				"x-amz-meta-origin": {"alice"},
			})
		})
	}
}

// assertReserved requires the call to be refused, with nothing handed back, and
// with a message a client can act on.
func assertReserved(t *testing.T, h http.Header) {
	t.Helper()
	got, err := clientMetadata(h)
	if err == nil {
		t.Fatalf("clientMetadata accepted a reserved key and returned %v", got)
	}
	// Refused means refused outright. Returning the other, legitimate entries
	// alongside the error would invite a caller to use them.
	if got != nil {
		t.Errorf("metadata is %v on refusal, want nil", got)
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error is %q, want it to say the prefix is reserved", err)
	}
}

// TestClientMetadataAllowsKeysThatMerelyLookReserved: the check is on the "bb-"
// prefix, not on the letters appearing anywhere in the key. A client that
// happens to use "bbx" or "abb-" for its own metadata keeps working, so the
// refusal above is not quietly broader than docs/FORMAT.md section 6.3 says.
func TestClientMetadataAllowsKeysThatMerelyLookReserved(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"x-amz-meta-abb-x",
		"x-amz-meta-bbx",
		"x-amz-meta-b",
		"x-amz-meta-bb", // "bb" without the dash is not the reserved prefix
		"x-amz-meta-xbb-dek",
		"x-amz-meta-dek",
	}

	for _, name := range allowed {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			h.Set(name, "mine")
			got, err := clientMetadata(h)
			if err != nil {
				t.Fatalf("clientMetadata refused %q: %v", name, err)
			}
			key := strings.TrimPrefix(name, "x-amz-meta-")
			if lowerMeta(t, got)[key] != "mine" {
				t.Errorf("metadata = %v, want %q carried through", got, key)
			}
		})
	}
}
