package proxy

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// TestListingCache: the cache is an optimisation whose every miss re-reads the
// prefix, so what matters is that it never serves an expired or foreign
// listing, and never grows past its bound.
func TestListingCache(t *testing.T) {
	rows := func(key string) []listingRow { return []listingRow{{key: key}} }

	t.Run("a nil cache is a permanent miss", func(t *testing.T) {
		var c *listingCache
		c.put("b", "p/", "/", rows("x"))
		if _, ok := c.get("b", "p/", "/"); ok {
			t.Error("a nil cache returned a listing")
		}
	})

	t.Run("a listing is kept per bucket, prefix and delimiter", func(t *testing.T) {
		c := newListingCache(time.Minute, 8)
		c.put("b", "p/", "/", rows("x"))
		if got, ok := c.get("b", "p/", "/"); !ok || got[0].key != "x" {
			t.Fatalf("got %v, %t", got, ok)
		}
		for _, other := range [][3]string{{"other", "p/", "/"}, {"b", "q/", "/"}, {"b", "p/", ""}} {
			if _, ok := c.get(other[0], other[1], other[2]); ok {
				t.Errorf("%q served a listing cached for another request", other)
			}
		}
	})

	t.Run("an expired listing is not served", func(t *testing.T) {
		c := newListingCache(time.Nanosecond, 8)
		c.put("b", "p/", "/", rows("x"))
		time.Sleep(time.Millisecond)
		if _, ok := c.get("b", "p/", "/"); ok {
			t.Error("an expired listing was served")
		}
		if len(c.entries) != 0 {
			t.Error("the expired entry was not dropped")
		}
	})

	t.Run("the bound evicts the oldest", func(t *testing.T) {
		c := newListingCache(time.Minute, 2)
		c.put("b", "1/", "/", rows("1"))
		time.Sleep(time.Millisecond)
		c.put("b", "2/", "/", rows("2"))
		c.put("b", "3/", "/", rows("3"))
		if len(c.entries) != 2 {
			t.Fatalf("the cache holds %d entries, bound 2", len(c.entries))
		}
		if _, ok := c.get("b", "1/", "/"); ok {
			t.Error("the oldest entry survived an eviction")
		}
		if _, ok := c.get("b", "3/", "/"); !ok {
			t.Error("the newest entry was evicted")
		}
	})

	t.Run("expired entries go first", func(t *testing.T) {
		c := newListingCache(5*time.Millisecond, 2)
		c.put("b", "old/", "/", rows("old"))
		time.Sleep(10 * time.Millisecond)
		c.ttl = time.Minute // the next entry lives; the first is already past it
		c.entries["b\x00old/\x00/"].born = time.Now().Add(-2 * time.Minute)
		c.put("b", "kept/", "/", rows("kept"))
		c.put("b", "new/", "/", rows("new"))
		if _, ok := c.get("b", "kept/", "/"); !ok {
			t.Error("a live entry was evicted while an expired one could have gone")
		}
	})
}

func TestListingProviderErrors(t *testing.T) {
	for _, tc := range []struct {
		name, query, code string
		status, want      int
		wantCode          string
	}{
		{"v1 dot", "prefix=.", "XMinioInvalidResourceName", 400, 400, "XMinioInvalidResourceName"},
		{"v2 argument", "list-type=2&prefix=docs/", "InvalidArgument", 400, 400, "InvalidArgument"},
		{"unknown code", "list-type=2", "ProviderSpecificArgument", 400, 400, "ProviderSpecificArgument"},
		{"repeated prefix", "prefix=.&prefix=other&X-Amz-Credential=client-only", "InvalidRequest", 400, 400, "InvalidRequest"},
		{"forbidden", "prefix=.", "AccessDenied", 403, 403, "AccessDenied"},
		{"missing bucket", "prefix=.", "NoSuchBucket", 404, 404, "NoSuchBucket"},
		{"condition", "prefix=.", "PreconditionFailed", 412, 412, "PreconditionFailed"},
		{"range", "prefix=.", "InvalidRange", 416, 416, "InvalidRange"},
		{"other client error", "prefix=.", "ProviderSpecificArgument", 422, 502, "InternalError"},
		{"server error", "prefix=.", "ProviderSpecificArgument", 500, 502, "InternalError"},
		{"provider accepts dot", "prefix=.", "", 200, 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const message = `provider explains "prefix" & delimiter`
			var attempts atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				original, _ := url.ParseQuery(tc.query)
				original.Del("X-Amz-Credential")
				if !reflect.DeepEqual(r.URL.Query(), original) {
					t.Errorf("provider query = %v, want %v", r.URL.Query(), original)
				}
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					_, _ = io.WriteString(w, `<ListBucketResult><Name>bucket</Name><Prefix>.</Prefix></ListBucketResult>`)
					return
				}
				_, _ = fmt.Fprintf(w, `<Error><Code>%s</Code><Message>provider explains &quot;prefix&quot; &amp; delimiter</Message><Resource>PRIVATE-STORED-NAME</Resource><RequestId>PRIVATE-PROVIDER-ID</RequestId></Error>`, tc.code)
			}))
			defer provider.Close()
			client, err := upstream.New(upstream.Config{Endpoint: provider.URL, Region: "us-east-1", PathStyle: true,
				AccessKeyID: "synthetic-access", SecretAccessKey: "synthetic-secret", MaxRetries: 1})
			if err != nil {
				t.Fatal(err)
			}
			p := &Proxy{upstream: client}
			r := httptest.NewRequest(http.MethodGet, "/bucket?"+tc.query, nil)
			w := httptest.NewRecorder()
			op := s3api.OpListObjects
			if r.URL.Query().Get("list-type") == "2" {
				op = s3api.OpListObjectsV2
			}
			apiErr := p.listObjects(w, r, s3api.Request{Op: op, Bucket: "bucket"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if apiErr != nil {
				s3api.WriteError(w, r, apiErr, "gateway-request")
			}
			var result struct{ Code, Message string }
			if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("response XML: %v", err)
			}
			if w.Code != tc.want || result.Code != tc.wantCode {
				t.Fatalf("listing returned %d %s: %s; want %d %s", w.Code, result.Code, w.Body.String(), tc.want, tc.wantCode)
			}
			if tc.want == 400 && result.Message != message {
				t.Errorf("message = %q, want %q", result.Message, message)
			}
			if strings.Contains(w.Body.String(), "PRIVATE-") {
				t.Error("provider resource or request id reached the client")
			}
			if attempts.Load() != 1 {
				t.Errorf("provider attempts = %d, want 1 with retries disabled", attempts.Load())
			}
		})
	}
}

func TestProviderBadRequestWithoutListingContext(t *testing.T) {
	err := translateUpstream(&upstream.APIError{StatusCode: 400, Code: "InvalidArgument", Message: "provider detail"})
	if err.HTTPStatus != 502 || err.Code != "InternalError" || strings.Contains(err.Message, "provider detail") {
		t.Fatalf("generic translation = %v, want 502 InternalError without provider message", err)
	}
}

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
