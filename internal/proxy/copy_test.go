package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// These three functions decide whether a copy happens at all, and they are pure:
// no network, no keys. They are otherwise reached only by integration tests that
// skip without a running provider, so a plain `go test ./...` would not notice
// one of them changing. Rotation depends on x-amz-copy-source-if-match being
// honoured (ADR-020), which is why the conditions are worth pinning one by one.
//
// Errors are compared by Code, never by message: the message is for people and
// may be reworded (ADR-021).

// wantCode fails unless got carries the S3 error code want. An empty want means
// no error at all.
func wantCode(t *testing.T, got *s3api.Error, want string) {
	t.Helper()
	switch {
	case want == "" && got != nil:
		t.Fatalf("got error %s (%s), want none", got.Code, got.Message)
	case want != "" && got == nil:
		t.Fatalf("got no error, want %s", want)
	case want != "" && got.Code != want:
		t.Fatalf("got error %s (%s), want %s", got.Code, got.Message, want)
	}
}

func TestParseCopySourceReadsBucketAndKey(t *testing.T) {
	cases := []struct {
		name, raw, bucket, key string
	}{
		{"with a leading slash", "/bucket/key", "bucket", "key"},
		{"without a leading slash", "bucket/key", "bucket", "key"},
		{"a key with slashes keeps them", "/bucket/a/b/c", "bucket", "a/b/c"},
		{"a percent-encoded key is decoded", "/bucket/a%20b/c%2Bd", "bucket", "a b/c+d"},
		{"a percent-encoded bucket is decoded", "/my%2Dbucket/key", "my-bucket", "key"},
		{"a key may end in a slash", "/bucket/dir/", "bucket", "dir/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseCopySource(c.raw)
			wantCode(t, err, "")
			if got.Bucket != c.bucket || got.Key != c.key {
				t.Errorf("parseCopySource(%q) = bucket %q key %q, want bucket %q key %q",
					c.raw, got.Bucket, got.Key, c.bucket, c.key)
			}
		})
	}
}

// TestParseCopySourceSplitsBeforeDecoding: a key may contain a slash and a
// bucket may not, so an encoded slash belongs to the key. Splitting the decoded
// value instead would move it into the bucket and copy from the wrong object.
func TestParseCopySourceSplitsBeforeDecoding(t *testing.T) {
	got, err := parseCopySource("/bucket/a%2Fb")
	wantCode(t, err, "")
	if got.Bucket != "bucket" || got.Key != "a/b" {
		t.Errorf("got bucket %q key %q, want bucket %q key %q", got.Bucket, got.Key, "bucket", "a/b")
	}
}

// TestParseCopySourceRefusesAVersionIdInsteadOfCopyingTheCurrentVersion: copying
// the current version when a specific one was asked for would be the wrong kind
// of helpful, so it is NotImplemented rather than quietly something else.
func TestParseCopySourceRefusesAVersionIdInsteadOfCopyingTheCurrentVersion(t *testing.T) {
	for _, raw := range []string{
		"/bucket/key?versionId=3HL4kqtJlcpXroDTDmJ",
		"bucket/key?versionId=null",
		"/bucket/key?foo=bar&versionId=abc",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseCopySource(raw)
			wantCode(t, err, "NotImplemented")
		})
	}
}

func TestParseCopySourceIgnoresQueryParametersOtherThanVersionId(t *testing.T) {
	for _, raw := range []string{
		"/bucket/key?foo=bar",
		"/bucket/key?versionId=",
		"/bucket/key?",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := parseCopySource(raw)
			wantCode(t, err, "")
			if got.Bucket != "bucket" || got.Key != "key" {
				t.Errorf("got bucket %q key %q, want bucket %q key %q", got.Bucket, got.Key, "bucket", "key")
			}
		})
	}
}

func TestParseCopySourceRefusesWhatIsNotABucketAndAKey(t *testing.T) {
	cases := []struct {
		name, raw string
	}{
		{"the empty string", ""},
		{"a slash and nothing else", "/"},
		{"a bucket with no key", "/bucket"},
		{"a bucket with an empty key", "/bucket/"},
		{"a key with no bucket", "//key"},
		{"a bad escape in the key", "/bucket/a%zz"},
		{"a bad escape in the bucket", "/b%zz/key"},
		{"a bad escape in the query", "/bucket/key?%zz=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseCopySource(c.raw)
			wantCode(t, err, "InvalidArgument")
		})
	}
}

func TestEtagMatchesIgnoresQuotingOnEitherSide(t *testing.T) {
	cases := []struct {
		name, want, have string
	}{
		{"both quoted", `"abc"`, `"abc"`},
		{"both bare", `abc`, `abc`},
		{"wanted quoted, held bare", `"abc"`, `abc`},
		{"wanted bare, held quoted", `abc`, `"abc"`},
		{"a multipart ETag with its part count", `"abc-3"`, `abc-3`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !etagMatches(c.want, c.have) {
				t.Errorf("etagMatches(%q, %q) = false, want true", c.want, c.have)
			}
		})
	}
}

func TestEtagMatchesAStarMatchesAnyETag(t *testing.T) {
	for _, have := range []string{`abc`, `"abc"`, `"abc-3"`} {
		if !etagMatches("*", have) {
			t.Errorf(`etagMatches("*", %q) = false, want true`, have)
		}
	}
}

func TestEtagMatchesReadsACommaSeparatedList(t *testing.T) {
	cases := []struct {
		name, want, have string
		matches          bool
	}{
		{"the match is first", `"abc","x","y"`, `abc`, true},
		{"the match is last", `"x","y","abc"`, `abc`, true},
		{"spaces around the commas", `"x" , "abc" ,  "y"`, `abc`, true},
		{"a star among others", `"x", *`, `abc`, true},
		{"none of the list", `"x", "y", "z"`, `abc`, false},
		{"a prefix of the ETag is not the ETag", `"ab"`, `abc`, false},
		{"the ETag as a prefix of a candidate is not a match", `"abcd"`, `abc`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := etagMatches(c.want, c.have); got != c.matches {
				t.Errorf("etagMatches(%q, %q) = %v, want %v", c.want, c.have, got, c.matches)
			}
		})
	}
}

func TestEtagMatchesDoesNotMatchADifferentETag(t *testing.T) {
	if etagMatches(`"abc"`, `"def"`) {
		t.Error(`etagMatches("abc", "def") = true, want false`)
	}
	// ETags are opaque tags, so they are compared exactly, not case-folded.
	if etagMatches(`"ABC"`, `"abc"`) {
		t.Error(`etagMatches("ABC", "abc") = true, want false`)
	}
}

// copySourceModified is when the fake source object was last modified.
var copySourceModified = time.Date(2024, time.January, 15, 12, 0, 0, 0, time.UTC)

// at formats a moment the way an HTTP date header carries it.
func at(offset time.Duration) string {
	return copySourceModified.Add(offset).Format(http.TimeFormat)
}

// TestCheckCopyConditionsOneHeaderAtATime covers each header on its own, both
// outcomes. Combinations of headers are not covered here: S3 evaluates some of
// them together, and the gateway does not yet follow it (issue #90).
func TestCheckCopyConditionsOneHeaderAtATime(t *testing.T) {
	const etag = `"abc"`
	cases := []struct {
		name   string
		header string
		value  string
		want   string // the error code, or "" for a copy that goes ahead
	}{
		{"if-match with the ETag copies", "X-Amz-Copy-Source-If-Match", `"abc"`, ""},
		{"if-match with another ETag is refused", "X-Amz-Copy-Source-If-Match", `"def"`, "PreconditionFailed"},
		{"if-match with a star copies", "X-Amz-Copy-Source-If-Match", "*", ""},
		{"if-match among others copies", "X-Amz-Copy-Source-If-Match", `"x", "abc"`, ""},

		{"if-none-match with the ETag is refused", "X-Amz-Copy-Source-If-None-Match", `"abc"`, "PreconditionFailed"},
		{"if-none-match with another ETag copies", "X-Amz-Copy-Source-If-None-Match", `"def"`, ""},
		{"if-none-match with a star is refused", "X-Amz-Copy-Source-If-None-Match", "*", "PreconditionFailed"},

		// An object modified exactly at the given time was not modified after it.
		{"if-unmodified-since after the change copies", "X-Amz-Copy-Source-If-Unmodified-Since", at(time.Hour), ""},
		{"if-unmodified-since exactly at the change copies", "X-Amz-Copy-Source-If-Unmodified-Since", at(0), ""},
		{"if-unmodified-since before the change is refused", "X-Amz-Copy-Source-If-Unmodified-Since", at(-time.Second), "PreconditionFailed"},

		{"if-modified-since before the change copies", "X-Amz-Copy-Source-If-Modified-Since", at(-time.Second), ""},
		{"if-modified-since exactly at the change is refused", "X-Amz-Copy-Source-If-Modified-Since", at(0), "PreconditionFailed"},
		{"if-modified-since after the change is refused", "X-Amz-Copy-Source-If-Modified-Since", at(time.Hour), "PreconditionFailed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(c.header, c.value)
			wantCode(t, checkCopyConditions(h, etag, copySourceModified), c.want)
		})
	}
}

func TestCheckCopyConditionsWithNoHeadersCopies(t *testing.T) {
	wantCode(t, checkCopyConditions(http.Header{}, `"abc"`, copySourceModified), "")
}

// TestCheckCopyConditionsTreatsAnUnparseableDateAsABadRequest: a date the
// gateway cannot read is the client's mistake, not a precondition that failed,
// and answering 412 would tell it the source had changed when nothing was
// compared at all.
func TestCheckCopyConditionsTreatsAnUnparseableDateAsABadRequest(t *testing.T) {
	for _, header := range []string{
		"X-Amz-Copy-Source-If-Unmodified-Since",
		"X-Amz-Copy-Source-If-Modified-Since",
	} {
		for _, value := range []string{"yesterday", "2024-01-15", "Mon, 32 Jan 2024 12:00:00 GMT"} {
			t.Run(header+"/"+value, func(t *testing.T) {
				h := http.Header{}
				h.Set(header, value)
				wantCode(t, checkCopyConditions(h, `"abc"`, copySourceModified), "InvalidArgument")
			})
		}
	}
}
