package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// TestParseRange holds the Range header to RFC 9110 as S3 applies it. The header
// is the client's to write, and every value it can hold has to end in either a
// range inside the object or a refusal -- never an offset past the end, which
// would be mapped onto ciphertext that is not there.
func TestParseRange(t *testing.T) {
	const size = 1000
	for _, tc := range []struct {
		spec       string
		start, end int64
		err        *s3api.Error
	}{
		{"bytes=0-99", 0, 99, nil},
		{"bytes=100-", 100, 999, nil},
		{"bytes=-100", 900, 999, nil},
		{"bytes=990-5000", 990, 999, nil}, // an end past the object is clamped
		{"bytes=-5000", 0, 999, nil},      // so is a suffix longer than it
		{"bytes= 5 - 9 ", 5, 9, nil},      // spaces around the numbers
		{"  bytes=5-9", 5, 9, nil},        // and around the header value
		{"bytes=999-999", 999, 999, nil},

		{"items=0-99", 0, 0, s3api.ErrInvalidRange},
		{"bytes=0-1,5-6", 0, 0, s3api.ErrNotImplemented},
		{"bytes=100", 0, 0, s3api.ErrInvalidRange},
		{"bytes=-", 0, 0, s3api.ErrInvalidRange},
		{"bytes=-0", 0, 0, s3api.ErrInvalidRange},
		{"bytes=-x", 0, 0, s3api.ErrInvalidRange},
		{"bytes=x-", 0, 0, s3api.ErrInvalidRange},
		{"bytes=-5-", 0, 0, s3api.ErrInvalidRange},
		{"bytes=1000-", 0, 0, s3api.ErrInvalidRange},
		{"bytes=1000-1001", 0, 0, s3api.ErrInvalidRange},
		{"bytes=50-10", 0, 0, s3api.ErrInvalidRange},
		{"bytes=a-b", 0, 0, s3api.ErrInvalidRange},
		{"bytes=9223372036854775808-", 0, 0, s3api.ErrInvalidRange},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			start, end, apiErr := parseRange(tc.spec, size)
			if tc.err != nil {
				if apiErr == nil || apiErr.Code != tc.err.Code {
					t.Fatalf("got %d-%d, %v; want %s", start, end, apiErr, tc.err.Code)
				}
				return
			}
			if apiErr != nil {
				t.Fatalf("refused: %v", apiErr)
			}
			if start != tc.start || end != tc.end {
				t.Errorf("got %d-%d, want %d-%d", start, end, tc.start, tc.end)
			}
			if start < 0 || end >= size || start > end {
				t.Errorf("%d-%d is not inside an object of %d bytes", start, end, size)
			}
		})
	}
}

// TestPassthroughContentEncoding: aws-chunked describes how the request body was
// framed, not what the object is. Stored against the object, it would make a
// later reader try to un-chunk a plain body.
func TestPassthroughContentEncoding(t *testing.T) {
	for header, want := range map[string]string{
		"":                           "",
		"aws-chunked":                "",
		"AWS-Chunked":                "",
		"gzip":                       "gzip",
		"aws-chunked,gzip":           "gzip",
		"gzip, aws-chunked":          "gzip",
		"gzip, aws-chunked, br":      "gzip, br",
		" , aws-chunked , , zstd , ": "zstd",
	} {
		r := httptest.NewRequest("PUT", "/bucket/key", nil)
		if header != "" {
			r.Header.Set("Content-Encoding", header)
		}
		if got := passthroughContentEncoding(r); got != want {
			t.Errorf("Content-Encoding %q forwarded as %q, want %q", header, got, want)
		}
	}
}

// TestRejectUnsupportedUpload: each of these would be silently wrong if
// ignored. Tags and SSE headers would reach the provider in plaintext or ask it
// to hold keys; a copy source on a plain upload would store an empty body.
func TestRejectUnsupportedUpload(t *testing.T) {
	for name, header := range map[string][2]string{
		"a copy source":              {"X-Amz-Copy-Source", "/bucket/other"},
		"SSE":                        {"X-Amz-Server-Side-Encryption", "AES256"},
		"SSE-C":                      {"X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256"},
		"SSE-KMS, differently cased": {"x-amz-server-side-encryption-aws-kms-key-id", "alias/x"},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("PUT", "/bucket/key", nil)
			r.Header.Set(header[0], header[1])
			if apiErr := rejectUnsupportedUpload(r); apiErr == nil || apiErr.Code != s3api.ErrNotImplemented.Code {
				t.Errorf("got %v, want NotImplemented", apiErr)
			}
		})
	}

	r := httptest.NewRequest("PUT", "/bucket/key", nil)
	r.Header.Set("Content-Type", "application/zstd")
	r.Header.Set("X-Amz-Meta-Origin", "backup-job")
	if apiErr := rejectUnsupportedUpload(r); apiErr != nil {
		t.Errorf("an ordinary upload was refused: %v", apiErr)
	}
}
