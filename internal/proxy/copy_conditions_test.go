package proxy

import (
	"net/http"
	"testing"
	"time"
)

// The x-amz-copy-source-if-* headers are not independent: S3 documents that a
// matching if-match decides the copy and if-unmodified-since is not held against
// it (issue #90). These tests pin every combination of the pair, on the function
// both CopyObject and UploadPartCopy call.
//
// Single headers are covered separately; this file is only about how they
// combine, and it uses nothing from the test files beside it.

const condETag = `"abc"`

// condModified is when the source object was last modified.
var condModified = time.Date(2024, time.January, 15, 12, 0, 0, 0, time.UTC)

// condDate renders a moment relative to condModified as an HTTP date.
func condDate(offset time.Duration) string {
	return condModified.Add(offset).Format(http.TimeFormat)
}

// condCheck runs checkCopyConditions with the given headers and returns the S3
// error code it answers, or "" for a copy that goes ahead.
func condCheck(headers map[string]string) string {
	h := http.Header{}
	for name, value := range headers {
		h.Set(name, value)
	}
	if err := checkCopyConditions(h, condETag, condModified); err != nil {
		return err.Code
	}
	return ""
}

const (
	hdrIfMatch           = "X-Amz-Copy-Source-If-Match"
	hdrIfNoneMatch       = "X-Amz-Copy-Source-If-None-Match"
	hdrIfUnmodifiedSince = "X-Amz-Copy-Source-If-Unmodified-Since"
	hdrIfModifiedSince   = "X-Amz-Copy-Source-If-Modified-Since"
)

// TestCopyIfMatchOutranksIfUnmodifiedSince: when the ETag matches and the date
// condition fails, S3 copies. Evaluating the headers one after another refused
// this request with a 412 the client had no way to fix.
func TestCopyIfMatchOutranksIfUnmodifiedSince(t *testing.T) {
	// A date before the change makes if-unmodified-since false on its own.
	failingDate := condDate(-time.Hour)
	holdingDate := condDate(time.Hour)

	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			"a matching ETag copies although the source changed after the date",
			map[string]string{hdrIfMatch: condETag, hdrIfUnmodifiedSince: failingDate},
			"",
		},
		{
			"a matching ETag copies when the date also holds",
			map[string]string{hdrIfMatch: condETag, hdrIfUnmodifiedSince: holdingDate},
			"",
		},
		{
			"a matching star copies although the source changed after the date",
			map[string]string{hdrIfMatch: "*", hdrIfUnmodifiedSince: failingDate},
			"",
		},
		{
			"a mismatched ETag is refused even when the date holds",
			map[string]string{hdrIfMatch: `"other"`, hdrIfUnmodifiedSince: holdingDate},
			"PreconditionFailed",
		},
		{
			"a mismatched ETag is refused when the date fails too",
			map[string]string{hdrIfMatch: `"other"`, hdrIfUnmodifiedSince: failingDate},
			"PreconditionFailed",
		},
		{
			// Without if-match nothing outranks the date, so this is unchanged.
			"a failing date alone is still refused",
			map[string]string{hdrIfUnmodifiedSince: failingDate},
			"PreconditionFailed",
		},
		{
			"a holding date alone still copies",
			map[string]string{hdrIfUnmodifiedSince: holdingDate},
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := condCheck(c.headers); got != c.want {
				t.Errorf("answered %q, want %q", got, c.want)
			}
		})
	}
}

// TestCopyIfMatchStillRefusesADateItCannotRead: not holding the date against the
// copy is not the same as not reading it. A malformed date is the client's
// mistake whatever else is in the request, and it keeps the answer it had.
func TestCopyIfMatchStillRefusesADateItCannotRead(t *testing.T) {
	got := condCheck(map[string]string{hdrIfMatch: condETag, hdrIfUnmodifiedSince: "yesterday"})
	if got != "InvalidArgument" {
		t.Errorf("answered %q, want InvalidArgument", got)
	}
}

// TestCopyIfNoneMatchWithIfModifiedSince covers the pair where S3 documents the
// answer: when the excluded ETag is the source's, S3 refuses, whatever the date
// says. That is a 412 here too, and this pins it so a reordering of the pair
// cannot change it unnoticed.
//
// The remaining case, an ETag that is not excluded with a date condition that
// fails, is left out on purpose. The reference does not document it, RFC 9110
// would copy where this refuses, and what S3 does has to be measured before
// either answer is written down as a test.
func TestCopyIfNoneMatchWithIfModifiedSince(t *testing.T) {
	// A date before the change makes if-modified-since true on its own.
	holdingDate := condDate(-time.Hour)
	failingDate := condDate(time.Hour)

	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			"the excluded ETag is the source's and the date holds: refused",
			map[string]string{hdrIfNoneMatch: condETag, hdrIfModifiedSince: holdingDate},
			"PreconditionFailed",
		},
		{
			"the excluded ETag is the source's and the date fails: refused",
			map[string]string{hdrIfNoneMatch: condETag, hdrIfModifiedSince: failingDate},
			"PreconditionFailed",
		},
		{
			"another ETag is excluded and the date holds: copies",
			map[string]string{hdrIfNoneMatch: `"other"`, hdrIfModifiedSince: holdingDate},
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := condCheck(c.headers); got != c.want {
				t.Errorf("answered %q, want %q", got, c.want)
			}
		})
	}
}

// TestCopyAllFourHeadersTogether: the two pairs are independent of each other, so
// a request carrying all four copies exactly when each pair would on its own.
func TestCopyAllFourHeadersTogether(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			"if-match outranks a failing if-unmodified-since, and the other pair holds",
			map[string]string{
				hdrIfMatch:           condETag,
				hdrIfUnmodifiedSince: condDate(-time.Hour), // fails on its own
				hdrIfNoneMatch:       `"other"`,
				hdrIfModifiedSince:   condDate(-time.Hour), // holds
			},
			"",
		},
		{
			"the first pair copies and the second refuses",
			map[string]string{
				hdrIfMatch:           condETag,
				hdrIfUnmodifiedSince: condDate(-time.Hour),
				hdrIfNoneMatch:       condETag, // excludes the source's own ETag
				hdrIfModifiedSince:   condDate(-time.Hour),
			},
			"PreconditionFailed",
		},
		{
			"the first pair refuses and the second would copy",
			map[string]string{
				hdrIfMatch:           `"other"`,
				hdrIfUnmodifiedSince: condDate(time.Hour),
				hdrIfNoneMatch:       `"other"`,
				hdrIfModifiedSince:   condDate(-time.Hour),
			},
			"PreconditionFailed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := condCheck(c.headers); got != c.want {
				t.Errorf("answered %q, want %q", got, c.want)
			}
		})
	}
}
