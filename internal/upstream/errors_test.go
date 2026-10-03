package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A HEAD carries no body, so the status-to-code mapping is the only thing a
// caller has to go on. Answering NoSuchKey for a missing bucket sends a client
// -- or a readiness probe -- looking for the wrong thing, which is how this was
// found.
func TestStatusCodeDistinguishesBucketsFromKeys(t *testing.T) {
	cases := []struct {
		status int
		op     string
		want   string
	}{
		{http.StatusNotFound, "HeadObject", "NoSuchKey"},
		{http.StatusNotFound, "GetObject", "NoSuchKey"},
		{http.StatusNotFound, "Passthrough", "NoSuchBucket"},
		{http.StatusNotFound, "ListObjects", "NoSuchBucket"},
		{http.StatusNotFound, "DeleteObjects", "NoSuchBucket"},
		{http.StatusForbidden, "Passthrough", "AccessDenied"},
		{http.StatusPreconditionFailed, "CompleteMultipartUpload", "PreconditionFailed"},
	}
	for _, tc := range cases {
		if got := statusCode(tc.status, tc.op); got != tc.want {
			t.Errorf("statusCode(%d, %q) = %q, want %q", tc.status, tc.op, got, tc.want)
		}
	}
}

// TestErrorInsideA200KeepsItsCondition: CompleteMultipartUpload and the copy
// calls may answer 200 and put the error in the body, and AWS does exactly that
// with a failed If-Match or If-None-Match once a completion has started
// streaming. The guards of rotate and migrate-names, and probe's measurement of
// them, tell a condition that held from a provider failure by the status; a
// PreconditionFailed in a 200 must therefore come out as a 412.
func TestErrorInsideA200KeepsItsCondition(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		code       string
		wantStatus int
	}{
		{"PreconditionFailed", http.StatusPreconditionFailed},
		{"ConditionalRequestConflict", http.StatusConflict},
		{"InternalError", http.StatusInternalServerError},
	} {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				// The keep-alive whitespace S3 sends before the document.
				_, _ = fmt.Fprintf(w, "\n \n<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
					"<Error><Code>%s</Code><Message>m</Message></Error>", tc.code)
			}))
			defer srv.Close()
			c := testClient(t, srv.URL)

			_, completeErr := c.CompleteMultipartUpload(context.Background(), CompleteMultipartUploadInput{
				Bucket: "bucket", Key: "key", UploadID: "u", IfNoneMatch: "*",
				Parts: []CompletedPart{{PartNumber: 1, ETag: `"e"`}},
			})
			_, copyErr := c.CopyObject(context.Background(), CopyObjectInput{
				SourceBucket: "bucket", SourceKey: "key", Bucket: "bucket", Key: "key",
				SourceIfMatch: `"e"`,
			})
			for op, err := range map[string]error{"CompleteMultipartUpload": completeErr, "CopyObject": copyErr} {
				ae, ok := AsAPIError(err)
				if !ok {
					t.Fatalf("%s: got %T (%v), want *APIError", op, err, err)
				}
				if ae.StatusCode != tc.wantStatus || ae.Code != tc.code {
					t.Errorf("%s: got %d %s, want %d %s", op, ae.StatusCode, ae.Code, tc.wantStatus, tc.code)
				}
				if got, want := PreconditionFailed(err), tc.code == "PreconditionFailed"; got != want {
					t.Errorf("%s: PreconditionFailed = %t, want %t", op, got, want)
				}
			}
		})
	}
}
