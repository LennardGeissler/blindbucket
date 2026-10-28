package proxy

import (
	"net/http"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// TestOnlyTheConditionalConflictPassesAs409: two conditional writes racing is
// the client's to retry, and the provider says so with this code. Every other
// 409 stays the gateway's own business.
func TestOnlyTheConditionalConflictPassesAs409(t *testing.T) {
	got := translateUpstream(&upstream.APIError{
		StatusCode: http.StatusConflict, Code: "ConditionalRequestConflict", Message: "retry",
	})
	if got.HTTPStatus != http.StatusConflict || got.Code != "ConditionalRequestConflict" {
		t.Errorf("a conditional conflict became %d %s", got.HTTPStatus, got.Code)
	}
	got = translateUpstream(&upstream.APIError{StatusCode: http.StatusConflict, Code: "OperationAborted"})
	if got.HTTPStatus != http.StatusBadGateway {
		t.Errorf("another 409 became %d %s, want 502", got.HTTPStatus, got.Code)
	}
}

// TestABucketsConflictIsTheClients: the 409s of bucket requests are the
// provider's answer about the bucket, and a client acts on them; any other 409
// stays a 502 (#194).
func TestABucketsConflictIsTheClients(t *testing.T) {
	for _, code := range []string{"BucketAlreadyOwnedByYou", "BucketAlreadyExists", "BucketNotEmpty"} {
		got := translateUpstream(&upstream.APIError{StatusCode: http.StatusConflict, Code: code, Message: "m"})
		if got.HTTPStatus != http.StatusConflict || got.Code != code {
			t.Errorf("%s became %d %s", code, got.HTTPStatus, got.Code)
		}
	}
	if got := translateUpstream(&upstream.APIError{StatusCode: http.StatusConflict, Code: "OperationAborted"}); got.HTTPStatus != http.StatusBadGateway {
		t.Errorf("another 409 became %d, want 502", got.HTTPStatus)
	}
}
