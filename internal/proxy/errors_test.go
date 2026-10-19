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
	got = translateUpstream(&upstream.APIError{StatusCode: http.StatusConflict, Code: "BucketNotEmpty"})
	if got.HTTPStatus != http.StatusBadGateway {
		t.Errorf("another 409 became %d %s, want 502", got.HTTPStatus, got.Code)
	}
}
