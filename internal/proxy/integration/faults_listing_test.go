package integration

import (
	"encoding/xml"
	"net/http"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// The same provider refusal is client input only when the listing query was
// forwarded. Name encryption builds a different query and keeps the gateway
// error instead (ADR-027).
func TestFaultListingBadRequest(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name, wantStatus, wantCode := "plaintext", http.StatusBadRequest, "ProviderSpecificArgument"
		if encrypted {
			name, wantStatus, wantCode = "encrypted", http.StatusBadGateway, "InternalError"
		}
		t.Run(name, func(t *testing.T) {
			f := newFaultyProvider(t)
			options := []any{f.option(t)}
			if encrypted {
				option, _ := proxytest.WithEncryptedNames(t)
				options = append(options, option)
			}
			h := proxytest.New(t, options...)
			rule := f.fail(&fault{match: func(r *http.Request) bool {
				return r.Method == http.MethodGet && r.URL.Query().Has("list-type")
			}, status: http.StatusBadRequest, code: "ProviderSpecificArgument"})
			status, body, _ := listQuery(t, h, "list-type=2&prefix=docs/")
			var result struct{ Code, Message string }
			if err := xml.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("error document: %v", err)
			}
			if status != wantStatus || result.Code != wantCode {
				t.Fatalf("listing returned %d %s: %s; want %d %s", status, result.Code, body, wantStatus, wantCode)
			}
			if encrypted && result.Message == "injected by the test" {
				t.Error("encrypted listing forwarded the provider's message")
			}
			if !encrypted && result.Message != "injected by the test" {
				t.Errorf("plaintext message = %q, want the provider's message", result.Message)
			}
			if got := f.hits(rule); got != 1 {
				t.Errorf("injected provider requests = %d, want 1", got)
			}
		})
	}
}
