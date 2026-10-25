package proxytest

import (
	"encoding/xml"
	"io"
	"net/http"
	"sort"
	"testing"
)

// Tags returns an object's tags as the gateway answers GetObjectTagging, each
// as key=value, sorted, and fails the test unless the answer is a 200.
func (h *Harness) Tags(t *testing.T, key string) []string {
	t.Helper()
	resp := h.Do(t, http.MethodGet, key+"?tagging")
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetObjectTagging %s: %d %s", key, resp.StatusCode, raw)
	}
	var doc struct {
		Tags []struct{ Key, Value string } `xml:"TagSet>Tag"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the Tagging answer does not parse: %v", err)
	}
	out := []string{}
	for _, tag := range doc.Tags {
		out = append(out, tag.Key+"="+tag.Value)
	}
	sort.Strings(out)
	return out
}
