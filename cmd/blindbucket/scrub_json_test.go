package main

import (
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/scrub"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/verify"
)

// scrubJSONFields is the document's contract under ADR-021: every one of these,
// always.
var scrubJSONFields = []string{
	"bucket", "prefix", "started", "duration_seconds",
	"scanned", "verified", "failed", "unreadable", "foreign", "vanished",
	"ciphertext_bytes", "findings", "unreadable_objects",
}

func TestMarshalScrubJSON(t *testing.T) {
	started := time.Date(2026, 10, 11, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	run := scrubRun{Bucket: "backups", Prefix: "photos/", Started: started, Elapsed: 2500 * time.Millisecond}

	t.Run("a clean run has an empty array, not a null", func(t *testing.T) {
		data, err := marshalScrubJSON(run, &scrub.Result{Scanned: 3, Verified: 3, CipherBytes: 4096})
		if err != nil {
			t.Fatalf("marshalScrubJSON: %v", err)
		}
		if !strings.HasSuffix(string(data), "\n") {
			t.Error("the document does not end in a newline")
		}
		doc := decodeFields(t, data)
		assertFields(t, doc, scrubJSONFields)
		for field, want := range map[string]any{
			"bucket": "backups", "prefix": "photos/", "started": "2026-10-11T10:00:00Z",
			"duration_seconds": 2.5, "scanned": float64(3), "verified": float64(3),
			"failed": float64(0), "unreadable": float64(0), "foreign": float64(0),
			"vanished": float64(0), "ciphertext_bytes": float64(4096),
		} {
			if doc[field] != want {
				t.Errorf("%s = %v, want %v", field, doc[field], want)
			}
		}
		for _, list := range []string{"findings", "unreadable_objects"} {
			if items, ok := doc[list].([]any); !ok || len(items) != 0 {
				t.Errorf("%s = %#v, want []", list, doc[list])
			}
		}
	})

	t.Run("a finding carries its key, kind and detail; an unreadable object its key", func(t *testing.T) {
		data, err := marshalScrubJSON(run, &scrub.Result{
			Scanned: 3, Verified: 1, Failed: 1, Errors: 1,
			Findings:   []scrub.Finding{{Key: "photos/a.jpg", Kind: verify.KindChunk, Detail: "stream: chunk 3"}},
			Unreadable: []scrub.Unreadable{{Key: "photos/b.jpg", Detail: "short read"}},
		})
		if err != nil {
			t.Fatalf("marshalScrubJSON: %v", err)
		}
		findings, _ := decodeFields(t, data)["findings"].([]any)
		if len(findings) != 1 {
			t.Fatalf("findings = %#v, want one", findings)
		}
		f, _ := findings[0].(map[string]any)
		if f["key"] != "photos/a.jpg" || f["kind"] != "chunk" || f["detail"] != "stream: chunk 3" {
			t.Errorf("finding = %#v", f)
		}
		unreadable, _ := decodeFields(t, data)["unreadable_objects"].([]any)
		if len(unreadable) != 1 {
			t.Fatalf("unreadable_objects = %#v, want one", unreadable)
		}
		if u, _ := unreadable[0].(map[string]any); u["key"] != "photos/b.jpg" || u["detail"] != "short read" {
			t.Errorf("unreadable object = %#v", u)
		}
	})
}

// TestScrubJSONThroughTheCommand: an empty prefix on a real provider, through
// the command as an operator runs it -- the configuration, the keyring and the
// document on stdout.
func TestScrubJSONThroughTheCommand(t *testing.T) {
	p := testprovider.Require(t)
	keyring := setupKeyring(t, "2026-10")
	cfg := providerConfig(t, p, keyring)
	target := "s3://" + p.Bucket + "/" + testprovider.RunPrefix() + "scrub-empty/"

	stdout, _, err := runCLI(t, "scrub", "--config", cfg, "--json", target)
	if err != nil {
		t.Fatalf("scrub --json: %v", err)
	}
	doc := decodeFields(t, []byte(stdout))
	assertFields(t, doc, scrubJSONFields)
	if doc["scanned"] != float64(0) || doc["failed"] != float64(0) {
		t.Errorf("an empty prefix reports scanned %v, failed %v", doc["scanned"], doc["failed"])
	}
}
