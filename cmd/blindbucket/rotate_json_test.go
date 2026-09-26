package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/rotate"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// rotateJSONFields is the document's contract: every one of these, always, and
// nothing else.
var rotateJSONFields = []string{
	"already_current", "bucket", "conflicted", "dry_run", "duration_seconds",
	"failed", "foreign", "prefix", "rotated", "scanned", "started", "target_kid",
	"unconditional",
}

func TestMarshalRotateJSON(t *testing.T) {
	started := time.Date(2026, 9, 26, 3, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	data, err := marshalRotateJSON(rotateRun{
		Bucket: "backups", Prefix: "photos/", TargetKID: "2026-10", DryRun: true,
		Started: started, Elapsed: 250 * time.Millisecond,
	}, &rotate.Result{Scanned: 5, Rotated: 3, AlreadyCurrent: 2})
	if err != nil {
		t.Fatalf("marshalRotateJSON: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("the document does not end in a newline")
	}
	doc := decodeFields(t, data)
	assertFields(t, doc, rotateJSONFields)

	for field, want := range map[string]any{
		"target_kid":       "2026-10",
		"started":          "2026-09-26T01:00:00Z",
		"duration_seconds": 0.25,
		"dry_run":          true,
		"unconditional":    false,
		"rotated":          float64(3),
		"conflicted":       float64(0),
		"foreign":          float64(0),
		"failed":           float64(0),
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
}

// TestRotateJSONThroughTheCommand runs `rotate --json` as a user would, against
// a real provider and a real keyring. Always a dry run under this run's own
// prefix, and with --allow-unconditional so that it runs on every provider,
// Garage included -- which also makes the command print a warning, the stderr
// line that must stay off stdout.
func TestRotateJSONThroughTheCommand(t *testing.T) {
	p := testprovider.Require(t)
	keyring := setupKeyring(t, "2026-09")
	cfg := providerConfig(t, p, keyring)
	target := "s3://" + p.Bucket + "/" + testprovider.RunPrefix() + "rotate-json/"

	rotateCmd := func(t *testing.T, extra ...string) (stdout, stderr string) {
		t.Helper()
		args := append([]string{"rotate", "--config", cfg, "--dry-run", "--allow-unconditional"}, extra...)
		var runErr error
		stderr = captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				runErr = run(t.Context(), append(args, target))
			})
		})
		if runErr != nil {
			t.Fatalf("rotate %v: %v\nstderr: %s", extra, runErr, stderr)
		}
		return stdout, stderr
	}

	t.Run("json", func(t *testing.T) {
		stdout, stderr := rotateCmd(t, "--json")
		doc := decodeFields(t, []byte(stdout))
		assertFields(t, doc, rotateJSONFields)
		if doc["target_kid"] != "2026-09" || doc["dry_run"] != true || doc["unconditional"] != true {
			t.Errorf("target_kid %v, dry_run %v, unconditional %v",
				doc["target_kid"], doc["dry_run"], doc["unconditional"])
		}
		if _, err := time.Parse(time.RFC3339, fmt.Sprint(doc["started"])); err != nil {
			t.Errorf("started %v is not RFC 3339: %v", doc["started"], err)
		}
		if !strings.Contains(stderr, "--allow-unconditional writes without If-Match") {
			t.Errorf("the unconditional warning is not on stderr:\n%s", stderr)
		}
	})

	t.Run("text is unchanged", func(t *testing.T) {
		stdout, _ := rotateCmd(t)
		if !strings.Contains(stdout, "objects scanned in") || !strings.Contains(stdout, `would rotate:`) {
			t.Errorf("the text summary changed:\n%s", stdout)
		}
		if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
			t.Errorf("the text path printed JSON:\n%s", stdout)
		}
	})
}
