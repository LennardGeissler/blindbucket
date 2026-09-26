package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/gc"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// gcJSONFields is the document's contract: every one of these, always, and
// nothing else.
var gcJSONFields = []string{
	"bucket", "deleted", "dry_run", "duration_seconds", "errors", "keys_scanned",
	"keys_skipped", "kept_current", "kept_too_new", "kept_unreadable",
	"manifests_seen", "prefix", "started",
}

func decodeFields(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("not a JSON document: %v\n%s", err, data)
	}
	if dec.More() {
		t.Fatalf("more than one document:\n%s", data)
	}
	return doc
}

func assertFields(t *testing.T, doc map[string]any, want []string) {
	t.Helper()
	got := make([]string, 0, len(doc))
	for k := range doc {
		got = append(got, k)
	}
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("fields are %v, want %v", got, want)
	}
}

func TestMarshalGCJSON(t *testing.T) {
	started := time.Date(2026, 9, 26, 3, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	data, err := marshalGCJSON(gcRun{
		Bucket: "backups", Prefix: "", DryRun: true,
		Started: started, Elapsed: 1532 * time.Millisecond,
	}, &gc.Result{ManifestsSeen: 7, KeysScanned: 3, Deleted: 2, KeptCurrent: 1})
	if err != nil {
		t.Fatalf("marshalGCJSON: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("the document does not end in a newline")
	}
	doc := decodeFields(t, data)
	// The zero counts are the point: a parser must never have to tell zero
	// from absent.
	assertFields(t, doc, gcJSONFields)

	for field, want := range map[string]any{
		"started":          "2026-09-26T01:00:00Z",
		"duration_seconds": 1.532,
		"dry_run":          true,
		"deleted":          float64(2),
		"keys_skipped":     float64(0),
		"kept_unreadable":  float64(0),
		"errors":           float64(0),
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
}

// gcConfig writes a configuration pointing at the provider under test. gc
// reads the upstream section and nothing that needs a keyring.
func gcConfig(t *testing.T, p testprovider.Provider) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	yaml := fmt.Sprintf(`server:
  listen: "127.0.0.1:0"
upstream:
  endpoint: %s
  region: %s
  path_style: %t
  access_key_id: %s
  secret_access_key: %s
  session_token: %q
keys:
  provider: file
  keyring: keyring.json
clients:
  - name: gc-test
    access_key_id: GCTESTKEY
    secret_access_key: gc-test-secret-key
    buckets: [%q]
`, p.Endpoint, p.Region, p.PathStyle, p.AccessKey, p.SecretKey, p.SessionToken, p.Bucket)
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing the config: %v", err)
	}
	return path
}

// TestGCJSONThroughTheCommand runs `gc --json` as a user would, against a
// real provider. Always a dry run, and always under this run's own prefix: a gc
// over a shared test bucket would otherwise act on other runs' objects.
func TestGCJSONThroughTheCommand(t *testing.T) {
	p := testprovider.Require(t)
	cfg := gcConfig(t, p)
	target := "s3://" + p.Bucket + "/" + testprovider.RunPrefix() + "gc-json/"

	gcCmd := func(t *testing.T, extra ...string) (stdout, stderr string) {
		t.Helper()
		var runErr error
		stderr = captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				runErr = run(t.Context(), append(append([]string{"gc", "--config", cfg, "--dry-run"}, extra...), target))
			})
		})
		if runErr != nil {
			t.Fatalf("gc %v: %v\nstderr: %s", extra, runErr, stderr)
		}
		return stdout, stderr
	}

	t.Run("json", func(t *testing.T) {
		stdout, _ := gcCmd(t, "--json")
		doc := decodeFields(t, []byte(stdout))
		assertFields(t, doc, gcJSONFields)
		if doc["dry_run"] != true || doc["bucket"] != p.Bucket {
			t.Errorf("dry_run %v, bucket %v", doc["dry_run"], doc["bucket"])
		}
		if _, err := time.Parse(time.RFC3339, fmt.Sprint(doc["started"])); err != nil {
			t.Errorf("started %v is not RFC 3339: %v", doc["started"], err)
		}
	})

	t.Run("text is unchanged", func(t *testing.T) {
		stdout, _ := gcCmd(t)
		if !strings.Contains(stdout, "manifests seen across") || !strings.Contains(stdout, "would delete:") {
			t.Errorf("the text summary changed:\n%s", stdout)
		}
		if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
			t.Errorf("the text path printed JSON:\n%s", stdout)
		}
	})
}
