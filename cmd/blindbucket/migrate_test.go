package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/migrate"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// migrateJSONFields is the document's contract: every one of these, always, and
// nothing else (ADR-021, ADR-022).
var migrateJSONFields = []string{
	"bucket", "conflicted", "dry_run", "duration_seconds", "failed", "foreign",
	"migrated", "prefix", "resumed", "scanned", "started", "superseded", "too_long",
	"unconditional",
}

func TestMarshalMigrateJSON(t *testing.T) {
	started := time.Date(2026, 10, 2, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	data, err := marshalMigrateJSON(migrateRun{
		Bucket: "backups", Prefix: "photos/", DryRun: true,
		Started: started, Elapsed: 1500 * time.Millisecond,
	}, &migrate.Result{Scanned: 9, Migrated: 5, Resumed: 1, Superseded: 1, TooLong: 2})
	if err != nil {
		t.Fatalf("marshalMigrateJSON: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("the document does not end in a newline")
	}
	doc := decodeFields(t, data)
	assertFields(t, doc, migrateJSONFields)
	for field, want := range map[string]any{
		"bucket":           "backups",
		"prefix":           "photos/",
		"started":          "2026-10-02T10:00:00Z",
		"duration_seconds": 1.5,
		"dry_run":          true,
		"unconditional":    false,
		"scanned":          float64(9),
		"migrated":         float64(5),
		"resumed":          float64(1),
		"superseded":       float64(1),
		"conflicted":       float64(0),
		"too_long":         float64(2),
		"failed":           float64(0),
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
}

// TestMigrateExitStatus: exit 0 answers "is everything the gateway wrote under
// the prefix at its encrypted name?", so anything left in clear is a failure --
// conflicts and keys too long included, which nothing went wrong to produce.
// Objects the gateway did not write are not its to migrate and do not count.
func TestMigrateExitStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		result migrate.Result
		fails  bool
	}{
		"all moved":            {migrate.Result{Scanned: 3, Migrated: 2, Resumed: 1}, false},
		"foreign objects only": {migrate.Result{Scanned: 1, Foreign: 1}, false},
		"nothing to do":        {migrate.Result{}, false},
		"a conflict":           {migrate.Result{Scanned: 1, Conflicted: 1}, true},
		"a key too long":       {migrate.Result{Scanned: 1, TooLong: 1}, true},
		"a failure":            {migrate.Result{Scanned: 1, Failed: 1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			err := migrateErrors(&tc.result, false)
			if (err != nil) != tc.fails {
				t.Errorf("migrateErrors(%+v) = %v, want failure %t", tc.result, err, tc.fails)
			}
		})
	}
	if err := migrateErrors(&migrate.Result{TooLong: 1}, true); err == nil ||
		!strings.Contains(err.Error(), "would be left in clear") {
		t.Errorf("a dry run's refusal reads %v", err)
	}
}

func TestPrintMigrateNamesWhatIsLeft(t *testing.T) {
	var buf bytes.Buffer
	printMigrate(&buf, migrateRun{DryRun: true, Elapsed: time.Second},
		&migrate.Result{Scanned: 4, Migrated: 1, Resumed: 1, Foreign: 1, TooLong: 1})
	out := buf.String()
	for _, want := range []string{"4 keys in clear scanned", "would migrate:", "resumed:", "not ours:", "too long:"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "conflicted:") {
		t.Errorf("a count of zero is printed:\n%s", out)
	}
}

// withNamesEncrypted appends the names section to a configuration file.
func withNamesEncrypted(t *testing.T, cfg string) string {
	t.Helper()
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("names:\n  encrypt: true\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	return cfg
}

// TestMigrateNamesThroughTheCommand runs the command as an operator would,
// against a real provider and a real keyring, under this run's own prefix: a
// dry run before the switch, then a real run after it, over an object the
// gateway did not write -- the one kind of object a test outside the gateway
// can plant -- which is left alone and does not make the run fail.
func TestMigrateNamesThroughTheCommand(t *testing.T) {
	p := testprovider.Require(t)
	keyring := setupKeyring(t, "2026-10")
	prefix := testprovider.RunPrefix() + "migrate-cli/"
	target := "s3://" + p.Bucket + "/" + prefix

	client, err := upstream.New(upstream.Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey, SessionToken: p.SessionToken,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	if _, err := client.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: p.Bucket, Key: prefix + "foreign.txt",
		Body: strings.NewReader("not ours"), ContentLength: 8,
	}); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	t.Cleanup(func() { _ = client.DeleteObject(context.Background(), p.Bucket, prefix+"foreign.txt") })

	before := providerConfig(t, p, keyring)
	after := withNamesEncrypted(t, providerConfig(t, p, keyring))
	// Guarded where the provider allows it, so that the probe runs through the
	// command too; on Garage, unconditional, which also prints the warning.
	guard := []string{}
	if !p.MigrationGuarded() {
		guard = []string{"--allow-unconditional"}
	}

	t.Run("a real run before the switch is refused", func(t *testing.T) {
		_, _, err := runCLI(t, append([]string{"migrate-names", "--config", before}, append(guard, target)...)...)
		if !errors.Is(err, errNamesInClear) {
			t.Fatalf("got %v, want errNamesInClear", err)
		}
	})

	t.Run("a dry run before the switch", func(t *testing.T) {
		args := append([]string{"migrate-names", "--config", before, "--dry-run", "--json"}, guard...)
		stdout, stderr, err := runCLI(t, append(args, target)...)
		if err != nil {
			t.Fatalf("dry run: %v\n%s", err, stderr)
		}
		doc := decodeFields(t, []byte(stdout))
		assertFields(t, doc, migrateJSONFields)
		if doc["dry_run"] != true || doc["scanned"] != float64(1) || doc["foreign"] != float64(1) {
			t.Errorf("got %v", doc)
		}
	})

	t.Run("a real run after it", func(t *testing.T) {
		args := append([]string{"migrate-names", "--config", after}, guard...)
		stdout, stderr, err := runCLI(t, append(args, target)...)
		if err != nil {
			t.Fatalf("migrate-names: %v\n%s", err, stderr)
		}
		if !strings.Contains(stdout, "1 keys in clear scanned") || !strings.Contains(stdout, "not ours:") {
			t.Errorf("the summary reads:\n%s", stdout)
		}
		if len(guard) > 0 && !strings.Contains(stderr, "--allow-unconditional publishes without If-None-Match") {
			t.Errorf("the unconditional warning is not on stderr:\n%s", stderr)
		}
		if _, err := client.HeadObject(t.Context(), p.Bucket, prefix+"foreign.txt"); err != nil {
			t.Errorf("the foreign object was touched: %v", err)
		}
	})
}

// TestMigrateNamesNeedsTheNameKey: a keyring without a name key has nothing to
// migrate names into, and the refusal names the command that adds one. It
// comes before any request to the provider, which is a stub here.
func TestMigrateNamesNeedsTheNameKey(t *testing.T) {
	provider, _ := stubProvider(t)
	keyring := setupKeyring(t, "2026-10")
	stripKeys(t, keyring, "name_key")
	cfg := fmt.Sprintf(`
upstream: { endpoint: %q, region: us-east-1, path_style: true, access_key_id: u, secret_access_key: s }
keys: { provider: file, keyring: %q }
clients:
  - { name: t, access_key_id: T, secret_access_key: s, buckets: ["*"] }
names: { encrypt: true }
`, provider.URL, keyring)
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := runCLI(t, "migrate-names", "--config", path, "--dry-run", "s3://bucket")
	if err == nil || !strings.Contains(err.Error(), "--add-name-key") {
		t.Errorf("got %v, want a refusal naming --add-name-key", err)
	}
}

func TestMigrateNamesCommandLineMistakes(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no target":        {[]string{"migrate-names"}, ""},
		"two targets":      {[]string{"migrate-names", "s3://a", "s3://b"}, ""},
		"not an s3 url":    {[]string{"migrate-names", "https://bucket"}, "s3://"},
		"a missing config": {[]string{"migrate-names", "--config", "/nonexistent/blindbucket.yaml", "s3://bucket"}, "no such file"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runCLI(t, tc.args...)
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want == "" {
				if !errors.Is(err, errUsage) {
					t.Errorf("got %v, want the usage error", err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
