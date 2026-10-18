package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/encrypt"
	"github.com/LennardGeissler/blindbucket/internal/objectmeta"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// encryptJSONFields is the document's contract: every one of these, always, and
// nothing else (ADR-021, ADR-034).
var encryptJSONFields = []string{
	"bucket", "bytes_encrypted", "conflicted", "dry_run", "duration_seconds", "encrypted",
	"failed", "locked", "names_encrypted", "needs_name_migration", "obsolete", "prefix",
	"scanned", "skipped", "started", "tagged", "too_long", "unconditional", "unreadable",
}

func TestMarshalEncryptJSON(t *testing.T) {
	started := time.Date(2026, 10, 18, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	data, err := marshalEncryptJSON(encryptRun{
		Bucket: "nextcloud", Prefix: "urn:oid:", DryRun: true, NamesEncrypted: true,
		Started: started, Elapsed: 1500 * time.Millisecond,
	}, &encrypt.Result{Scanned: 9, Encrypted: 5, Obsolete: 1, Skipped: 2, Tagged: 1, BytesEncrypted: 4096})
	if err != nil {
		t.Fatalf("marshalEncryptJSON: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("the document does not end in a newline")
	}
	doc := decodeFields(t, data)
	assertFields(t, doc, encryptJSONFields)
	for field, want := range map[string]any{
		"bucket":           "nextcloud",
		"prefix":           "urn:oid:",
		"started":          "2026-10-18T10:00:00Z",
		"duration_seconds": 1.5,
		"dry_run":          true,
		"unconditional":    false,
		"names_encrypted":  true,
		"scanned":          float64(9),
		"encrypted":        float64(5),
		"obsolete":         float64(1),
		"skipped":          float64(2),
		"tagged":           float64(1),
		"conflicted":       float64(0),
		"bytes_encrypted":  float64(4096),
	} {
		if doc[field] != want {
			t.Errorf("%s = %v, want %v", field, doc[field], want)
		}
	}
}

// TestEncryptExitStatus: exit 0 answers "is any plaintext left under the
// prefix?", so every object a run leaves unencrypted fails it, whatever the
// reason; objects the gateway wrote, and plaintext made obsolete, do not.
func TestEncryptExitStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		result encrypt.Result
		fails  bool
	}{
		"all encrypted":         {encrypt.Result{Scanned: 3, Encrypted: 2, Obsolete: 1}, false},
		"gateway objects only":  {encrypt.Result{Scanned: 1, Skipped: 1}, false},
		"nothing to do":         {encrypt.Result{}, false},
		"a conflict":            {encrypt.Result{Scanned: 1, Conflicted: 1}, true},
		"one for migrate-names": {encrypt.Result{Scanned: 1, NeedsNameMigration: 1}, true},
		"a key too long":        {encrypt.Result{Scanned: 1, TooLong: 1}, true},
		"a tagged object":       {encrypt.Result{Scanned: 1, Tagged: 1}, true},
		"a locked object":       {encrypt.Result{Scanned: 1, Locked: 1}, true},
		"an unreadable object":  {encrypt.Result{Scanned: 1, Unreadable: 1}, true},
		"a failure":             {encrypt.Result{Scanned: 1, Failed: 1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := encryptErrors(&tc.result, false); (err != nil) != tc.fails {
				t.Errorf("encryptErrors(%+v) = %v, want failure %t", tc.result, err, tc.fails)
			}
		})
	}
	if err := encryptErrors(&encrypt.Result{Tagged: 1}, true); err == nil ||
		!strings.Contains(err.Error(), "would be left unencrypted") {
		t.Errorf("a dry run's refusal reads %v", err)
	}
}

func TestPrintEncryptSaysWhatIsLeft(t *testing.T) {
	var buf bytes.Buffer
	printEncrypt(&buf, encryptRun{DryRun: true, Elapsed: time.Second},
		&encrypt.Result{Scanned: 4, Encrypted: 1, Skipped: 1, Tagged: 1, Locked: 1, BytesEncrypted: 10})
	out := buf.String()
	for _, want := range []string{"4 keys scanned", "would encrypt:", "(10 bytes)", "tagged:", "locked:",
		"written by the gateway:"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "conflicted:") {
		t.Errorf("a count of zero is printed:\n%s", out)
	}
}

// TestEncryptExistingThroughTheCommand runs the command as an operator would,
// against a real provider and a real keyring, under this run's own prefix: a
// dry run that changes nothing, then a run that leaves the object carrying the
// gateway's envelope.
func TestEncryptExistingThroughTheCommand(t *testing.T) {
	p := testprovider.Require(t)
	keyring := setupKeyring(t, "2026-10")
	prefix := testprovider.RunPrefix() + "encrypt-cli/"
	target := "s3://" + p.Bucket + "/" + prefix
	key := prefix + "before-the-gateway.txt"

	client, err := upstream.New(upstream.Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey, SessionToken: p.SessionToken,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	if _, err := client.PutObject(t.Context(), upstream.PutObjectInput{
		Bucket: p.Bucket, Key: key, Body: strings.NewReader("stored in clear"), ContentLength: 15,
	}); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	t.Cleanup(func() { _ = client.DeleteObject(context.Background(), p.Bucket, key) })

	cfg := providerConfig(t, p, keyring)
	// Guarded where the provider allows it, so that the probe runs through the
	// command too; on Garage, unconditional, which also prints the warning.
	guard := []string{}
	if p.CompleteIfMatch != "enforced" {
		guard = []string{"--allow-unconditional"}
	}
	envelope := func() bool {
		info, err := client.HeadObject(t.Context(), p.Bucket, key)
		if err != nil {
			t.Fatalf("HEAD: %v", err)
		}
		_, err = objectmeta.Parse(info.Metadata, 16)
		return err == nil
	}

	t.Run("a dry run", func(t *testing.T) {
		args := append([]string{"encrypt-existing", "--config", cfg, "--dry-run", "--json"}, guard...)
		stdout, stderr, err := runCLI(t, append(args, target)...)
		if err != nil {
			t.Fatalf("dry run: %v\n%s", err, stderr)
		}
		doc := decodeFields(t, []byte(stdout))
		assertFields(t, doc, encryptJSONFields)
		if doc["dry_run"] != true || doc["encrypted"] != float64(1) || doc["bytes_encrypted"] != float64(15) {
			t.Errorf("got %v", doc)
		}
		if envelope() {
			t.Error("the dry run encrypted the object")
		}
	})

	t.Run("a real run", func(t *testing.T) {
		args := append([]string{"encrypt-existing", "--config", cfg}, guard...)
		stdout, stderr, err := runCLI(t, append(args, target)...)
		if err != nil {
			t.Fatalf("encrypt-existing: %v\n%s", err, stderr)
		}
		if !strings.Contains(stdout, "encrypted:") || !strings.Contains(stdout, "(15 bytes)") {
			t.Errorf("the summary reads:\n%s", stdout)
		}
		if len(guard) > 0 && !strings.Contains(stderr, "--allow-unconditional writes without") {
			t.Errorf("the unconditional warning is not on stderr:\n%s", stderr)
		}
		if !envelope() {
			t.Error("the object does not carry the gateway's envelope after the run")
		}
	})
}
