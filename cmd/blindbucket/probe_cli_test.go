package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// TestProbeThroughTheCommand runs `blindbucket probe` against the provider under
// test and holds its verdict to what the provider profile says it enforces --
// exit status included, since the command exists so that a script can ask.
func TestProbeThroughTheCommand(t *testing.T) {
	p := testprovider.Require(t)
	cfg := providerConfig(t, p, "unused-keyring.json")
	target := "s3://" + p.Bucket

	stdout, _, err := runCLI(t, "probe", "--config", cfg, "--json", target)
	if p.Guarded() {
		if err != nil {
			t.Fatalf("a guarded provider was reported unguarded: %v\n%s", err, stdout)
		}
	} else if !errors.Is(err, errUnguarded) {
		t.Fatalf("got %v, want errUnguarded for a provider that ignores a condition\n%s", err, stdout)
	}

	var doc struct {
		Bucket  string `json:"bucket"`
		Guarded bool   `json:"guarded"`
		Checks  []struct {
			Outcome string `json:"outcome"`
		} `json:"checks"`
		Migration struct {
			Guarded bool `json:"guarded"`
		} `json:"migration"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("--json did not print JSON: %v\n%s", err, stdout)
	}
	if doc.Bucket != p.Bucket || doc.Guarded != p.Guarded() || len(doc.Checks) != 2 {
		t.Errorf("got %+v for a provider with guarded=%t", doc, p.Guarded())
	}
	if doc.Migration.Guarded != p.MigrationGuarded() {
		t.Errorf("migration guarded = %t for a provider stated as %t",
			doc.Migration.Guarded, p.MigrationGuarded())
	}

	// The human form says the same thing in words.
	text, _, _ := runCLI(t, "probe", "--config", cfg, target)
	if !strings.Contains(text, "If-Match on CompleteMultipartUpload") {
		t.Errorf("the text output does not name the checks:\n%s", text)
	}
}

func TestProbeCommandLineMistakes(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no target":        {[]string{"probe"}, ""},
		"a prefix":         {[]string{"probe", "s3://bucket/some/prefix"}, "not a prefix"},
		"not an s3 url":    {[]string{"probe", "https://bucket"}, "s3://"},
		"a missing config": {[]string{"probe", "--config", "/nonexistent/blindbucket.yaml", "s3://bucket"}, "no such file"},
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
