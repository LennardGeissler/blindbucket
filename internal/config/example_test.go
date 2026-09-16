package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestShippedExampleLoads reads blindbucket.example.yaml, the file the README
// points at and that operators copy.
//
// It is a document, and an undetected mistake in it is a mistake every reader
// inherits. The decoder runs with KnownFields(true), so a key that no longer
// exists -- or one written at the wrong nesting -- is a startup error rather
// than a setting quietly ignored, and there was nothing checking that the
// example stayed on the right side of that. Two bugs this would have caught on
// its own: a `presign:` block written as a second top-level `server:` key, and
// any renamed field the example was not updated for.
func TestShippedExampleLoads(t *testing.T) {
	for k, v := range map[string]string{
		"UPSTREAM_ACCESS_KEY_ID":     "example-upstream-key",
		"UPSTREAM_SECRET_ACCESS_KEY": "example-upstream-secret",
		"BB_ACCESS_KEY_ID":           "example-client-key",
		"BB_SECRET_ACCESS_KEY":       "example-client-secret",
	} {
		t.Setenv(k, v)
	}

	path := filepath.Join("..", "..", "blindbucket.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the example config is not where the README says it is: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("the shipped example config does not load: %v", err)
	}

	// Spot-check the settings the example exists to demonstrate, so that a field
	// renamed out from under it fails here rather than in someone's deployment.
	if cfg.Server.Listen == "" {
		t.Error("the example sets no listen address")
	}
	if !cfg.Server.Presign.Enabled {
		t.Error("the example turns presigned URLs off; the default is on")
	}
	expiry, err := cfg.Server.Presign.Expiry()
	if err != nil {
		t.Fatalf("the example's presign.max_expiry does not parse: %v", err)
	}
	if expiry != time.Hour {
		t.Errorf("the example's presign.max_expiry is %s, want the documented 1h", expiry)
	}
}
