package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeKeyListRing struct {
	kids    []string
	created map[string]time.Time
	active  string
}

func (r fakeKeyListRing) KIDs() []string { return r.kids }
func (r fakeKeyListRing) Created(kid string) (time.Time, bool) {
	t, ok := r.created[kid]
	return t, ok
}
func (r fakeKeyListRing) ActiveKID() string { return r.active }

func TestMarshalKeysJSON(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.FixedZone("IST", 5*60*60+30*60))
	created := now.Add(-25 * time.Hour)
	ring := fakeKeyListRing{
		kids:    []string{"2026-09", "legacy"},
		created: map[string]time.Time{"2026-09": created},
		active:  "2026-09",
	}

	data, err := marshalKeysJSON(now, ring)
	if err != nil {
		t.Fatalf("marshalKeysJSON: %v", err)
	}

	var got struct {
		Keys []struct {
			KID        string  `json:"kid"`
			Created    *string `json:"created"`
			AgeSeconds *int64  `json:"age_seconds"`
			Active     bool    `json:"active"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.Keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(got.Keys))
	}
	if got.Keys[0].KID != "2026-09" || !got.Keys[0].Active {
		t.Errorf("active entry = %+v", got.Keys[0])
	}
	expectedCreated := created.UTC().Format(time.RFC3339)
	if got.Keys[0].Created == nil || *got.Keys[0].Created != expectedCreated {
		t.Errorf("created = %v, want %s", got.Keys[0].Created, expectedCreated)
	}
	if got.Keys[0].AgeSeconds == nil || *got.Keys[0].AgeSeconds != 90000 {
		t.Errorf("age_seconds = %v, want 90000", got.Keys[0].AgeSeconds)
	}
	if got.Keys[1].Created != nil || got.Keys[1].AgeSeconds != nil || got.Keys[1].Active {
		t.Errorf("unknown inactive entry = %+v", got.Keys[1])
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("JSON output is missing its trailing newline")
	}
}

// TestKeysListThroughTheCommand runs `keys list` as a user would and looks at
// both streams. TestMarshalKeysJSON pins the document's shape; this pins that
// --json reaches it, that stdout carries that document and nothing else, and
// that the warnings which may precede it stay on stderr.
func TestKeysListThroughTheCommand(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	// World-readable, so opening it warns: the one stderr line every keyring
	// can be made to produce.
	if err := os.Chmod(keyring, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	list := func(t *testing.T, extra ...string) (stdout, stderr string) {
		t.Helper()
		var runErr error
		stderr = captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				runErr = run(t.Context(), append([]string{"keys", "list", "--keyring", keyring}, extra...))
			})
		})
		if runErr != nil {
			t.Fatalf("keys list %v: %v\nstderr: %s", extra, runErr, stderr)
		}
		return stdout, stderr
	}

	t.Run("json", func(t *testing.T) {
		stdout, stderr := list(t, "--json")

		// The whole of stdout, so a stray line anywhere in it fails.
		var doc struct {
			Keys []struct {
				KID    string `json:"kid"`
				Active bool   `json:"active"`
			} `json:"keys"`
		}
		dec := json.NewDecoder(strings.NewReader(stdout))
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("stdout is not the key-list document: %v\n%s", err, stdout)
		}
		if rest, _ := io.ReadAll(dec.Buffered()); strings.TrimSpace(string(rest)) != "" || dec.More() {
			t.Fatalf("stdout carries more than one document:\n%s", stdout)
		}
		if len(doc.Keys) != 1 || doc.Keys[0].KID != "2026-09" || !doc.Keys[0].Active {
			t.Errorf("document lists %+v, want the one active key", doc.Keys)
		}

		if !strings.Contains(stderr, "readable beyond its owner") {
			t.Errorf("the permission warning is not on stderr:\n%s", stderr)
		}
		if strings.Contains(stdout, "warning") {
			t.Errorf("a warning reached stdout:\n%s", stdout)
		}
	})

	t.Run("table", func(t *testing.T) {
		stdout, stderr := list(t)

		lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("the table has %d lines, want a header and one key:\n%s", len(lines), stdout)
		}
		if fields := strings.Fields(lines[0]); strings.Join(fields, " ") != "KEY ID CREATED AGE" {
			t.Errorf("header is %q", lines[0])
		}
		row := strings.Fields(lines[1])
		if len(row) != 4 || row[0] != "2026-09" || row[3] != "active" {
			t.Errorf("row is %q, want the key id, its creation time, its age and \"active\"", lines[1])
		}
		if _, err := time.Parse(time.RFC3339, row[1]); err != nil {
			t.Errorf("created column %q is not RFC 3339: %v", row[1], err)
		}
		if !strings.Contains(stderr, "readable beyond its owner") || strings.Contains(stdout, "warning") {
			t.Errorf("the warning is not on stderr alone:\nstdout: %s\nstderr: %s", stdout, stderr)
		}
	})
}
