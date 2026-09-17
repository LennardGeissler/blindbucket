package main

import (
	"encoding/json"
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
