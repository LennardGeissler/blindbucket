package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/probe"
)

// What Garage v2.4.1 answers, which is the case the output exists for.
var garageConditions = probe.Conditions{
	CopySourceIfMatch:   probe.Check{Name: "x-amz-copy-source-if-match on UploadPartCopy", Outcome: probe.Enforced},
	CompleteIfMatch:     probe.Check{Name: "If-Match on CompleteMultipartUpload", Outcome: probe.Ignored},
	CompleteIfNoneMatch: probe.Check{Name: "If-None-Match on CompleteMultipartUpload", Outcome: probe.Ignored},
}

func TestMarshalProbeJSON(t *testing.T) {
	data, err := marshalProbeJSON("backups", garageConditions)
	if err != nil {
		t.Fatalf("marshalProbeJSON: %v", err)
	}
	type check struct {
		Name    string `json:"name"`
		Outcome string `json:"outcome"`
	}
	var got struct {
		Bucket    string  `json:"bucket"`
		Checks    []check `json:"checks"`
		Guarded   bool    `json:"guarded"`
		Migration struct {
			Checks  []check `json:"checks"`
			Guarded bool    `json:"guarded"`
		} `json:"migration"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, data)
	}
	// checks and guarded are about rotation, exactly as in 1.0 (ADR-021): the
	// migration's condition must not appear among them.
	if got.Bucket != "backups" || got.Guarded || len(got.Checks) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got.Checks[1].Outcome != "ignored" {
		t.Errorf("completion outcome %q, want ignored", got.Checks[1].Outcome)
	}
	if got.Migration.Guarded || len(got.Migration.Checks) != 1 ||
		got.Migration.Checks[0].Name != "If-None-Match on CompleteMultipartUpload" {
		t.Errorf("migration = %+v", got.Migration)
	}

	// The exact field set: a field is never removed or renamed (ADR-021).
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	var names []string
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	if want := []string{"bucket", "checks", "guarded", "migration"}; !slices.Equal(names, want) {
		t.Errorf("fields %v, want %v", names, want)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Error("the document does not end in a newline")
	}
}

func TestPrintProbeSaysWhatRotationWillDo(t *testing.T) {
	var buf bytes.Buffer
	printProbe(&buf, "backups", garageConditions)
	out := buf.String()
	for _, want := range []string{
		"If-Match on CompleteMultipartUpload", "If-None-Match on CompleteMultipartUpload",
		"ignored", "rotation: refused without --allow-unconditional",
		"migrate-names: refused without --allow-unconditional",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}
}
