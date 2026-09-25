package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/probe"
)

// What Garage v2.4.1 answers, which is the case the output exists for.
var garageConditions = probe.Conditions{
	CopySourceIfMatch: probe.Check{Name: "x-amz-copy-source-if-match on UploadPartCopy", Outcome: probe.Enforced},
	CompleteIfMatch:   probe.Check{Name: "If-Match on CompleteMultipartUpload", Outcome: probe.Ignored},
}

func TestMarshalProbeJSON(t *testing.T) {
	data, err := marshalProbeJSON("backups", garageConditions)
	if err != nil {
		t.Fatalf("marshalProbeJSON: %v", err)
	}
	var got struct {
		Bucket string `json:"bucket"`
		Checks []struct {
			Name    string `json:"name"`
			Outcome string `json:"outcome"`
		} `json:"checks"`
		Guarded bool `json:"guarded"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, data)
	}
	if got.Bucket != "backups" || got.Guarded || len(got.Checks) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got.Checks[1].Outcome != "ignored" {
		t.Errorf("completion outcome %q, want ignored", got.Checks[1].Outcome)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Error("the document does not end in a newline")
	}
}

func TestPrintProbeSaysWhatRotationWillDo(t *testing.T) {
	var buf bytes.Buffer
	printProbe(&buf, "backups", garageConditions)
	out := buf.String()
	for _, want := range []string{"If-Match on CompleteMultipartUpload", "ignored", "--allow-unconditional"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}
}
