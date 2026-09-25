package rotate

import (
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/probe"
)

// The refusal is the one thing an operator sees, so it has to name the missing
// guard, leave out the one that held, and say what to do.
func TestUnguardedErrorNamesWhatIsMissing(t *testing.T) {
	err := &UnguardedError{Bucket: "backups", Conditions: probe.Conditions{
		CopySourceIfMatch: probe.Check{Name: "x-amz-copy-source-if-match on UploadPartCopy", Outcome: probe.Enforced},
		CompleteIfMatch:   probe.Check{Name: "If-Match on CompleteMultipartUpload", Outcome: probe.Ignored},
	}}
	msg := err.Error()
	for _, want := range []string{"backups", "If-Match on CompleteMultipartUpload: ignored", "--allow-unconditional"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "x-amz-copy-source-if-match") {
		t.Errorf("the refusal lists a guard that held:\n%s", msg)
	}
}
