package proxy

import (
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// TestTouchesReservedPrefix covers both directions a common prefix can reveal
// the gateway's own objects: a prefix under the reserved one, and a shorter one
// that a delimiter other than "/" groups them under.
func TestTouchesReservedPrefix(t *testing.T) {
	reserved := s3api.ReservedPrefix
	for prefix, want := range map[string]bool{
		"":                         false,
		reserved:                   true,
		reserved + "manifests/":    true,
		reserved[:1]:               true, // "." with delimiter "b" groups them
		reserved[:len(reserved)-1]: true,
		"backups/":                 false,
		".config/":                 false, // a dot-directory of the client's own
		strings.ToUpper(reserved):  false, // keys are case-sensitive
		reserved[:3] + "x":         false,
	} {
		if got := touchesReservedPrefix(prefix); got != want {
			t.Errorf("touchesReservedPrefix(%q) = %t, want %t", prefix, got, want)
		}
	}
}
