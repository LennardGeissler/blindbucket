package probe

import "testing"

func TestSafeNeedsBothEnforced(t *testing.T) {
	for _, c := range []struct {
		copySource, complete Outcome
		want                 bool
	}{
		{Enforced, Enforced, true},
		{Enforced, Ignored, false},
		{Ignored, Enforced, false},
		{Enforced, Refused, false},
		{Refused, Refused, false},
	} {
		got := Conditions{
			CopySourceIfMatch: Check{Outcome: c.copySource},
			CompleteIfMatch:   Check{Outcome: c.complete},
		}.Safe()
		if got != c.want {
			t.Errorf("copy source %s, completion %s: Safe() = %v, want %v",
				c.copySource, c.complete, got, c.want)
		}
	}
}
