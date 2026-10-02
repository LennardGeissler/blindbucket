package probe

import "testing"

func TestSafeForRotationNeedsBothEnforced(t *testing.T) {
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
			// Ignored on purpose: the migration's guard must not move a
			// rotation's verdict either way.
			CompleteIfNoneMatch: Check{Outcome: Ignored},
		}.SafeForRotation()
		if got != c.want {
			t.Errorf("copy source %s, completion %s: SafeForRotation() = %v, want %v",
				c.copySource, c.complete, got, c.want)
		}
	}
}

// TestSafeForMigrationNeedsOnlyTheCreateGuard holds the migration's verdict to
// the one condition spec/tla/Migrate.tla shows it needs. A provider that
// enforces nothing a rotation relies on can still be safe to migrate on, and
// one that enforces everything a rotation relies on can still not be.
func TestSafeForMigrationNeedsOnlyTheCreateGuard(t *testing.T) {
	for _, c := range []struct {
		rotation, ifNoneMatch Outcome
		want                  bool
	}{
		{Enforced, Enforced, true},
		{Ignored, Enforced, true},
		{Enforced, Ignored, false},
		{Enforced, Refused, false},
	} {
		got := Conditions{
			CopySourceIfMatch:   Check{Outcome: c.rotation},
			CompleteIfMatch:     Check{Outcome: c.rotation},
			CompleteIfNoneMatch: Check{Outcome: c.ifNoneMatch},
		}.SafeForMigration()
		if got != c.want {
			t.Errorf("rotation guards %s, If-None-Match %s: SafeForMigration() = %v, want %v",
				c.rotation, c.ifNoneMatch, got, c.want)
		}
	}
}
