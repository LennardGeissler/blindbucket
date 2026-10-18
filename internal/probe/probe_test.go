package probe

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

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

func TestOutcomeString(t *testing.T) {
	for _, tc := range []struct {
		outcome Outcome
		want    string
	}{
		{Enforced, "enforced"},
		{Ignored, "ignored"},
		{Refused, "refused"},
		{Outcome(99), "Outcome(99)"},
		{Outcome(-1), "Outcome(-1)"},
	} {
		if got := tc.outcome.String(); got != tc.want {
			t.Errorf("Outcome(%d).String() = %q, want %q", int(tc.outcome), got, tc.want)
		}
	}
}

func TestClassify(t *testing.T) {
	t.Run("nil error is classified as Ignored", func(t *testing.T) {
		got, err := classify("guard", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := Check{Name: "guard", Outcome: Ignored}
		if got != want {
			t.Errorf("classify() = %+v, want %+v", got, want)
		}
	})

	t.Run("412 PreconditionFailed is classified as Enforced", func(t *testing.T) {
		apiErr := &upstream.APIError{StatusCode: http.StatusPreconditionFailed, Code: "PreconditionFailed"}
		for _, inErr := range []error{
			apiErr,
			fmt.Errorf("wrapped: %w", apiErr),
			&upstream.APIError{StatusCode: http.StatusPreconditionFailed, Code: "SomethingElse"},
			fmt.Errorf("wrapped: %w", &upstream.APIError{StatusCode: 412, Code: "NotImplemented"}),
		} {
			got, err := classify("guard", inErr)
			if err != nil {
				t.Fatalf("for %v: unexpected error: %v", inErr, err)
			}
			want := Check{Name: "guard", Outcome: Enforced}
			if got != want {
				t.Errorf("for %v: classify() = %+v, want %+v", inErr, got, want)
			}
		}
	})

	t.Run("other provider errors are classified as Refused", func(t *testing.T) {
		apiErr := &upstream.APIError{StatusCode: http.StatusBadRequest, Code: "InvalidArgument", Message: "header not supported"}
		for _, inErr := range []error{
			apiErr,
			fmt.Errorf("wrapped: %w", apiErr),
			&upstream.APIError{StatusCode: http.StatusNotImplemented, Code: "NotImplemented"},
			&upstream.APIError{StatusCode: http.StatusInternalServerError, Code: "InternalError"},
		} {
			got, err := classify("guard", inErr)
			if err != nil {
				t.Fatalf("for %v: unexpected error: %v", inErr, err)
			}
			want := Check{Name: "guard", Outcome: Refused, Detail: inErr.Error()}
			if got != want {
				t.Errorf("for %v: classify() = %+v, want %+v", inErr, got, want)
			}
		}
	})

	t.Run("network failure or lack of provider answer returns error matching original", func(t *testing.T) {
		for _, networkErr := range []error{
			io.ErrUnexpectedEOF,
			io.EOF,
			fmt.Errorf("connection reset: %w", io.ErrUnexpectedEOF),
		} {
			got, err := classify("guard", networkErr)
			if err == nil {
				t.Fatalf("for %v: expected error, got Check %+v", networkErr, got)
			}
			if !errors.Is(err, networkErr) {
				t.Errorf("for %v: expected errors.Is match, got %v", networkErr, err)
			}
		}
	})
}

