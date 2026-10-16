// Package doctor holds the checks `blindbucket doctor` runs: each asks one
// question about a deployment, and answers with what to change when the
// answer is no (ADR-031).
//
// The checks that need the CLI's own helpers -- loading the configuration,
// opening the keyring the way serve does -- are assembled in cmd/blindbucket.
// What lives here is what can be asked of a provider, a file or the clock
// without them.
package doctor

import "fmt"

// Outcome is how a check ended.
type Outcome int

const (
	// OK means the check found nothing to change.
	OK Outcome = iota
	// Warning means the gateway works, and something about it is still worth
	// changing: a keyring readable beyond its owner, a provider that ignores
	// the conditions rotation relies on.
	Warning
	// Failed means serve would not start, or a client would fail.
	Failed
	// Skipped means the check could not be asked, because something it
	// depends on failed, or did not apply.
	Skipped
)

func (o Outcome) String() string {
	switch o {
	case OK:
		return "ok"
	case Warning:
		return "warning"
	case Failed:
		return "failed"
	case Skipped:
		return "skipped"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// Check is one question and its answer.
type Check struct {
	// Name is one of a fixed set, pinned by the `doctor --json` document.
	Name string
	// Bucket is set for the checks asked once per bucket.
	Bucket  string
	Outcome Outcome
	// Detail says what was found, for every outcome.
	Detail string
	// Fix says what to change, for a warning or a failure: the setting, the
	// command or the permission, not only the symptom.
	Fix string
}

// The names of the checks, in the order doctor runs them.
const (
	NameConfig            = "config"
	NameListener          = "listener"
	NameTLS               = "tls"
	NameKeyring           = "keyring"
	NameFeatureKeys       = "feature_keys"
	NameAuditLog          = "audit_log"
	NameFreshnessIndex    = "freshness_index"
	NameUpstreamCreds     = "upstream_credentials" //nolint:gosec // a check's name, not a credential.
	NameBucket            = "bucket"
	NameConditionalWrites = "conditional_writes"
	NameClock             = "clock"
)

// Ok returns a passing check.
func Ok(name, detail string) Check { return Check{Name: name, Outcome: OK, Detail: detail} }

// Fail returns a failed check with its fix.
func Fail(name, detail, fix string) Check {
	return Check{Name: name, Outcome: Failed, Detail: detail, Fix: fix}
}

// Warn returns a warning with its fix.
func Warn(name, detail, fix string) Check {
	return Check{Name: name, Outcome: Warning, Detail: detail, Fix: fix}
}

// Skip returns a check that was not asked, and why.
func Skip(name, why string) Check { return Check{Name: name, Outcome: Skipped, Detail: why} }

// Failures counts the failed checks, and Warnings the warnings.
func Failures(checks []Check) int { return count(checks, Failed) }

// Warnings counts the checks that ended in a warning.
func Warnings(checks []Check) int { return count(checks, Warning) }

func count(checks []Check, o Outcome) int {
	n := 0
	for _, c := range checks {
		if c.Outcome == o {
			n++
		}
	}
	return n
}
