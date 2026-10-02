package migrate

import (
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/probe"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// The behaviour against a provider is in internal/proxy, where a gateway on
// either side of the switch can be run: migrate_integration_test.go. What is
// here needs neither.

func TestRunRefusesAnIncompleteConfig(t *testing.T) {
	client, err := upstream.New(upstream.Config{
		Endpoint: "http://127.0.0.1:1", Region: "us-east-1", PathStyle: true,
		AccessKeyID: "a", SecretAccessKey: "s",
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	ring := keys.NewKeyring()
	enc, err := names.New(make([]byte, names.KeySize))
	if err != nil {
		t.Fatalf("names.New: %v", err)
	}
	whole := Config{Upstream: client, Keys: ring, Names: enc, Bucket: "b"}
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"no upstream": {func() Config { c := whole; c.Upstream = nil; return c }(), "upstream"},
		"no keys":     {func() Config { c := whole; c.Keys = nil; return c }(), "key provider"},
		"no names":    {func() Config { c := whole; c.Names = nil; return c }(), "name encrypter"},
		"no bucket":   {func() Config { c := whole; c.Bucket = ""; return c }(), "bucket"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Run(t.Context(), tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error about the %s", err, tc.want)
			}
		})
	}
}

// TestUnguardedErrorNamesOnlyTheMigrationsGuard: a provider like Garage ignores
// both completion conditions, and the refusal has to name the one a migration
// relies on -- not rotation's, which would send an operator after the wrong
// header.
func TestUnguardedErrorNamesOnlyTheMigrationsGuard(t *testing.T) {
	err := &UnguardedError{Bucket: "backups", Conditions: probe.Conditions{
		CopySourceIfMatch:   probe.Check{Name: "x-amz-copy-source-if-match on UploadPartCopy", Outcome: probe.Enforced},
		CompleteIfMatch:     probe.Check{Name: "If-Match on CompleteMultipartUpload", Outcome: probe.Ignored},
		CompleteIfNoneMatch: probe.Check{Name: "If-None-Match on CompleteMultipartUpload", Outcome: probe.Ignored},
	}}
	msg := err.Error()
	for _, want := range []string{"backups", "If-None-Match on CompleteMultipartUpload: ignored",
		"--allow-unconditional", "ADR-022"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "If-Match on CompleteMultipartUpload") {
		t.Errorf("the refusal names rotation's guard:\n%s", msg)
	}
}

func TestIncompleteMeansSomethingIsLeftInClear(t *testing.T) {
	for _, tc := range []struct {
		r    Result
		want bool
	}{
		{Result{Migrated: 3, Resumed: 1, Superseded: 1}, false},
		{Result{Foreign: 4}, false},
		{Result{Conflicted: 1}, true},
		{Result{TooLong: 1}, true},
		{Result{Failed: 1}, true},
	} {
		if got := tc.r.Incomplete(); got != tc.want {
			t.Errorf("%+v: Incomplete() = %v, want %v", tc.r, got, tc.want)
		}
	}
}
