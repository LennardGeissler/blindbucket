package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// TestBucketCommandsRefuseBadInvocations covers what rotate and gc check before
// touching a bucket. Both act on every object under a target, so a target that
// is read differently from how it was meant is the mistake worth stopping.
func TestBucketCommandsRefuseBadInvocations(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	for _, cmd := range []string{"rotate", "gc", "scrub"} {
		for name, tc := range map[string]struct {
			args []string
			want string
		}{
			"no target":        {nil, ""},
			"two targets":      {[]string{"s3://a", "s3://b"}, ""},
			"not an s3 url":    {[]string{"backups"}, "must look like s3://bucket"},
			"no bucket":        {[]string{"s3:///prefix"}, "names no bucket"},
			"a missing config": {[]string{"--config", missing, "s3://bucket"}, "no such file"},
		} {
			t.Run(cmd+"/"+name, func(t *testing.T) {
				_, _, err := runCLI(t, append([]string{cmd}, tc.args...)...)
				if err == nil {
					t.Fatal("accepted")
				}
				if tc.want == "" {
					if !errors.Is(err, errUsage) {
						t.Errorf("got %v, want the usage error", err)
					}
					return
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q does not mention %q", err, tc.want)
				}
			})
		}
	}
}

// TestRotateRefusesAnUnknownTarget: rotating onto a key the keyring does not
// hold would wrap every data key under nothing that can open it again.
func TestRotateRefusesAnUnknownTarget(t *testing.T) {
	p := testprovider.Require(t)
	keyring := setupKeyring(t, "2026-09")
	cfg := providerConfig(t, p, keyring)
	target := "s3://" + p.Bucket + "/" + testprovider.RunPrefix() + "rotate-unknown/"

	_, _, err := runCLI(t, "rotate", "--config", cfg, "--dry-run", "--allow-unconditional",
		"--to-kid", "no-such-key", target)
	if err == nil || !strings.Contains(err.Error(), "no-such-key") {
		t.Errorf("got %v, want a refusal naming the key", err)
	}
}

// TestBucketCommandsNeedTheirKeyring: rotate opens the keyring, and a gateway
// configuration pointing at one that is not there must say so before anything
// is listed. gc does not open it, which is what lets it run without a secret.
func TestBucketCommandsNeedTheirKeyring(t *testing.T) {
	p := testprovider.Require(t)
	cfg := providerConfig(t, p, filepath.Join(t.TempDir(), "absent-keyring.json"))
	target := "s3://" + p.Bucket + "/" + testprovider.RunPrefix() + "no-keyring/"

	if _, _, err := runCLI(t, "rotate", "--config", cfg, "--dry-run", target); err == nil {
		t.Error("rotate ran without its keyring")
	}
	if _, _, err := runCLI(t, "gc", "--config", cfg, "--dry-run", target); err != nil {
		t.Errorf("gc needed the keyring it never opens: %v", err)
	}
}
