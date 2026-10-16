package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/doctor"
	"github.com/LennardGeissler/blindbucket/internal/testprovider"
)

// doctorSetup writes a configuration with init, for a provider at endpoint,
// and loads its environment file as `set -a; . blindbucket.env` would.
func doctorSetup(t *testing.T, endpoint, bucket string) string {
	t.Helper()
	initEnv(t)
	dir := t.TempDir()
	if _, _, err := runCLI(t, "init", "--non-interactive", "--dir", dir,
		"--endpoint", endpoint, "--bucket", bucket); err != nil {
		t.Fatalf("init: %v", err)
	}
	for name, value := range readInitEnv(t, filepath.Join(dir, initEnvName)) {
		t.Setenv(name, value)
	}
	return filepath.Join(dir, initConfigName)
}

// editConfig replaces old with replacement in the configuration at path.
func editConfig(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the test's own file.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("the configuration holds no %q", old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), old, replacement, 1)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// runDoctorJSON runs doctor with --json and decodes what it printed.
func runDoctorJSON(t *testing.T, args ...string) (doctorJSON, error) {
	t.Helper()
	stdout, _, err := runCLI(t, append([]string{"doctor", "--json"}, args...)...)
	var doc doctorJSON
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("doctor --json printed something that is not its document: %v\n%s", jerr, stdout)
	}
	return doc, err
}

func find(t *testing.T, doc doctorJSON, name, bucket string) doctorCheckJSON {
	t.Helper()
	for _, c := range doc.Checks {
		if c.Name == name && c.Bucket == bucket {
			return c
		}
	}
	t.Fatalf("no check %q for bucket %q in %+v", name, bucket, doc.Checks)
	return doctorCheckJSON{}
}

// unreachable is an endpoint where nothing listens.
const unreachable = "http://127.0.0.1:1"

// TestDoctorJSONDocument pins the document ADR-021 promises to keep: its
// fields, and every check present by name, in order, even when the
// configuration does not load and none of them could run.
func TestDoctorJSONDocument(t *testing.T) {
	doc, err := runDoctorJSON(t, "--config", "/nonexistent/blindbucket.yaml", "s3://b")
	if err == nil {
		t.Fatal("doctor succeeded without a configuration")
	}
	var names []string
	for _, c := range doc.Checks {
		names = append(names, c.Name)
	}
	want := []string{
		doctor.NameConfig, doctor.NameListener, doctor.NameTLS, doctor.NameKeyring,
		doctor.NameFeatureKeys, doctor.NameAuditLog, doctor.NameFreshnessIndex,
		doctor.NameUpstreamCreds, doctor.NameBucket, doctor.NameConditionalWrites, doctor.NameClock,
	}
	if !slices.Equal(names, want) {
		t.Errorf("checks %v, want %v", names, want)
	}
	if doc.OK || doc.Config != "/nonexistent/blindbucket.yaml" {
		t.Errorf("document = %+v", doc)
	}
	config := find(t, doc, doctor.NameConfig, "")
	if config.Outcome != "failed" || !strings.Contains(config.Fix, "blindbucket init") {
		t.Errorf("config = %+v", config)
	}
	if c := find(t, doc, doctor.NameBucket, "b"); c.Outcome != "skipped" {
		t.Errorf("bucket = %+v, want skipped", c)
	}

	var raw map[string]any
	stdout, _, _ := runCLI(t, "doctor", "--json", "--config", "/nonexistent/blindbucket.yaml")
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"config", "ok", "checks"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("the document has no %q", field)
		}
	}
	first := raw["checks"].([]any)[0].(map[string]any)
	for _, field := range []string{"name", "outcome", "detail", "fix"} {
		if _, ok := first[field]; !ok {
			t.Errorf("a failed check has no %q", field)
		}
	}
}

func TestDoctorNamesAnUnsetVariable(t *testing.T) {
	conf := doctorSetup(t, unreachable, "b")
	t.Setenv(envClientSecret, "")
	if err := os.Unsetenv(envClientSecret); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	doc, _ := runDoctorJSON(t, "--config", conf)
	c := find(t, doc, doctor.NameConfig, "")
	if c.Outcome != "failed" || !strings.Contains(c.Detail, envClientSecret) || !strings.Contains(c.Fix, initEnvName) {
		t.Errorf("config = %+v", c)
	}
}

func TestDoctorKeyring(t *testing.T) {
	t.Run("a wrong passphrase", func(t *testing.T) {
		conf := doctorSetup(t, unreachable, "b")
		t.Setenv(passphraseEnv, "not the passphrase")
		doc, _ := runDoctorJSON(t, "--config", conf)
		if c := find(t, doc, doctor.NameKeyring, ""); c.Outcome != "failed" || !strings.Contains(c.Fix, passphraseEnv) {
			t.Errorf("keyring = %+v", c)
		}
		if c := find(t, doc, doctor.NameFeatureKeys, ""); c.Outcome != "skipped" {
			t.Errorf("feature_keys = %+v, want skipped", c)
		}
	})
	t.Run("readable beyond its owner", func(t *testing.T) {
		conf := doctorSetup(t, unreachable, "b")
		if err := os.Chmod(filepath.Join(filepath.Dir(conf), initKeyringName), 0o644); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		doc, _ := runDoctorJSON(t, "--config", conf)
		if c := find(t, doc, doctor.NameKeyring, ""); c.Outcome != "warning" || !strings.Contains(c.Fix, "chmod 600") {
			t.Errorf("keyring = %+v", c)
		}
	})
	t.Run("missing", func(t *testing.T) {
		conf := doctorSetup(t, unreachable, "b")
		if err := os.Remove(filepath.Join(filepath.Dir(conf), initKeyringName)); err != nil {
			t.Fatalf("remove: %v", err)
		}
		doc, _ := runDoctorJSON(t, "--config", conf)
		if c := find(t, doc, doctor.NameKeyring, ""); c.Outcome != "failed" || !strings.Contains(c.Fix, "keygen") {
			t.Errorf("keyring = %+v", c)
		}
	})
}

// TestDoctorFeatureKeys covers the startup refusal serve makes for a feature
// whose key the keyring lacks, found before serve is started.
func TestDoctorFeatureKeys(t *testing.T) {
	conf := doctorSetup(t, unreachable, "b")
	dir := filepath.Dir(conf)
	editConfig(t, conf, "# names:\n#   encrypt: true\n",
		"names:\n  encrypt: true\naudit:\n  log: "+filepath.Join(dir, "audit.log")+"\n")
	doc, _ := runDoctorJSON(t, "--config", conf)
	if c := find(t, doc, doctor.NameFeatureKeys, ""); c.Outcome != "ok" {
		t.Errorf("feature_keys with every key present = %+v", c)
	}
	if c := find(t, doc, doctor.NameAuditLog, ""); c.Outcome != "ok" {
		t.Errorf("audit_log = %+v", c)
	}

	stripKeys(t, filepath.Join(dir, initKeyringName), "name_key")
	doc, _ = runDoctorJSON(t, "--config", conf)
	c := find(t, doc, doctor.NameFeatureKeys, "")
	if c.Outcome != "failed" || !strings.Contains(c.Fix, "--add-name-key") || strings.Contains(c.Fix, "--add-audit-key") {
		t.Errorf("feature_keys without the name key = %+v", c)
	}
}

func TestDoctorAuditLogInAMissingDirectory(t *testing.T) {
	conf := doctorSetup(t, unreachable, "b")
	editConfig(t, conf, "# names:\n", "audit:\n  log: /nonexistent/dir/audit.log\n# names:\n")
	doc, _ := runDoctorJSON(t, "--config", conf)
	if c := find(t, doc, doctor.NameAuditLog, ""); c.Outcome != "failed" || !strings.Contains(c.Fix, "audit.log") {
		t.Errorf("audit_log = %+v", c)
	}
}

func TestDoctorWithNothingListening(t *testing.T) {
	conf := doctorSetup(t, unreachable, "b")
	doc, err := runDoctorJSON(t, "--config", conf)
	if err == nil || !strings.Contains(err.Error(), "checks failed") {
		t.Errorf("err = %v, want one saying checks failed", err)
	}
	if c := find(t, doc, doctor.NameBucket, "b"); c.Outcome != "failed" || !strings.Contains(c.Fix, "upstream.endpoint") {
		t.Errorf("bucket = %+v", c)
	}
	if c := find(t, doc, doctor.NameConditionalWrites, "b"); c.Outcome != "skipped" {
		t.Errorf("conditional_writes = %+v, want skipped", c)
	}
	if c := find(t, doc, doctor.NameClock, ""); c.Outcome != "skipped" {
		t.Errorf("clock = %+v, want skipped", c)
	}
	// Everything that does not need the provider still ran.
	if c := find(t, doc, doctor.NameKeyring, ""); c.Outcome != "ok" {
		t.Errorf("keyring = %+v", c)
	}
}

func TestDoctorNeedsABucketForAWildcardClient(t *testing.T) {
	conf := doctorSetup(t, unreachable, "b")
	editConfig(t, conf, `buckets: ["b"]`, `buckets: ["*"]`)
	doc, _ := runDoctorJSON(t, "--config", conf)
	if c := find(t, doc, doctor.NameBucket, ""); c.Outcome != "failed" || !strings.Contains(c.Fix, "s3://") {
		t.Errorf("bucket = %+v", c)
	}
}

func TestDoctorRefusesAPrefix(t *testing.T) {
	_, _, err := runCLI(t, "doctor", "s3://b/some/prefix")
	if err == nil || !strings.Contains(err.Error(), "not a prefix") {
		t.Fatalf("err = %v", err)
	}
}

func TestDoctorHumanOutput(t *testing.T) {
	conf := doctorSetup(t, unreachable, "b")
	stdout, _, _ := runCLI(t, "doctor", "--config", conf)
	for _, want := range []string{"failed   bucket b", "fix: nothing answered at upstream.endpoint", "1 failed, 0 warnings"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the output does not contain %q:\n%s", want, stdout)
		}
	}
}

// TestIntegrationDoctor runs doctor on a configuration init wrote, against a
// real provider: nothing fails.
//
//	docker compose up -d
//	BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./cmd/blindbucket -run Doctor
func TestIntegrationDoctor(t *testing.T) {
	tp := testprovider.Require(t)
	initEnv(t)
	t.Setenv(envUpstreamKeyID, tp.AccessKey)
	t.Setenv(envUpstreamSecret, tp.SecretKey)
	dir := t.TempDir()
	args := []string{"init", "--non-interactive", "--dir", dir,
		"--endpoint", tp.Endpoint, "--region", tp.Region, "--bucket", tp.Bucket}
	if !tp.PathStyle {
		args = append(args, "--path-style=false")
	}
	if _, _, err := runCLI(t, args...); err != nil {
		t.Fatalf("init: %v", err)
	}
	for name, value := range readInitEnv(t, filepath.Join(dir, initEnvName)) {
		t.Setenv(name, value)
	}
	conf := filepath.Join(dir, initConfigName)

	doc, err := runDoctorJSON(t, "--config", conf)
	if err != nil || !doc.OK {
		t.Fatalf("doctor: %v\n%+v", err, doc.Checks)
	}
	if c := find(t, doc, doctor.NameBucket, tp.Bucket); c.Outcome != "ok" {
		t.Errorf("bucket = %+v", c)
	}
	if c := find(t, doc, doctor.NameConditionalWrites, tp.Bucket); c.Outcome == "failed" || c.Outcome == "skipped" {
		t.Errorf("conditional_writes = %+v", c)
	}

	doc, err = runDoctorJSON(t, "--config", conf, "--no-write")
	if err != nil {
		t.Fatalf("doctor --no-write: %v", err)
	}
	if c := find(t, doc, doctor.NameConditionalWrites, tp.Bucket); c.Outcome != "skipped" {
		t.Errorf("conditional_writes with --no-write = %+v", c)
	}
}
