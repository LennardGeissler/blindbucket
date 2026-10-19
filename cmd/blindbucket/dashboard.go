package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/dashboard"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// startDashboard serves the read-only status page when admin.dashboard.listen
// is set (ADR-035), and returns nil when it is not.
func startDashboard(
	cfg *config.Config, ring *keys.Keyring, client *upstream.Client, auditLog *audit.Writer,
	started time.Time, log *slog.Logger,
) (*dashboard.Server, error) {
	if cfg.Admin.Dashboard.Listen == "" {
		return nil, nil
	}
	dc := dashboard.Config{
		Listen: cfg.Admin.Dashboard.Listen, Version: version, Started: started,
		Ready:   readiness(client, ring, probeBucket(cfg)),
		Keyring: ring, Sealing: sealing(cfg.Keys),
		Logger: log,
	}
	// Set only with a writer: a nil *audit.Writer in the interface would read
	// as a configured log.
	if auditLog != nil {
		key, ok := ring.AuditKey()
		if !ok {
			return nil, fmt.Errorf("the audit log is open but %s has no audit key", cfg.Keys.Keyring)
		}
		pub, err := key.Public()
		if err != nil {
			return nil, err
		}
		dc.Audit, dc.Verify = auditLog, auditVerifier(cfg.Audit.Log, pub)
	}
	d := dashboard.New(dc)
	if err := d.Start(); err != nil {
		return nil, listenError("admin.dashboard.listen", cfg.Admin.Dashboard.Listen, err)
	}
	return d, nil
}

// sealing says in words what seals the keyring, naming where and which key
// but no credential: the Vault token, KMS keys and the passphrase stay out.
func sealing(k config.Keys) string {
	switch k.Provider {
	case "vault":
		mount := k.Vault.Mount
		if mount == "" {
			mount = "transit"
		}
		s := fmt.Sprintf("Vault or OpenBao Transit at %s, key %s/%s", k.Vault.Address, mount, k.Vault.KeyName)
		if k.Vault.Namespace != "" {
			s += ", namespace " + k.Vault.Namespace
		}
		return s
	case "awskms":
		s := "AWS KMS, key " + k.AWSKMS.KeyID
		if k.AWSKMS.Region != "" {
			s += " in " + k.AWSKMS.Region
		}
		return s
	default:
		return "a passphrase"
	}
}

// auditVerifier verifies the audit log's chain as `blindbucket audit verify`
// does: the current file and every rotated one beside it, in the order their
// heads link them, with the public key from the keyring.
func auditVerifier(path string, pub ed25519.PublicKey) func(context.Context) dashboard.Verification {
	return func(context.Context) dashboard.Verification {
		v := dashboard.Verification{At: time.Now().UTC()}
		paths, err := chainFiles(path)
		if err != nil {
			v.Error = err.Error()
			return v
		}
		ordered, err := orderLogs(paths)
		if err != nil {
			v.Error = err.Error()
			return v
		}
		v.Files = len(ordered)
		files := make([]audit.NamedReader, 0, len(ordered))
		for _, p := range ordered {
			//nolint:gosec // the path comes from the operator's configuration.
			f, err := os.Open(p)
			if err != nil {
				v.Error = err.Error()
				return v
			}
			defer f.Close() //nolint:errcheck // read-only.
			files = append(files, audit.NamedReader{Name: filepath.Base(p), Reader: f})
		}
		results, err := audit.VerifyChain(files, audit.VerifyOptions{PublicKey: pub})
		if err != nil {
			v.Error = err.Error()
			return v
		}
		if len(results) > 0 {
			last := results[len(results)-1]
			v.Entries, v.SignedThrough = last.Entries, last.SignedThrough
		}
		v.OK = true
		return v
	}
}

// chainFiles lists the audit log and the files it was rotated to, which the
// writer names after it: <path>.<timestamp>, with a suffix on a clash.
func chainFiles(path string) ([]string, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	paths := []string{path}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), base+".") {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}
