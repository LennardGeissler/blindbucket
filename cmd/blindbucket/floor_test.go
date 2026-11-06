package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// stripToVersion1 turns a version 2 keyring into a version 1 one without any
// key: the version says 1, and the members only version 2 has are gone. The
// default tenant's keys open as they did (FORMAT §18.6).
func stripToVersion1(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["version"] = 1
	for _, member := range []string{"generation", "directory", "tenants"} {
		delete(doc, member)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A keyring below keys.min_generation is refused, whether it is an older copy
// put back in place of the newest or a version 2 file stripped down to
// version 1; without a floor, each still opens (ADR-040).
func TestKeyringBelowTheFloorIsRefused(t *testing.T) {
	path := setupKeyring(t, "2026-09")
	v1 := mustRead(t, path)
	if _, _, err := runCLI(t, "tenants", "create", "--keyring", path, "--deployment-lock",
		"--kid", "acme-1", "acme", "acme-*"); err != nil {
		t.Fatalf("create: %v", err)
	}
	gen1 := mustRead(t, path)
	if _, _, err := runCLI(t, "tenants", "activate", "--keyring", path, "acme"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	gen2 := mustRead(t, path)

	floor := keysConfigFile(t, "  min_generation: 2")
	none := keysConfigFile(t, "")
	for name, c := range map[string]struct {
		data  []byte
		above bool
	}{
		"the newest":              {gen2, true},
		"an older copy":           {gen1, false},
		"version 1 from before":   {v1, false},
		"version 2 stripped to 1": {stripToVersion1(t, gen2), false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, c.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := runCLI(t, "tenants", "list", "--keyring", path, "--config", floor)
			switch {
			case c.above && err != nil:
				t.Errorf("with the floor: %v", err)
			case !c.above && !errors.Is(err, keys.ErrKeyringBelowFloor):
				t.Errorf("with the floor: %v, want ErrKeyringBelowFloor", err)
			case !c.above && !strings.Contains(err.Error(), "lower keys.min_generation"):
				t.Errorf("the refusal does not say how to proceed: %v", err)
			}
			if _, _, err := runCLI(t, "tenants", "list", "--keyring", path, "--config", none); err != nil {
				t.Errorf("without a floor: %v", err)
			}
		})
	}
}
