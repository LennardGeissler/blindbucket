package integration

import (
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/proxy/proxytest"
)

// TestMain sweeps what the tests left at the provider once they have run.
func TestMain(m *testing.M) { proxytest.Main(m) }
