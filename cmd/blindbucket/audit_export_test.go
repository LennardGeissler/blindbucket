package main

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestExportReporterLogsChangesOfState is a receiver slower than the gateway:
// sends succeed between entries the full queue drops. That is one line when the
// export starts failing and one when it has gone a minute without losing an
// entry, not a line for every switch.
func TestExportReporterLogsChangesOfState(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	r := newExportReporter(slog.New(slog.NewTextHandler(&buf, nil)), nil)
	r.now = func() time.Time { return now }
	lines := func(level string) int { return strings.Count(buf.String(), "level="+level) }

	dropped := errors.New("audit: otlp export queue is full; dropping entry")
	for range 100 {
		r.failed("otlp", dropped)
		r.delivered("otlp")
	}
	if lines("ERROR") != 1 || lines("INFO") != 0 {
		t.Fatalf("alternating drops and sends logged %d ERROR and %d INFO lines, want 1 and 0:\n%s",
			lines("ERROR"), lines("INFO"), buf.String())
	}

	now = now.Add(exportRecovery - time.Second)
	r.delivered("otlp")
	if lines("INFO") != 0 {
		t.Fatalf("recovered before a minute without a lost entry:\n%s", buf.String())
	}

	now = now.Add(time.Second)
	r.delivered("otlp")
	if lines("INFO") != 1 || !strings.Contains(buf.String(), "entries_lost=100") {
		t.Fatalf("want one recovery naming the 100 lost entries:\n%s", buf.String())
	}

	r.failed("otlp", dropped)
	if lines("ERROR") != 2 {
		t.Errorf("a new failure after the recovery was not logged:\n%s", buf.String())
	}
}
