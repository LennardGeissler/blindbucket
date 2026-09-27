package main

import (
	"errors"
	"flag"
	"strings"
	"testing"
)

// Every command with --json says, in its help, that consumers must ignore
// fields they do not know: the promise ADR-021 makes about the documents is
// only half a promise if the consumers are never told the other half.
func TestJSONFlagsSayToIgnoreUnknownFields(t *testing.T) {
	for _, cmd := range [][]string{
		{"keys", "list"}, {"gc"}, {"rotate"}, {"probe"},
	} {
		var err error
		help := captureStderr(t, func() {
			err = run(t.Context(), append(append([]string(nil), cmd...), "-h"))
		})
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%v -h returned %v, want flag.ErrHelp", cmd, err)
		}
		if !strings.Contains(help, "-json") || !strings.Contains(help, ignoreUnknownFields) {
			t.Errorf("%v -h does not tell a --json consumer to ignore unknown fields:\n%s", cmd, help)
		}
	}
}
