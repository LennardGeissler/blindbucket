package main

import "flag"

// ignoreUnknownFields is what every --json document tells its consumers. The
// documents are a stable interface (ADR-021): a field is never removed,
// renamed or retyped, but later releases may add fields, and a parser that
// rejects the ones it does not know would break on an upgrade that broke
// nothing.
const ignoreUnknownFields = "later releases may add fields; ignore the ones you do not know"

// jsonFlag registers --json with a description that carries that rule, so the
// commands that have one cannot come to say different things about it.
func jsonFlag(fs *flag.FlagSet, what string) *bool {
	return fs.Bool("json", false, "emit "+what+" as JSON; "+ignoreUnknownFields)
}
