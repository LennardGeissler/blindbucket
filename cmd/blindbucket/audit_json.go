package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/audit"
)

// The --json document of `audit verify`, for the job this command most often
// runs as: a cron entry checking that the audit log still verifies against a
// checkpoint recorded elsewhere. Without it such a job can read the exit code
// and nothing else -- which checkpoint the chain reached, how many entries sit
// past the last signature, and whether signatures were checked at all are only
// in the prose.
//
// The field names are a stable interface under ADR-021: never removed, renamed
// or retyped once released. Only what #69 asks for is included, because a field
// added speculatively is a field that can never be taken back.
//
// Three decisions are worth stating, because none of them falls out of the
// shape:
//
// A failed run still prints its document. Suppressing it would make the flag
// useless to the job it is for: a monitor needs to know where the chain broke,
// and that is exactly what a failed run knows. What must not happen is a
// consumer reading a failed run as a good one, so the failure is a value of
// verdict rather than the absence of one, with the reason in error.
//
// There is no ok boolean. Three different outcomes exit 0 -- chain and
// signatures verified, chain intact but signatures not checked, chain intact
// but nothing is signed -- and a single ok: true would erase the difference the
// text output goes to some length to make. A monitor that saw ok: true for an
// unsigned log would be told the opposite of what ADR-016 says about it.
// verdict carries the answer and is never "verified" unless everything held.
//
// entries_past_last_signature is null rather than 0 when signatures were not
// checked. The count is Entries - SignedThrough, and with no public key
// SignedThrough is 0, so a number here would equal the entry count and read as
// "all of them are unsigned" when the truth is "this run did not look".
type auditVerifyJSON struct {
	Verdict           string                `json:"verdict"`
	SignaturesChecked bool                  `json:"signatures_checked"`
	Error             string                `json:"error,omitempty"`
	Files             []auditVerifyFileJSON `json:"files"`
	Expect            *auditExpectJSON      `json:"expect,omitempty"`
}

// The verdicts. A consumer that knows only these four and treats anything else
// as a failure stays correct if a later release adds one.
const (
	// auditVerdictVerified is the only one that says the audit key covered the
	// log: chain intact and every checkpoint signed by it.
	auditVerdictVerified = "verified"
	// auditVerdictUnchecked: the chain is intact, so the file has not been
	// edited in place. It does not say this gateway wrote it -- without a
	// public key a log forged end to end verifies too.
	auditVerdictUnchecked = "signatures_not_checked"
	// auditVerdictNothingSigned: checked against a key, but the log carries no
	// checkpoint, so none of it is covered. Saying "signatures verified" of
	// zero signatures would be true and useless.
	auditVerdictNothingSigned = "nothing_signed"
	// auditVerdictFailed: the run did not verify. Never emitted with a zero
	// exit code, and never alongside an empty error.
	auditVerdictFailed = "failed"
)

// auditVerifyFileJSON is one log file's result. The files appear in the order
// their heads say they belong in, which is the order they were checked.
type auditVerifyFileJSON struct {
	Name        string `json:"name"`
	Chain       string `json:"chain"`
	Entries     uint64 `json:"entries"`
	First       string `json:"first,omitempty"`
	Last        string `json:"last,omitempty"`
	Checkpoints int    `json:"checkpoints"`
	// LastCheckpoint is null for a file carrying none. Split into seq and hash
	// rather than the "<seq>:<hash>" string the text prints, so a consumer
	// comparing against a recorded checkpoint does not have to parse it.
	LastCheckpoint *auditCheckpointJSON `json:"last_checkpoint"`
	// EntriesPastLastSignature is null when signatures were not checked.
	EntriesPastLastSignature *uint64 `json:"entries_past_last_signature"`
	// TornTail reports a final record cut off mid-write, which is what a crash
	// between checkpoints looks like rather than tampering.
	TornTail bool `json:"torn_tail"`
}

type auditCheckpointJSON struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// auditExpectJSON is what --expect compared against, and whether it agreed.
// Absent when --expect was not given, so its presence alone says the
// truncation window of ADR-016 was closed on this run.
type auditExpectJSON struct {
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
	Matched bool   `json:"matched"`
	// Chain names the chain the matching checkpoint was found in, and is empty
	// when nothing matched.
	Chain string `json:"chain,omitempty"`
}

// writeAuditVerifyJSON prints the document and hands back the failure it
// reports, so the exit code still says what happened.
//
// failure is what the run came to: a broken chain, or an --expect that did not
// hold. Either one makes the verdict "failed".
func writeAuditVerifyJSON(
	paths []string, results []*audit.Result, signaturesChecked bool,
	failure error, outcome expectOutcome,
) error {
	data, err := marshalAuditVerifyJSON(paths, results, signaturesChecked, failure, outcome)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return failure
}

// marshalAuditVerifyJSON builds the document. Separate from writing it so the
// shape can be tested without capturing stdout.
func marshalAuditVerifyJSON(
	paths []string, results []*audit.Result, signaturesChecked bool,
	failure error, outcome expectOutcome,
) ([]byte, error) {
	doc := auditVerifyJSON{
		SignaturesChecked: signaturesChecked,
		Files:             make([]auditVerifyFileJSON, 0, len(results)),
	}

	var signed int
	for i, result := range results {
		file := auditVerifyFileJSON{
			Chain:       result.Chain,
			Entries:     result.Entries,
			Checkpoints: result.Checkpoints,
			TornTail:    result.TornTail,
		}
		// The base name, as the text output prints: the full path is what the
		// caller passed and already knows.
		if i < len(paths) {
			file.Name = filepath.Base(paths[i])
		}
		if result.Entries > 0 {
			file.First = result.First.Format(time.RFC3339)
			file.Last = result.Last.Format(time.RFC3339)
		}
		if point := result.LastCheckpoint; point != nil {
			file.LastCheckpoint = &auditCheckpointJSON{Seq: point.Seq, Hash: point.Hash}
		}
		if signaturesChecked {
			unsigned := result.Entries - result.SignedThrough
			file.EntriesPastLastSignature = &unsigned
		}
		signed += result.Checkpoints
		doc.Files = append(doc.Files, file)
	}

	switch {
	case failure != nil:
		doc.Verdict = auditVerdictFailed
		doc.Error = failure.Error()
	case !signaturesChecked:
		doc.Verdict = auditVerdictUnchecked
	case signed == 0:
		doc.Verdict = auditVerdictNothingSigned
	default:
		doc.Verdict = auditVerdictVerified
	}

	if outcome.asked() {
		doc.Expect = &auditExpectJSON{Seq: outcome.seq, Hash: outcome.hash}
		if outcome.matched != nil {
			doc.Expect.Matched = true
			doc.Expect.Chain = outcome.matched.chain
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}
