package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The document's fields, pinned exactly. They are a stable interface under
// ADR-021 -- never removed, renamed or retyped once released -- so a test that
// merely checked the ones it cared about would let a rename through.
// error and expect are omitempty and asserted where they belong.
var (
	auditVerifyJSONFields = []string{"files", "signatures_checked", "verdict"}
	auditVerifyFileFields = []string{
		"chain", "checkpoints", "entries", "entries_past_last_signature",
		"first", "last", "last_checkpoint", "name", "torn_tail",
	}
)

// auditVerifyJSONDoc runs `audit verify --json` through the command, as #19
// asks, and decodes what it put on stdout.
func auditVerifyJSONDoc(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	out, err := auditVerify(t, append([]string{"--json"}, args...)...)
	return decodeFields(t, []byte(out)), err
}

// firstFile is the one file's object in a single-file document.
func firstFile(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	files, ok := doc["files"].([]any)
	if !ok || len(files) != 1 {
		t.Fatalf("files is %v, want exactly one entry", doc["files"])
	}
	file, ok := files[0].(map[string]any)
	if !ok {
		t.Fatalf("files[0] is %T, want an object", files[0])
	}
	return file
}

func TestAuditVerifyJSONThroughTheCommand(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 5, 2, 0)
	pub := auditPubkey(t, keyring)

	doc, err := auditVerifyJSONDoc(t, "--public-key", pub, logs[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertFields(t, doc, auditVerifyJSONFields)

	if doc["verdict"] != auditVerdictVerified {
		t.Errorf("verdict is %v, want %q", doc["verdict"], auditVerdictVerified)
	}
	if doc["signatures_checked"] != true {
		t.Errorf("signatures_checked is %v, want true", doc["signatures_checked"])
	}

	file := firstFile(t, doc)
	assertFields(t, file, auditVerifyFileFields)

	// Counts are numbers, not strings: a consumer must not have to parse them.
	if entries, ok := file["entries"].(float64); !ok || entries != 5 {
		t.Errorf("entries is %#v, want the number 5", file["entries"])
	}
	if _, ok := file["checkpoints"].(float64); !ok {
		t.Errorf("checkpoints is %#v, want a number", file["checkpoints"])
	}
	if file["torn_tail"] != false {
		t.Errorf("torn_tail is %v, want false for an intact log", file["torn_tail"])
	}
	if name, _ := file["name"].(string); !strings.HasSuffix(name, "audit.log") {
		t.Errorf("name is %v, want the log's base name", file["name"])
	}

	for _, field := range []string{"first", "last"} {
		value, _ := file[field].(string)
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			t.Errorf("%s is %q, which is not RFC 3339: %v", field, value, err)
		}
	}

	// The checkpoint is seq and hash, not the "<seq>:<hash>" string the text
	// prints, so a consumer comparing against a recorded one need not split it.
	point, ok := file["last_checkpoint"].(map[string]any)
	if !ok {
		t.Fatalf("last_checkpoint is %#v, want an object", file["last_checkpoint"])
	}
	assertFields(t, point, []string{"hash", "seq"})
	if _, ok := point["seq"].(float64); !ok {
		t.Errorf("last_checkpoint.seq is %#v, want a number", point["seq"])
	}
	if hash, _ := point["hash"].(string); hash == "" {
		t.Error("last_checkpoint.hash is empty")
	}

	// Signatures were checked, so the count past the last one is known.
	if _, ok := file["entries_past_last_signature"].(float64); !ok {
		t.Errorf("entries_past_last_signature is %#v, want a number when signatures were checked",
			file["entries_past_last_signature"])
	}
}

// TestAuditVerifyJSONDistinguishesTheThreeGoodOutcomes: all three exit 0 and
// mean very different things. A single ok: true would erase the difference the
// text output goes to some length to make, so each gets its own verdict.
func TestAuditVerifyJSONDistinguishesTheThreeGoodOutcomes(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	pub := auditPubkey(t, keyring)

	t.Run("chain and signatures verified", func(t *testing.T) {
		logs := writeAuditLog(t, keyring, 5, 2, 0)
		doc, err := auditVerifyJSONDoc(t, "--public-key", pub, logs[0])
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if doc["verdict"] != auditVerdictVerified || doc["signatures_checked"] != true {
			t.Errorf("verdict %v, signatures_checked %v", doc["verdict"], doc["signatures_checked"])
		}
	})

	t.Run("chain intact, signatures not checked", func(t *testing.T) {
		logs := writeAuditLog(t, keyring, 3, 2, 0)
		doc, err := auditVerifyJSONDoc(t, logs[0])
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if doc["verdict"] != auditVerdictUnchecked {
			t.Errorf("verdict is %v, want %q", doc["verdict"], auditVerdictUnchecked)
		}
		if doc["signatures_checked"] != false {
			t.Errorf("signatures_checked is %v, want false", doc["signatures_checked"])
		}
		// Null rather than 0: with no key nothing is known about the tail, and
		// a number here would equal the entry count and read as "all unsigned".
		file := firstFile(t, doc)
		if file["entries_past_last_signature"] != nil {
			t.Errorf("entries_past_last_signature is %#v, want null when signatures were not checked",
				file["entries_past_last_signature"])
		}
	})

	t.Run("chain intact, nothing is signed", func(t *testing.T) {
		logs := writeAuditLog(t, keyring, 3, 0, 0)
		dropLastLine(t, logs[0])
		doc, err := auditVerifyJSONDoc(t, "--public-key", pub, logs[0])
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if doc["verdict"] != auditVerdictNothingSigned {
			t.Errorf("verdict is %v, want %q", doc["verdict"], auditVerdictNothingSigned)
		}
		// The key was given, so the absence of signatures is a fact about the
		// log and not about the run.
		if doc["signatures_checked"] != true {
			t.Errorf("signatures_checked is %v, want true", doc["signatures_checked"])
		}
		if file := firstFile(t, doc); file["last_checkpoint"] != nil {
			t.Errorf("last_checkpoint is %#v, want null for a log carrying none",
				file["last_checkpoint"])
		}
	})

	t.Run("the three verdicts are distinct", func(t *testing.T) {
		seen := map[string]bool{}
		for _, v := range []string{auditVerdictVerified, auditVerdictUnchecked, auditVerdictNothingSigned} {
			if seen[v] {
				t.Errorf("verdict %q is used for more than one outcome", v)
			}
			seen[v] = true
			if v == auditVerdictFailed {
				t.Errorf("a successful outcome uses the failure verdict %q", v)
			}
		}
	})
}

// TestAuditVerifyJSONOnAFailedRunCannotBeReadAsAGoodOne is the property that
// matters most: the document is still printed, because a monitor needs to know
// where the chain broke, but nothing in it says the log verified.
func TestAuditVerifyJSONOnAFailedRunCannotBeReadAsAGoodOne(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 5, 2, 0)
	pub := auditPubkey(t, keyring)

	data, readErr := os.ReadFile(logs[0])
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	edited := bytes.Replace(data, []byte(`"bytes":1001`), []byte(`"bytes":9001`), 1)
	if bytes.Equal(edited, data) {
		t.Fatal("the test did not find the field it edits")
	}
	if err := os.WriteFile(logs[0], edited, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	doc, err := auditVerifyJSONDoc(t, "--public-key", pub, logs[0])
	if err == nil {
		t.Fatal("an edited log verified")
	}
	// Still a document, and still only a document.
	assertFields(t, doc, append(auditVerifyJSONFields, "error"))
	if doc["verdict"] != auditVerdictFailed {
		t.Errorf("verdict is %v, want %q", doc["verdict"], auditVerdictFailed)
	}
	if reason, _ := doc["error"].(string); reason == "" {
		t.Error("the failure carries no error text, so a consumer cannot say what broke")
	}
	// VerifyChain reports the files that verified whole, so the one that broke
	// is not among them: with a single file there is nothing to report. It must
	// still be an empty array rather than null, so a consumer can iterate it.
	files, ok := doc["files"].([]any)
	if !ok {
		t.Fatalf("files is %#v on a failed run, want an array", doc["files"])
	}
	if len(files) != 0 {
		t.Errorf("files has %d entries, want none: the only file given is the broken one", len(files))
	}
}

// TestAuditVerifyJSONReportsWhatVerifiedBeforeTheBreak is why a failed run
// prints its document at all: across rotated files, the ones that verified
// whole say where the log stops being trustworthy.
func TestAuditVerifyJSONReportsWhatVerifiedBeforeTheBreak(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	pub := auditPubkey(t, keyring)
	logs := writeAuditLog(t, keyring, 40, 4, 2048)
	if len(logs) < 3 {
		t.Fatalf("expected the log to rotate at least twice, got %d files", len(logs))
	}

	// Break the earliest file after the first that carries an entry to edit, so
	// that at least the first file still verifies whole. Which of the rotated
	// files holds what depends on where the size limit fell, so the file is
	// found rather than assumed.
	broken := -1
	for i := 1; i < len(logs); i++ {
		data, readErr := os.ReadFile(logs[i])
		if readErr != nil {
			t.Fatalf("read: %v", readErr)
		}
		edited := bytes.Replace(data, []byte(`"op":"PutObject"`), []byte(`"op":"GetObject"`), 1)
		if bytes.Equal(edited, data) {
			continue
		}
		if err := os.WriteFile(logs[i], edited, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		broken = i
		break
	}
	if broken < 0 {
		t.Fatal("no rotated file after the first carries an entry to edit")
	}

	doc, err := auditVerifyJSONDoc(t, append([]string{"--public-key", pub}, logs...)...)
	if err == nil {
		t.Fatal("a chain with an edited final file verified")
	}
	if doc["verdict"] != auditVerdictFailed {
		t.Errorf("verdict is %v, want %q", doc["verdict"], auditVerdictFailed)
	}
	files := doc["files"].([]any)
	if len(files) != broken {
		t.Errorf("files has %d entries, want %d: the files before the break",
			len(files), broken)
	}
	// And each one still carries its own result, so a monitor can say how far
	// the log was good.
	for i, raw := range files {
		file := raw.(map[string]any)
		assertFields(t, file, auditVerifyFileFields)
		if entries, _ := file["entries"].(float64); entries == 0 {
			t.Errorf("files[%d] reports no entries", i)
		}
	}
}

// TestAuditVerifyJSONRefusesPrint: --print writes every entry to stdout, and
// the document has to be the only thing there.
func TestAuditVerifyJSONRefusesPrint(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 3, 2, 0)

	out, err := auditVerify(t, "--json", "--print", "--keyring", keyring, logs[0])
	if err == nil {
		t.Fatalf("--json --print was accepted:\n%s", out)
	}
	for _, want := range []string{"--json", "--print"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("the refusal printed to stdout:\n%s", out)
	}
}

// TestAuditVerifyJSONRecordsWhatExpectCompared: --expect is what closes the
// truncation window of ADR-016, so whether it was given and whether it held
// belong in the document rather than only in the exit code.
func TestAuditVerifyJSONRecordsWhatExpectCompared(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	pub := auditPubkey(t, keyring)
	logs := writeAuditLog(t, keyring, 5, 3, 0)

	doc, err := auditVerifyJSONDoc(t, "--public-key", pub, logs[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	point := firstFile(t, doc)["last_checkpoint"].(map[string]any)
	seq := uint64(point["seq"].(float64))
	hash := point["hash"].(string)
	recorded := fmt.Sprintf("%d:%s", seq, hash)

	t.Run("absent unless asked for", func(t *testing.T) {
		if _, ok := doc["expect"]; ok {
			t.Errorf("expect is present without the flag: %v", doc["expect"])
		}
	})

	t.Run("a checkpoint that matches", func(t *testing.T) {
		got, err := auditVerifyJSONDoc(t, "--public-key", pub, "--expect", recorded, logs[0])
		if err != nil {
			t.Fatalf("the log did not match its own checkpoint: %v", err)
		}
		assertFields(t, got, append(auditVerifyJSONFields, "expect"))
		if got["verdict"] != auditVerdictVerified {
			t.Errorf("verdict is %v, want %q", got["verdict"], auditVerdictVerified)
		}
		expect := got["expect"].(map[string]any)
		assertFields(t, expect, []string{"chain", "hash", "matched", "seq"})
		if expect["matched"] != true {
			t.Errorf("matched is %v, want true", expect["matched"])
		}
		if expect["hash"] != hash || uint64(expect["seq"].(float64)) != seq {
			t.Errorf("expect records %v:%v, want %d:%s", expect["seq"], expect["hash"], seq, hash)
		}
		if chain, _ := expect["chain"].(string); chain == "" {
			t.Error("chain is empty on a match, so which chain agreed is lost")
		}
	})

	t.Run("a checkpoint that does not match", func(t *testing.T) {
		wrong := fmt.Sprintf("%d:%s", seq, strings.Repeat("0", 64))
		got, err := auditVerifyJSONDoc(t, "--public-key", pub, "--expect", wrong, logs[0])
		if err == nil {
			t.Fatal("a different checkpoint at the same entry was accepted")
		}
		// The chain itself verified, but the run did not, and the verdict is
		// about the run: a consumer reading only the document must not see it
		// as good.
		if got["verdict"] != auditVerdictFailed {
			t.Errorf("verdict is %v, want %q", got["verdict"], auditVerdictFailed)
		}
		expect := got["expect"].(map[string]any)
		if expect["matched"] != false {
			t.Errorf("matched is %v, want false", expect["matched"])
		}
		if _, ok := expect["chain"]; ok {
			t.Errorf("chain is present with no match: %v", expect["chain"])
		}
	})
}

// TestAuditVerifyTextOutputIsUnchanged: the flag adds a document, it does not
// reshape what the command printed before.
func TestAuditVerifyTextOutputIsUnchanged(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	logs := writeAuditLog(t, keyring, 5, 2, 0)
	pub := auditPubkey(t, keyring)

	out, err := auditVerify(t, "--public-key", pub, logs[0])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("the text path printed JSON:\n%s", out)
	}
	for _, want := range []string{"chain and signatures verified", "5 entries", "last checkpoint:"} {
		if !strings.Contains(out, want) {
			t.Errorf("the text output no longer says %q:\n%s", want, out)
		}
	}
}

// TestMarshalAuditVerifyJSONIsValidJSON keeps the document parseable for the
// shapes the command cannot easily be driven into.
func TestMarshalAuditVerifyJSONIsValidJSON(t *testing.T) {
	data, err := marshalAuditVerifyJSON(nil, nil, false, nil, expectOutcome{})
	if err != nil {
		t.Fatalf("marshalAuditVerifyJSON: %v", err)
	}
	var doc auditVerifyJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("the document does not parse: %v\n%s", err, data)
	}
	if doc.Verdict != auditVerdictUnchecked {
		t.Errorf("verdict is %q, want %q with no key and no files", doc.Verdict, auditVerdictUnchecked)
	}
	// files is an empty array rather than null, so a consumer can iterate it
	// without a nil check.
	if !bytes.Contains(data, []byte(`"files": []`)) {
		t.Errorf("files is not an empty array:\n%s", data)
	}
}
