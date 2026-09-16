package names

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateVectors = flag.Bool("update", false, "regenerate testdata/vectors/names_v1.json")

const vectorPath = "../../../testdata/vectors/names_v1.json"

// vectorFile is the on-disk shape of the name-mapping vectors. It is a normative
// part of docs/FORMAT.md section 15: an implementation that reproduces every
// stored key below, character for character, implements the mapping.
type vectorFile struct {
	Note    string       `json:"note"`
	Vectors []nameVector `json:"vectors"`
}

type nameVector struct {
	Name         string `json:"name"`
	NameKey      string `json:"name_key"`
	PlaintextKey string `json:"plaintext_key"`
	StoredKey    string `json:"stored_key"`
}

// vectorSpecs are the cases the vectors pin. They cluster on the things an
// implementation gets wrong quietly: the context a segment is bound to, empty
// segments, and the separators at either end of a key.
var vectorSpecs = []struct{ name, key string }{
	{"empty key", ""},
	{"one segment", "report.pdf"},
	{"two segments", "photos/beach.jpg"},
	{"deep path", "a/b/c/d/e/f.txt"},
	// The pair that shows the context is load-bearing: the same leaf under two
	// parents must not encrypt the same way.
	{"same leaf under photos", "photos/report.pdf"},
	{"same leaf under invoices", "invoices/report.pdf"},
	// And the pair that shows it is only the *parent* that separates them: two
	// siblings of one name are one key, so this is the same vector twice under
	// different names is not possible -- instead, a sibling pair in one tree.
	{"sibling one", "shared/a/report.pdf"},
	{"sibling two", "shared/b/report.pdf"},
	{"empty middle segment", "a//b"},
	{"leading separator", "/leading"},
	{"trailing separator", "trailing/"},
	{"single character segments", "a/b/c"},
	{"utf-8 segment", "urlaub/münchen/straße.txt"},
	{"space and punctuation", "my documents/report (final).pdf"},
	{"long single segment", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
}

// vectorNameKey derives a fixed name key from the vector's position, so every
// vector uses different key material while staying reproducible.
func vectorNameKey(i int) []byte {
	key := make([]byte, KeySize)
	for j := range key {
		key[j] = byte(i*KeySize + j)
	}
	return key
}

func buildVectors(t *testing.T) []nameVector {
	t.Helper()
	out := make([]nameVector, 0, len(vectorSpecs))
	for i, spec := range vectorSpecs {
		key := vectorNameKey(i)
		enc, err := New(key)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		stored, err := enc.EncryptKey(spec.key)
		if err != nil {
			t.Fatalf("EncryptKey(%q): %v", spec.key, err)
		}
		out = append(out, nameVector{
			Name:         spec.name,
			NameKey:      hex.EncodeToString(key),
			PlaintextKey: spec.key,
			StoredKey:    stored,
		})
	}
	return out
}

// TestKnownAnswerVectors checks the committed vectors in both directions. Run
// with -update to regenerate the file after a deliberate change; a change that
// was not deliberate shows up here as a failure.
func TestKnownAnswerVectors(t *testing.T) {
	if *updateVectors {
		file := vectorFile{
			Note: "Known-answer vectors for the blindbucket object name mapping, " +
				"normative alongside docs/FORMAT.md section 15. The name key and the " +
				"plaintext key are fixed, so the stored key is fully determined. " +
				"Regenerate with: go test ./internal/crypto/names -update",
			Vectors: buildVectors(t),
		}
		data, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(vectorPath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %d vectors to %s", len(file.Vectors), vectorPath)
		return
	}

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors: %v (generate them with -update)", err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) != len(vectorSpecs) {
		t.Fatalf("vector file has %d entries, the generator produces %d",
			len(file.Vectors), len(vectorSpecs))
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			key, err := hex.DecodeString(v.NameKey)
			if err != nil {
				t.Fatalf("name key is not hex: %v", err)
			}
			enc, err := New(key)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			stored, err := enc.EncryptKey(v.PlaintextKey)
			if err != nil {
				t.Fatalf("EncryptKey: %v", err)
			}
			if stored != v.StoredKey {
				t.Errorf("stored key drifted:\n got %q\nwant %q", stored, v.StoredKey)
			}

			back, err := enc.DecryptKey(v.StoredKey)
			if err != nil {
				t.Fatalf("DecryptKey(%q): %v", v.StoredKey, err)
			}
			if back != v.PlaintextKey {
				t.Errorf("round trip gave %q, want %q", back, v.PlaintextKey)
			}
		})
	}
}

// TestVectorsCoverTheContextRule is the vectors' own sanity check: if the two
// "same leaf" vectors ever agreed, the context would not be binding and the
// mapping would be leaking which directories hold a file of the same name.
func TestVectorsCoverTheContextRule(t *testing.T) {
	key := vectorNameKey(0)
	enc, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	underPhotos, err := enc.EncryptKey("photos/report.pdf")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	underInvoices, err := enc.EncryptKey("invoices/report.pdf")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	leaf := func(k string) string { return k[len(k)-28:] }
	if leaf(underPhotos) == leaf(underInvoices) {
		t.Error("the same leaf encrypted identically under two parents")
	}
}
