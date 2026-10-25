package tags

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateVectors = flag.Bool("update", false, "regenerate testdata/vectors/tags_v1.json")

const vectorPath = "../../../testdata/vectors/tags_v1.json"

// vectorFile is the on-disk shape of the tag vectors. It is a normative part of
// docs/FORMAT.md section 17: an implementation that reproduces every encoded
// set, sidecar and path below, byte for byte, implements the section.
type vectorFile struct {
	Note    string      `json:"note"`
	Vectors []tagVector `json:"vectors"`
}

type tagVector struct {
	Name       string `json:"name"`
	DEK        string `json:"dek"`
	Nonce      string `json:"nonce"`
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	StoredKey  string `json:"stored_key"`
	WrappedDEK string `json:"wrapped_dek"`
	Tags       []Tag  `json:"tags"`
	Encoded    string `json:"encoded"`
	Sidecar    string `json:"sidecar"`
	Path       string `json:"path"`
}

// vectorSpecs cluster on what an implementation gets wrong quietly: the order
// a set is encoded in, an empty set and an empty value, the full ten, and
// characters outside ASCII.
var vectorSpecs = []struct {
	name, key, stored string
	tags              []Tag
}{
	{"empty set", "report.pdf", "report.pdf", nil},
	{"one tag", "report.pdf", "report.pdf", []Tag{{"project", "blue"}}},
	{"given unsorted", "a/b.txt", "a/b.txt", []Tag{{"zeta", "3"}, {"alpha", "1"}, {"mid", "2"}}},
	{"an empty value", "a/b.txt", "a/b.txt", []Tag{{"archived", ""}}},
	{"utf-8", "urlaub/münchen.jpg", "urlaub/münchen.jpg", []Tag{{"Ort", "München"}, {"Straße", "Ü 1"}}},
	// Under name encryption the path follows the stored key and the seal the
	// key the client named; this stored key stands in for an encrypted one.
	{"stored key differs from the key", "photos/beach.jpg", "OBUGK3DPMRZQ/MJSWC4TBMNUA", []Tag{{"owner", "alice"}}},
	{"ten tags", "full", "full", tenTags()},
	{"longest key and value", "long", "long", []Tag{{strings.Repeat("k", 128), strings.Repeat("v", 256)}}},
}

func tenTags() []Tag {
	out := make([]Tag, 10)
	for i := range out {
		out[i] = Tag{Key: fmt.Sprintf("key-%d", i), Value: fmt.Sprintf("value %d", i)}
	}
	return out
}

// vectorBytes derives fixed key material from a vector's position and a label.
func vectorBytes(i int, label string, n int) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("blindbucket tags vector %d %s", i, label)))
	return sum[:n]
}

func build(i int, spec struct {
	name, key, stored string
	tags              []Tag
}) (tagVector, error) {
	d := vectorBytes(i, "dek", dekSize)
	var nonce [NonceSize]byte
	copy(nonce[:], vectorBytes(i, "nonce", NonceSize))
	wrapped := hex.EncodeToString(vectorBytes(i, "wrapped", 32))
	encoded, err := Encode(spec.tags)
	if err != nil {
		return tagVector{}, err
	}
	sidecar, err := sealWithNonce(d, "bucket", spec.key, spec.tags, nonce)
	if err != nil {
		return tagVector{}, err
	}
	sorted, err := Decode(encoded)
	if err != nil {
		return tagVector{}, err
	}
	return tagVector{
		Name: spec.name, DEK: hex.EncodeToString(d), Nonce: hex.EncodeToString(nonce[:]),
		Bucket: "bucket", Key: spec.key, StoredKey: spec.stored, WrappedDEK: wrapped,
		Tags: sorted, Encoded: hex.EncodeToString(encoded), Sidecar: hex.EncodeToString(sidecar),
		Path: Path(spec.stored, wrapped),
	}, nil
}

func TestKnownAnswerVectors(t *testing.T) {
	file := vectorFile{Note: "docs/FORMAT.md section 17. Normative: reproduce encoded, sidecar " +
		"and path byte for byte. tags are listed in their canonical order; wrapped_dek stands " +
		"in for an object's bb-dek, and the path is derived from it and stored_key."}
	for i, spec := range vectorSpecs {
		v, err := build(i, spec)
		if err != nil {
			t.Fatalf("%s: %v", spec.name, err)
		}
		file.Vectors = append(file.Vectors, v)
	}
	if *updateVectors {
		raw, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("reading the vectors (regenerate with -update): %v", err)
	}
	var stored vectorFile
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Vectors) != len(file.Vectors) {
		t.Fatalf("%d vectors on disk, %d built", len(stored.Vectors), len(file.Vectors))
	}
	for i, want := range stored.Vectors {
		got := file.Vectors[i]
		if got.Encoded != want.Encoded || got.Sidecar != want.Sidecar || got.Path != want.Path {
			t.Errorf("%s: the implementation no longer reproduces the vector", want.Name)
		}
		// And the stored sidecar opens, from the vector's inputs alone.
		d, _ := hex.DecodeString(want.DEK)
		body, _ := hex.DecodeString(want.Sidecar)
		tags, err := Open(d, want.Bucket, want.Key, body)
		if err != nil {
			t.Errorf("%s: the stored sidecar does not open: %v", want.Name, err)
			continue
		}
		enc, _ := Encode(tags)
		if !bytes.Equal(enc, mustHex(want.Encoded)) {
			t.Errorf("%s: it opens to another set", want.Name)
		}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
