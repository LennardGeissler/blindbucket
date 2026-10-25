package tags

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func dek(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, dekSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var someTags = []Tag{{"project", "blue"}, {"owner", "alice"}, {"empty", ""}}

func TestSealOpenRoundTrip(t *testing.T) {
	k := dek(t)
	body, err := Seal(k, "photos", "2026/beach.jpg", someTags)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(k, "photos", "2026/beach.jpg", body)
	if err != nil {
		t.Fatal(err)
	}
	want := []Tag{{"empty", ""}, {"owner", "alice"}, {"project", "blue"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v, sorted by key", got, want)
		}
	}
	if bytes.Contains(body, []byte("alice")) {
		t.Fatal("the sidecar holds a value in the clear")
	}
}

// TestASidecarOpensOnlyForItsObjectVersion is what the binding is for: moved
// to another key or bucket, or left over from another version, it does not
// open, and neither does one that was altered.
func TestASidecarOpensOnlyForItsObjectVersion(t *testing.T) {
	k := dek(t)
	body, err := Seal(k, "photos", "a.jpg", someTags)
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Clone(body)
	altered[len(altered)-1] ^= 1
	for name, open := range map[string]func() error{
		"another key":     func() error { _, err := Open(k, "photos", "b.jpg", body); return err },
		"another bucket":  func() error { _, err := Open(k, "videos", "a.jpg", body); return err },
		"another version": func() error { _, err := Open(dek(t), "photos", "a.jpg", body); return err },
		"altered":         func() error { _, err := Open(k, "photos", "a.jpg", altered); return err },
	} {
		if err := open(); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	if _, err := Open(k, "photos", "a.jpg", append([]byte("BBT2"), body[4:]...)); !errors.Is(err, ErrMalformed) {
		t.Errorf("another magic: %v, want ErrMalformed", err)
	}
}

// TestDecodeRefusesWhatIsNotCanonical: one tag set, one encoding.
func TestDecodeRefusesWhatIsNotCanonical(t *testing.T) {
	good, err := Encode([]Tag{{"a", "1"}, {"b", "2"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(good); err != nil {
		t.Fatalf("the canonical encoding: %v", err)
	}
	unsorted := []byte{2, 0, 1, 'b', 0, 1, '2', 0, 1, 'a', 0, 1, '1'}
	twice := []byte{2, 0, 1, 'a', 0, 1, '1', 0, 1, 'a', 0, 1, '2'}
	for name, b := range map[string][]byte{
		"unsorted":         unsorted,
		"a key twice":      twice,
		"an empty key":     {1, 0, 0, 0, 0},
		"eleven tags":      {11},
		"trailing bytes":   append(bytes.Clone(good), 0),
		"cut short":        good[:len(good)-1],
		"no count at all":  {},
		"a prefix cut off": {1, 0},
	} {
		if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
	if b, err := Encode(nil); err != nil || !bytes.Equal(b, []byte{0}) {
		t.Errorf("the empty set encodes as %x, %v; want 00", b, err)
	}
}

func TestValidateAppliesS3sRules(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	ok := [][]Tag{
		nil,
		{{"project", "blue"}},
		{{"Abteilung", "Straße 1"}, {"path", "a/b:c@d=e+f-g_h.i"}},
		{{long(128), long(256)}},
	}
	for _, set := range ok {
		if err := Validate(set); err != nil {
			t.Errorf("%v: %v", set, err)
		}
	}
	eleven := make([]Tag, 11)
	for i := range eleven {
		eleven[i] = Tag{Key: string(rune('a' + i)), Value: "v"}
	}
	bad := map[string][]Tag{
		"eleven tags":        eleven,
		"an empty key":       {{"", "v"}},
		"a key of 129":       {{long(129), "v"}},
		"a value of 257":     {{"k", long(257)}},
		"a key twice":        {{"k", "1"}, {"k", "2"}},
		"the aws: prefix":    {{"aws:createdBy", "me"}},
		"a character not in": {{"k", "a&b"}},
		"a newline":          {{"k", "a\nb"}},
	}
	for name, set := range bad {
		if err := Validate(set); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("%s: %v, want ErrInvalidTag", name, err)
		}
	}
}

func TestBindingAndPath(t *testing.T) {
	a, b := BindingID("wrapped-one"), BindingID("wrapped-two")
	if a == b || len(a) != 22 {
		t.Fatalf("binding ids %q and %q", a, b)
	}
	p := Path("photos/a.jpg", "wrapped-one")
	if !strings.HasPrefix(p, PrefixFor("photos/a.jpg")) || !strings.HasSuffix(p, "/"+a) ||
		!strings.HasPrefix(p, ".blindbucket/t/") || strings.Contains(p, "photos") {
		t.Fatalf("path %q", p)
	}
}
