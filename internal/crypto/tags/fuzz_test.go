package tags

import (
	"bytes"
	"testing"
)

// FuzzDecode is what canonical means: whatever Decode accepts, Encode writes
// back as exactly the same bytes, so no tag set has two encodings.
func FuzzDecode(f *testing.F) {
	for _, set := range [][]Tag{nil, someTags, tenTags()} {
		b, err := Encode(set)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{2, 0, 1, 'b', 0, 0, 0, 1, 'a', 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		set, err := Decode(b)
		if err != nil {
			return
		}
		again, err := Encode(set)
		if err != nil {
			t.Fatalf("Decode accepted a set Encode refuses: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("two encodings of one set: %x and %x", b, again)
		}
	})
}

// FuzzOpen: a sidecar from anywhere either opens to a canonical set or is
// refused, and never panics.
func FuzzOpen(f *testing.F) {
	key := bytes.Repeat([]byte{7}, dekSize)
	if body, err := Seal(key, "b", "k", someTags); err == nil {
		f.Add(body)
	}
	f.Add([]byte("BBT1"))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = Open(key, "b", "k", body)
	})
}
