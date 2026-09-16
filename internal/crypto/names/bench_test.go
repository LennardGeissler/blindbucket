package names

import (
	"crypto/rand"
	"strings"
	"testing"
)

// BenchmarkKeyExpansion records what encryption costs a key in length, which is
// not one number: the 16-byte synthetic IV is charged per *segment*, so the
// expansion is driven by how many segments a key has rather than how long it is.
//
// The figures below are what ADR-015's key-length section and ADR-017's
// correction rest on, and the reason the first version of that section was
// wrong in both directions at once -- 1.6x is the encoding alone, which is right
// for a key that is one long segment and far too low for a deep path of short
// ones.
//
// Reported per shape as the longest plaintext key that still encrypts to a legal
// S3 key, because that is the limit a client actually hits.
func BenchmarkKeyExpansion(b *testing.B) {
	enc := benchEncrypter(b)

	shapes := []struct {
		name  string
		build func(n int) string
	}{
		{"one-long-segment", func(n int) string { return strings.Repeat("a", n) }},
		{"realistic-tree", func(n int) string {
			const base = "photos/2026/03/14/"
			if n <= len(base) {
				return strings.Repeat("a", n)
			}
			return base + strings.Repeat("a", n-len(base))
		}},
		{"segments-of-8", func(n int) string { return benchChunked(n, 8) }},
		{"segments-of-4", func(n int) string { return benchChunked(n, 4) }},
	}

	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			longest := 0
			for n := 1; n <= MaxStoredKey; n++ {
				if _, err := enc.EncryptKey(shape.build(n)); err != nil {
					break
				}
				longest = n
			}
			if longest == 0 {
				b.Fatal("no key of this shape encrypts")
			}
			stored, err := enc.EncryptKey(shape.build(longest))
			if err != nil {
				b.Fatalf("EncryptKey: %v", err)
			}
			b.ResetTimer()
			for b.Loop() {
				if _, err := enc.EncryptKey(shape.build(longest)); err != nil {
					b.Fatalf("EncryptKey: %v", err)
				}
			}

			// Reported after the loop: metrics set before it are discarded.
			b.ReportMetric(float64(longest), "B/max-plaintext-key")
			b.ReportMetric(float64(len(stored))/float64(longest), "expansion")
		})
	}
}

func benchChunked(n, seg int) string {
	var sb strings.Builder
	sb.Grow(n)
	for i := range n {
		if i > 0 && i%seg == 0 {
			sb.WriteByte('/')
		} else {
			sb.WriteByte('a')
		}
	}
	return sb.String()
}

func benchEncrypter(tb testing.TB) *Encrypter {
	tb.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	enc, err := New(key)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return enc
}
