package freshness

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// What the rollback index costs, measured rather than estimated.
//
// ADR-018 turns on these numbers. The index is memory proportional to live
// objects, which is a shape of cost nothing else in this gateway has -- every
// other structure is bounded by a chunk or by one prefix -- so whether the
// feature is affordable is a question about this table and not about the design.
//
// An earlier version of this file measured a prototype, because the decision was
// written before the code. It now measures the code, and ADR-018's table was
// corrected where the two disagreed.

func benchKeyAt(i int) string {
	prefixes := [...]string{"backups", "photos", "logs", "exports", "media"}
	return fmt.Sprintf("%s/%04d/%02d/%02d/object-%08d.bin",
		prefixes[i%len(prefixes)], 2020+i%6, 1+i%12, 1+i%28, i)
}

func benchTagAt(i int) Tag {
	var salt [SaltSize]byte
	for j := range salt {
		salt[j] = byte(i >> (j % 8))
	}
	t, err := TagFromSalts([][SaltSize]byte{salt})
	if err != nil {
		panic(err)
	}
	return t
}

func benchKey(tb testing.TB) []byte {
	tb.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	return k
}

func benchStore(tb testing.TB) *Local {
	tb.Helper()
	l, err := Open(Options{
		Path: filepath.Join(tb.TempDir(), "freshness.idx"),
		Key:  benchKey(tb),
		// High enough that setup is not an fsync benchmark. What an fsync costs
		// is BenchmarkRecord's business.
		SyncEvery: 1 << 30,
	})
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	tb.Cleanup(func() { _ = l.Close() })
	return l
}

// BenchmarkIndexMemory reports the retained heap of the map an instance holds,
// per object and in total.
//
// It measures the map rather than a whole Local, because that is where the cost
// is -- the file contributes a handle and a 48-byte scratch buffer -- and because
// ten million appends would make this an fsync benchmark instead. The entries and
// the hashes are the real ones.
func BenchmarkIndexMemory(b *testing.B) {
	for _, n := range []int{100_000, 1_000_000, 10_000_000} {
		b.Run(fmt.Sprintf("objects=%d", n), func(b *testing.B) {
			l := benchStore(b)

			// Retained heap: a GC with the map still alive is what separates
			// what is held from what was merely allocated on the way. Run with
			// -benchtime=1x so the survivor is one index, not several.
			var m map[nameHash]entry
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			for b.Loop() {
				m = make(map[nameHash]entry, n)
				for i := range n {
					m[l.name("bucket", benchKeyAt(i))] = entry{
						tag: benchTagAt(i), kind: kindPresent, when: int64(i),
					}
				}
			}

			b.StopTimer()
			runtime.GC()
			runtime.ReadMemStats(&after)
			retained := after.HeapAlloc - before.HeapAlloc
			runtime.KeepAlive(m)
			b.ReportMetric(float64(retained)/float64(n), "B/object")
			b.ReportMetric(float64(retained)/(1<<20), "MiB/index")
		})
	}
}

// BenchmarkIndexMemoryPlainNames prices the rejected shape -- names in clear --
// so that hashing them is a trade with a number on both sides rather than a
// reflex.
func BenchmarkIndexMemoryPlainNames(b *testing.B) {
	const n = 1_000_000

	var m map[string]entry
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for b.Loop() {
		m = make(map[string]entry, n)
		for i := range n {
			m["bucket/"+benchKeyAt(i)] = entry{
				tag: benchTagAt(i), kind: kindPresent, when: int64(i),
			}
		}
	}

	b.StopTimer()
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := after.HeapAlloc - before.HeapAlloc
	runtime.KeepAlive(m)
	b.ReportMetric(float64(retained)/float64(n), "B/object")
	b.ReportMetric(float64(retained)/(1<<20), "MiB/index")
}

// BenchmarkCheck is what a read pays for the guarantee: one keyed hash of the
// object's identity and one map lookup, against a request the gateway already
// costs 0.13 ms to serve.
func BenchmarkCheck(b *testing.B) {
	const n = 1_000_000
	l := benchStore(b)
	keys := make([]string, n)
	tags := make([]Tag, n)
	for i := range n {
		keys[i] = benchKeyAt(i)
		tags[i] = benchTagAt(i)
		if err := l.Record("bucket", keys[i], tags[i]); err != nil {
			b.Fatalf("Record: %v", err)
		}
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		v, err := l.Check("bucket", keys[i%n], tags[i%n])
		if err != nil {
			b.Fatalf("Check: %v", err)
		}
		if v != Fresh {
			b.Fatalf("object %d: %v, want fresh", i%n, v)
		}
		i++
	}
}

// BenchmarkRecord is what a write pays: the same hash, a 48-byte append, and an
// fsync once every SyncEvery records. Both settings are measured, because the
// difference between them is the whole of the durability trade.
func BenchmarkRecord(b *testing.B) {
	for _, every := range []int64{1, defaultSyncEvery} {
		b.Run(fmt.Sprintf("sync_every=%d", every), func(b *testing.B) {
			l, err := Open(Options{
				Path:      filepath.Join(b.TempDir(), "freshness.idx"),
				Key:       benchKey(b),
				SyncEvery: every,
			})
			if err != nil {
				b.Fatalf("Open: %v", err)
			}
			defer func() { _ = l.Close() }()

			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if err := l.Record("bucket", benchKeyAt(i), benchTagAt(i)); err != nil {
					b.Fatalf("Record: %v", err)
				}
				i++
			}
		})
	}
}

// BenchmarkOpen is the restart cost. An index is only useful once it has been
// read back, and until then every object is unknown to it.
func BenchmarkOpen(b *testing.B) {
	const n = 1_000_000
	dir := b.TempDir()
	path := filepath.Join(dir, "freshness.idx")
	key := benchKey(b)

	l, err := Open(Options{Path: path, Key: key, SyncEvery: 1 << 30})
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	for i := range n {
		if err := l.Record("bucket", benchKeyAt(i), benchTagAt(i)); err != nil {
			b.Fatalf("Record: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
	size, err := os.Stat(path)
	if err != nil {
		b.Fatalf("Stat: %v", err)
	}

	var loaded *Local
	for b.Loop() {
		reopened, err := Open(Options{Path: path, Key: key})
		if err != nil {
			b.Fatalf("Open: %v", err)
		}
		if got := reopened.Stats().Objects; got != n {
			b.Fatalf("replayed %d objects, want %d", got, n)
		}
		if loaded != nil {
			_ = loaded.Close()
		}
		loaded = reopened
	}

	b.StopTimer()
	if loaded != nil {
		_ = loaded.Close()
	}
	b.ReportMetric(float64(size.Size())/float64(n), "B/object-on-disk")
	b.ReportMetric(float64(size.Size())/(1<<20), "MiB/file")
}
