package proxy

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// What a buffered listing would cost, measured rather than estimated.
//
// ADR-015 leaves one decision open: with encrypted names the provider sorts by
// the stored key, so a listing reaches the client in an order that is arbitrary
// to it -- and an unsorted listing makes `aws s3 sync --delete` delete objects
// that exist. The leading answer is to buffer a whole prefix, decrypt, sort and
// serve pages from that, and the objection to it is memory: ADR-015 puts it at
// "roughly 100 MB for a million-object prefix" against a design whose headline
// is O(chunk size).
//
// That figure is an estimate of the keys alone. A listing entry is not a key: it
// carries a timestamp, an ETag, a storage class and a size, each its own
// allocation once encoding/xml is done with it. This measures the whole entry,
// which is what a buffer would actually hold.
//
// It measures a prototype of a design under consideration, not shipped code --
// the proxy does not encrypt names yet. It lives here because this is the
// package the code would live in, and it is committed because ADR-017 rests on
// its numbers.

// benchKeyAt mints the i-th plaintext key of a synthetic but realistically
// shaped bucket: a handful of top-level prefixes over a date tree.
//
// Derived from i rather than drawn from a slice, so that generating a million
// keys retains nothing and the measurement sees only the buffer.
func benchKeyAt(i int) string {
	tops := [...]string{"photos", "invoices", "backups", "exports", "logs"}
	return fmt.Sprintf("%s/%04d/%02d/%02d/file-%07d.dat",
		tops[i%len(tops)], 2024+(i/500000)%3, 1+(i/40000)%12, 1+(i/1300)%28, i)
}

// benchEntryAt builds the listing entry a provider would return for it, with
// the key already encrypted.
//
// Every string field is freshly allocated. Shared literals would understate the
// result badly: encoding/xml allocates a new string per field, and those fields
// outweigh a short key.
func benchEntryAt(tb testing.TB, enc *names.Encrypter, i int) upstream.ObjectEntry {
	tb.Helper()
	stored, err := enc.EncryptKey(benchKeyAt(i))
	if err != nil {
		tb.Fatalf("EncryptKey: %v", err)
	}
	return upstream.ObjectEntry{
		Key:          stored,
		LastModified: fmt.Sprintf("2026-09-%02dT%02d:%02d:%02dZ", 1+i%28, i%24, i%60, (i*7)%60),
		ETag:         fmt.Sprintf("%q", fmt.Sprintf("%032x-%d", i, 1+i%8)),
		Size:         int64(i) * 1024,
		StorageClass: strings.Clone("STANDARD"),
	}
}

func benchEncrypter(tb testing.TB) *names.Encrypter {
	tb.Helper()
	key := make([]byte, names.KeySize)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	enc, err := names.New(key)
	if err != nil {
		tb.Fatalf("names.New: %v", err)
	}
	return enc
}

// bufferPrefix is the design under measurement: page through a prefix, decrypt
// each key, accumulate, and sort by the plaintext.
//
// Pages are minted one at a time and dropped, as the real pipeline drops an
// upstream response once its entries are taken -- so what survives the call is
// exactly what a gateway would be holding.
func bufferPrefix(tb testing.TB, enc *names.Encrypter, n, pageSize int) []upstream.ObjectEntry {
	tb.Helper()
	buf := make([]upstream.ObjectEntry, 0, n)
	for start := 0; start < n; start += pageSize {
		end := min(start+pageSize, n)
		page := make([]upstream.ObjectEntry, 0, end-start)
		for i := start; i < end; i++ {
			page = append(page, benchEntryAt(tb, enc, i))
		}
		buf = appendDecrypted(tb, enc, buf, page)
	}
	sortByKey(buf)
	return buf
}

// benchPages builds every page of a prefix up front, for the measurements that
// must not pay for generating their own input.
func benchPages(tb testing.TB, enc *names.Encrypter, n, pageSize int) [][]upstream.ObjectEntry {
	tb.Helper()
	pages := make([][]upstream.ObjectEntry, 0, (n+pageSize-1)/pageSize)
	for start := 0; start < n; start += pageSize {
		end := min(start+pageSize, n)
		page := make([]upstream.ObjectEntry, 0, end-start)
		for i := start; i < end; i++ {
			page = append(page, benchEntryAt(tb, enc, i))
		}
		pages = append(pages, page)
	}
	return pages
}

// gatherSorted is the gateway's share of a buffered listing, and nothing else.
func gatherSorted(tb testing.TB, enc *names.Encrypter, pages [][]upstream.ObjectEntry) []upstream.ObjectEntry {
	tb.Helper()
	n := 0
	for _, page := range pages {
		n += len(page)
	}
	buf := make([]upstream.ObjectEntry, 0, n)
	for _, page := range pages {
		buf = appendDecrypted(tb, enc, buf, page)
	}
	sortByKey(buf)
	return buf
}

func appendDecrypted(tb testing.TB, enc *names.Encrypter, buf, page []upstream.ObjectEntry) []upstream.ObjectEntry {
	tb.Helper()
	for _, entry := range page {
		plain, err := enc.DecryptKey(entry.Key)
		if err != nil {
			tb.Fatalf("DecryptKey: %v", err)
		}
		entry.Key = plain
		buf = append(buf, entry)
	}
	return buf
}

func sortByKey(buf []upstream.ObjectEntry) {
	slices.SortFunc(buf, func(a, b upstream.ObjectEntry) int {
		return strings.Compare(a.Key, b.Key)
	})
}

// BenchmarkBufferedListing reports the retained heap of a buffered prefix, per
// object and in total, alongside the time the first page costs -- because the
// client waits for the whole prefix before it sees one entry.
func BenchmarkBufferedListing(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("objects=%d", n), func(b *testing.B) {
			enc := benchEncrypter(b)

			// Retained heap: a GC with the buffer still alive is what separates
			// what is held from what was merely allocated on the way. Run with
			// -benchtime=1x so that the survivor is one prefix, not several.
			var buf []upstream.ObjectEntry
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			b.ReportAllocs()
			for b.Loop() {
				buf = bufferPrefix(b, enc, n, 1000)
			}

			b.StopTimer()
			runtime.GC()
			runtime.ReadMemStats(&after)
			retained := after.HeapAlloc - before.HeapAlloc
			runtime.KeepAlive(buf)
			b.ReportMetric(float64(retained)/float64(n), "B/object")
			b.ReportMetric(float64(retained)/(1<<20), "MiB/prefix")
		})
	}
}

// BenchmarkBufferedListingLatency measures the gateway's own share: decrypting
// every key of a prefix, accumulating and sorting.
//
// The pages are built before the timer starts. BenchmarkBufferedListing has to
// mint them inside the measured region to keep its heap honest, which makes it
// pay for an encryption the real gateway never performs -- the provider hands it
// stored keys already. This is the half that would actually be on the clock.
//
// It is a floor, not the latency a client would see: a prefix of n objects is
// also n/1000 sequential upstream round trips, and none of the work below can
// start on the first page until the last one has arrived, because any key still
// to come may sort first.
func BenchmarkBufferedListingLatency(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("objects=%d", n), func(b *testing.B) {
			enc := benchEncrypter(b)
			pages := benchPages(b, enc, n, 1000)

			b.ReportAllocs()
			for b.Loop() {
				runtime.KeepAlive(gatherSorted(b, enc, pages))
			}
			b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N*n), "us/object")
		})
	}
}

// BenchmarkMeanKeyLength records what the figures above are a function of, so
// that a reader can scale them to a bucket whose keys are not this long.
func BenchmarkMeanKeyLength(b *testing.B) {
	enc := benchEncrypter(b)
	var plain, stored int
	const n = 10_000
	for i := range n {
		p := benchKeyAt(i)
		s, err := enc.EncryptKey(p)
		if err != nil {
			b.Fatalf("EncryptKey: %v", err)
		}
		plain += len(p)
		stored += len(s)
	}
	b.ReportMetric(float64(plain)/n, "B/plaintext-key")
	b.ReportMetric(float64(stored)/n, "B/stored-key")
	b.ReportMetric(float64(stored)/float64(plain), "expansion")
}
