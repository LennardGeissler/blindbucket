# The laptop figures, measured again, 2026-10-07

The README's table of laptop figures dates from before `v0.1.0`, and for some of
them nothing in the repository showed where they came from. These are the same
measurements against `56f0ac6` (`1.1.0` plus documentation), with the output of
every run kept in [`raw/`](raw/).

Apple M4, 10 cores, 16 GiB, macOS 25.6.0, Go 1.27.1. The rotation ran against
MinIO `RELEASE.2026-09-22T19-25-18Z` in Docker on the same machine
([`raw/environment.txt`](raw/environment.txt)).

| File | What it is |
|---|---|
| [`raw/micro.txt`](raw/micro.txt) | `go test -p 1 -run '^$' -bench . -benchmem -count 6` over `crypto/stream`, `crypto/names`, `freshness`, `audit` and `proxy` |
| [`raw/micro-first-pass.txt`](raw/micro-first-pass.txt) | The same, minutes earlier, without `-p 1` |
| [`raw/stream-10gib.txt`](raw/stream-10gib.txt) | `TestLargeStreamRoundTrip` with `BLINDBUCKET_STREAM_SIZE=10GiB` |
| [`raw/rotate-{1,2,3}.txt`](raw/) | `TestIntegrationRotateAtScale`, three runs |
| [`raw/rotate-around-adr025.txt`](raw/rotate-around-adr025.txt) | The same test at the commit before ADR-025's open-upload check and at the commit that added it |

## Results

Medians of six runs; the range is the lowest and highest of the six.

| Measurement | Now | Before |
|---|---:|---:|
| Encrypt, 64 KiB chunks | **7.13 GB/s** (6.89–7.22) | 7.2 GB/s |
| Decrypt, 64 KiB chunks | **6.88 GB/s** (6.76–6.95) | 7.0 GB/s |
| Seal one 64 KiB chunk, steady state | 8.24 GB/s, **0 allocations** | 0 allocations |
| Allocations per 8 MiB stream | 22 encrypting, 26 decrypting | the same |
| 10 GiB encrypt + decrypt | **0.5 MiB** peak Go heap | 0.5 MiB |
| Freshness check on a read | 294 ns (291–297) | 279 ns |
| Freshness record on a write, fsync every 256 | 18.9 µs (18.4–19.1) | 21.3 µs |
| Freshness index, 1 M objects | 112.1 MiB, 117.5 B/object | the same |
| Sorted listing, gateway CPU for 100 000 keys | 301 ms (299–303) | 285 ms |
| Sorted listing, retained heap per key | 213 B | the same |
| Audit append / append with checkpoint | 3.6 µs / 22.3 µs | 3.6 µs / — |
| Rotation, 1000 × 64 KiB | **1.61–1.71 s, 2.5 MiB on the wire** (3 runs) | 1.5 s, 1.4 MiB |

Everything but the rotation moved by a few per cent, in both directions, which
is what the same laptop on a different day does. The "before" figures were single
runs; these are the ones to quote.

## The rotation moves more bytes than it did

2598 bytes per object, three runs out of three, where `ADR-009` recorded about
1500. Running the same test at the commits around
[ADR-025](../../../docs/adr/ADR-025-writes-rank-by-when-they-began.md) puts the
whole difference on one change: 1644 bytes per object before
`objcopy.YieldToUploads`, 2598 with it. That is the `ListMultipartUploads` each
object now makes before its copy completes, so that a rotation gives way to a
client's upload of the same key — the request and its XML answer, about 950 bytes.
ADR-025 names the request as the cost of the fix; this is its size.

The invariant ADR-009 claims is unchanged: the cost per object does not grow with
the object. 62.5 MiB of payload, 2.5 MiB on the wire. The time is too: the
listing is one more round trip to a provider on the same machine.

## What the first pass got wrong, and what it did not

The first pass of the micro-benchmarks ran without `-p 1`, on the assumption that
`go test` would run the five packages' benchmarks at the same time and let them
compete for the cores. It does not: the go command makes each benchmark run wait
for the one before it ("Force benchmarks to run in serial", `cmd/go/internal/test`
in Go 1.27.1), and the first pass took as long as the five packages end to end. Its figures agree with the second pass to within a few per
cent. It is kept rather than discarded, as a second sample of the same
measurement.

## What is not here

The gateway's resident memory with real clients — 12 MiB for one 5 GiB stream,
56 MiB per instance for a 5 GiB multipart upload across two, 82 MiB for 10 GiB
with ten parts in flight — comes from `bench/gateway-memory.sh` and was not
measured again. Its figure is [`../memory-light.svg`](../memory-light.svg); the
run behind it is not committed.
