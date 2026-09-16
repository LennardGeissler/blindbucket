# ADR-017 — Listing order under name encryption: buffer and sort, bounded, or refuse

**Status:** Proposed
**Date:** 2026-09-16
**Milestone:** M6
**Would implement:** `internal/proxy` (`listObjects`), `internal/config`

## Context

[ADR-015](ADR-015-object-name-encryption.md) settles how an object key maps to
the key a provider stores it under, and leaves exactly one thing open. S3 returns
keys in lexicographic order of the *stored* key. Encrypted names sort differently
from plaintext ones, so a listing reaches the client in an order that is
arbitrary to it.

That is not cosmetic. ADR-015 measured it against the AWS CLI with a stub
endpoint serving the same eight keys sorted and unsorted:

| Destination listing | `aws s3 sync local s3://bucket --delete` |
|---|---|
| sorted | 0 deletes — correct |
| unsorted | **7 deletes of objects that exist locally** |

The CLI's comparator is a merge-join over two sorted streams. Given an unsorted
one it concludes that present objects are absent and deletes them, with no error
and no warning. The gateway cannot refuse the dangerous case, because `--delete`
is client-side logic it never sees. So name encryption cannot ship at all until
listing order has an answer.

ADR-015 named three candidates and left the choice open, with one number attached
to it: buffering a prefix would cost "roughly 100 MB for a million-object
prefix". This ADR is that decision, and it begins by replacing the estimate —
because the estimate was wrong in a direction that matters, and because it was
the wrong quantity to be estimating.

## What it actually costs

Measured by `BenchmarkBufferedListing` and `BenchmarkBufferedListingLatency` in
`internal/proxy/listbuffer_bench_test.go`, which page through a synthetic prefix,
decrypt every key, accumulate and sort — the design as it would be built.

```
host:   Darwin 25.6.0 arm64, Apple M4, 10 cores
go:     go1.27.1 darwin/arm64
keys:   mean 34.4 B plaintext, realistic depth (photos/2026/03/14/file-0001234.dat)
page:   1000 keys, the S3 default
```

| Prefix | Retained heap | Per object | Gateway CPU |
|---:|---:|---:|---:|
| 10,000 | 2.0 MiB | 214 B | 29 ms |
| 100,000 | 20.3 MiB | 213 B | 285 ms |
| 1,000,000 | 203.1 MiB | 213 B | 3.25 s |

**The memory estimate was half the real figure.** 203 MiB, not 100 MB. The
estimate counted keys; a listing entry is not a key. It carries a timestamp, an
ETag, a storage class and a size, each its own allocation once `encoding/xml` is
done with it, and those fields together outweigh a 34-byte key. 213 bytes per
object is the number to plan against, and it is flat across three orders of
magnitude.

**The binding constraint is not memory.** It is latency, which ADR-015 did not
raise at all. A buffered listing cannot emit its first key until it has seen its
last one, because any key still to come may sort first — so the client waits for
the whole prefix, including `n/1000` sequential upstream round trips that cannot
be overlapped, since each continuation token comes from the response before it.

The gateway's own share above is measured. The round trips are arithmetic over
it, at three plausible provider distances:

| Prefix | Gateway CPU | + local provider (1 ms) | + same region (20 ms) | + cross region (80 ms) |
|---:|---:|---:|---:|---:|
| 10,000 | 29 ms | 0.04 s | 0.2 s | 0.8 s |
| 100,000 | 285 ms | 0.4 s | 2.3 s | 8.3 s |
| 1,000,000 | 3.25 s | 4.2 s | **23.2 s** | **83.2 s** |

A million-object prefix against a provider in the same region makes the client
wait 23 seconds for its first page, and 83 seconds across regions. The AWS CLI's
default read timeout is 60 seconds. The cross-region case does not merely perform
badly; it fails, and it fails after the gateway has already done all the work.

**And the memory is per listing in flight, not per gateway:**

| Bound | Each | × 16 concurrent | × 64 concurrent |
|---:|---:|---:|---:|
| 10,000 | 2.0 MiB | 0.03 GiB | 0.13 GiB |
| 100,000 | 20.3 MiB | 0.32 GiB | 1.27 GiB |
| 1,000,000 | 203.1 MiB | 3.17 GiB | 12.70 GiB |

A bound on the prefix is therefore not by itself a bound on the gateway.

## Decision

### Three tiers, because most listings are cheap

**A prefix that fits in one upstream page is sorted in place.** If the provider
answers with `IsTruncated: false`, the gateway holds the complete answer already:
decrypt, sort, serve. No buffering beyond the page it was always going to hold,
no extra round trip, no state. This is the overwhelmingly common listing, and it
is exactly correct at zero cost — which is the single most important consequence
of the measurements above, because it means the expensive machinery is reached
only by prefixes that paginate.

**A prefix that paginates, up to a configured bound, is buffered.** Page through
it upstream, decrypt each key, sort by plaintext, serve pages from the result.

**A prefix beyond the bound is refused**, with an S3 error naming the limit and
the prefix, rather than served in the wrong order. The failure is loud, it names
its cause, and it cannot silently delete anything.

### The bound is chosen from latency, not from memory

This is the part the measurements change. Picking a bound from a memory budget
would land around a million keys on any ordinary host — at which point the
listing takes 23 seconds and the client has usually given up. Latency binds
roughly an order of magnitude earlier.

The default is **100,000 keys**: 2.3 seconds to the first page against a
same-region provider, 20.3 MiB per listing, and both degrade predictably from
there. It is configurable, because a deployment with a local provider and patient
clients can afford more and a deployment behind a proxy with a 5-second timeout
can afford less.

A second, independent bound caps **concurrent buffered listings**, because the
table above shows the per-prefix bound does not constrain the process. Listings
beyond it wait rather than allocate.

### Buffered listings need state, and that is new

Serving page two of a buffered listing means having the sorted result. Two ways,
and neither is free:

Re-buffering per page is the rejected alternative below — it turns a full walk
into `O(n²/1000)` upstream round trips. So the sorted result is **cached, keyed
by the continuation token**, with a TTL.

That makes listing the first stateful thing in the gateway, against a design
whose statelessness is deliberate — [ADR-006](ADR-006-upload-token.md) went to
the trouble of an encrypted upload token precisely to avoid server state. The
difference is that this state is a *cache*: a miss is correct, merely slow, so a
restart or a second instance re-buffers and answers correctly. The upload token
could not be a cache, because a miss there would lose an upload. Stating the
distinction is what keeps the two decisions consistent rather than contradictory.

The multi-instance case follows: a client whose next page lands on another
instance pays for a re-buffer. Correct, bounded by the same limit, and worth
measuring before it is called acceptable.

## Alternatives considered

**Re-scan per page**, carrying the last plaintext key in the continuation token.
Bounded memory and no state, which is why ADR-015 kept it on the list. Rejected
on arithmetic: each page must re-list the whole prefix to find what follows a
given plaintext key, so a full walk of a million objects is 1000 pages × 1000
round trips = **10⁶ upstream requests** where the buffered design makes 10³. At
the 20 ms round trip above, that is five and a half hours. It solves the memory problem by
making the feature unusable.

**Buffer with no bound at all.** Rejected: the 1M row is not a hypothetical, and
an unbounded buffer turns one client's large prefix into the gateway's memory
ceiling. The project's headline is `O(chunk size)`; "O(whatever the client asked
for)" is not a footnote to that, it is a retraction of it.

**Sort only when the client seems to need it.** There is no such signal.
`--delete` is client-side, and a listing that looks harmless is the same request
as one that precedes a destructive sync.

**Ship unsorted and document it.** Rejected in ADR-015 and re-rejected here. A
footgun that silently destroys data is not something a tool whose argument is
safety can ship behind a row in a compatibility matrix.

**Order-preserving encryption**, so that stored order is plaintext order.
Rejected in ADR-015: it leaks the order relation of every pair of names, which
for sorted data is close to leaking the names.

## Consequences

- `listObjects` gains three paths where it has one, and the single-page path must
  be the one that is obviously correct by inspection.
- Two configuration keys — the per-prefix bound and the concurrent-listing cap —
  both with defaults that work unconfigured, and both documented with the
  measurements above rather than as round numbers.
- A new S3 error for a prefix past the bound, and a row in
  `docs/COMPATIBILITY.md` describing it as a real limit rather than a caveat.
- A listing cache with a TTL, which is the gateway's first server-side state, and
  the first thing a second instance can miss. Its hit rate under a paging client
  is worth a metric.
- `blindbucket_listing_buffered_keys` and a refusal counter, because a bound
  nobody can see being approached is a bound that will be discovered in
  production.
- The benchmarks above stay in the tree and run under `make bench`, so the
  numbers this decision rests on can be re-checked on other hardware rather than
  taken on trust.

## A correction this measurement forced

While measuring, the key-expansion figure in ADR-015 turned out to be a best case
quoted as a rule, and it had reached shipped documentation:
`internal/crypto/names` said encryption costs "roughly 1.6×, so the usable key
length drops from 1024 bytes to something closer to 600".

1.6× is the base32 expansion alone. It omits the 16-byte synthetic IV that each
**segment** carries — so what drives the total is the number of segments, not the
length of the key. `BenchmarkKeyExpansion` measures the longest plaintext key of
each shape that still encrypts to a legal 1024-byte key:

| Key shape | Longest plaintext key | Expansion |
|---|---:|---:|
| one long segment | 624 B | 1.64× |
| realistic tree, long leaf (`photos/2026/03/14/…`) | 560 B | 1.83× |
| segments of 8 | 214 B | 4.79× |
| segments of 4 | 128 B | 8.00× |

The old figure was therefore right for one shape and wrong by nearly five times
for another. The usable length is between **128 and 624 bytes**, decided by a
deployment's naming convention.

This is worth recording as more than a typo, because of how it was found: it
survived an ADR, a code review and a shipped package, and it fell out of a
measurement taken for an unrelated reason. The first attempt at correcting it
overshot in the other direction — deriving ~190 bytes from the 5.3× mean
expansion of *typical* keys, which are short and nowhere near the limit — and
only measuring each shape settled it. Two different questions had been sharing
one number.

ADR-015 and the package documentation are corrected alongside this ADR;
`FORMAT.md` has no name-mapping section yet and gains one with the feature.
