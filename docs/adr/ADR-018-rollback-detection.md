# ADR-018 — Rollback detection: a local freshness index, trust on first use

**Status:** Accepted
**Date:** 2026-09-16
**Milestone:** M6
**Implements:** `internal/freshness`, `internal/proxy`, `internal/crypto/keys`, `internal/config`, `blindbucket keygen --add-freshness-key`

## Context

`THREAT_MODEL` §5.1 is the one row in the risk table that says **No**, and it has
said so since M0:

> If the provider serves an older but genuine version of the same object — from its
> own versioning, for instance — that version is cryptographically valid: the proxy
> produced it, and it is bound to the same bucket and key. Nothing in the format
> distinguishes "current" from "previous".

Every other active-provider attack in that table is closed by something the format
already carries. A swapped object is caught by the wrapping AAD, which binds bucket
and key ([ADR-002](ADR-002-key-hierarchy.md)). A reordered or substituted *part* is
caught by the salt the manifest records
([ADR-014](ADR-014-part-salts-in-the-manifest.md)). A truncated object is caught by
the size check of `FORMAT.md` §10.4. Rollback is left because it is the one attack
where the bytes are not wrong — they are simply from a write that is no longer the
current one, and no property of a single object can say so. Freshness is not a
property of a message; it is a property of a message *relative to what was seen
before*. Something has to remember.

Two earlier decisions say what remembering is allowed to cost.

**[ADR-002](ADR-002-key-hierarchy.md) rejected the index, and deferred this.** Among
its alternatives:

> **Storing wrapped DEKs in a sidecar index object or a database.** […] would enable
> a rollback-detecting version index. Rejected for now: it reintroduces shared mutable
> state, which is exactly what goal G5 (stateless horizontal scaling) avoids, and it
> creates a consistency problem between index and object. […] The rollback mitigation
> is deferred to M6.

**[ADR-016](ADR-016-audit-log.md) declined to be this feature**, in its own words, so
that a log named "audit" would not be mistaken for one: *"A log of what the gateway did
is not an authority on what the current version of an object is, and nothing here makes
a read consult it."*

This is that deferred decision.

## The object already says which write it is

The first question is what a reader would even compare, and the answer needs no new
format: `FORMAT.md` §4.1 requires a **fresh 20-byte salt per segment**, *including for
every retried attempt at the same part number*. That requirement exists to make nonce
reuse impossible, and [ADR-014](ADR-014-part-salts-in-the-manifest.md) already noticed
it does double duty — it identifies the attempt, so the manifest only has to write it
down.

This is that move one level up. A salt already identifies a *write*; something only has
to write down which write is current.

Three properties make the salt the right value rather than an adequate one.

- **It is authenticated.** The header is associated data of every chunk in the segment
  (§4.3), so a provider cannot forge a salt without breaking every tag. It can only
  serve a whole genuine segment — which is exactly the attack.
- **It survives key rotation.** [ADR-009](ADR-009-rotation-by-copy.md) rotates by
  re-wrapping metadata and explicitly *does not move ciphertext*. The salts are in the
  ciphertext, so a rotated object is the same write and the index needs no update. The
  wrapped DEK, the other candidate, changes on every re-wrap and would have made
  `rotate` invalidate the entire index.
- **It is already on the read path.** §10.4 requires a reader to load the manifest and
  compare each part's salt against its header before releasing plaintext. Both are read
  anyway; nothing extra is fetched.

So the recorded value is

```
tag = SHA-256("blindbucket/v1/freshness-tag" || uint32_be(n) || salt_1 || … || salt_n)[0:16]
```

over the segment salts in part order — one salt for a single-part object. Sixteen bytes
is not a birthday bound: an attacker cannot choose salts, so the question is
second-preimage over values the gateway generated, and 128 bits is far past what that
needs.

Nothing in `FORMAT.md` changes. The only open question is **where the tag is written
down, and what keeping it costs.**

## What remembering costs, measured

Apple M4, Go 1.27.1, from [`internal/freshness/bench_test.go`](../../internal/freshness/bench_test.go).

| | |
|---|---|
| Index of 100 000 objects | **7.0 MiB** (73 B/object) |
| Index of 1 000 000 objects | **112.1 MiB** (118 B/object) |
| Index of 10 000 000 objects | **896.6 MiB** (94 B/object) |
| The same index with names in clear, 1 M objects | 157.9 MiB (166 B/object) |
| One check on a read — keyed hash and lookup | **279 ns** |
| One record on a write, fsync every 256 | **21.3 µs** |
| One record on a write, fsync every record | 3.69 ms |
| Rebuilding the index at startup | **106 ms per million objects** |
| On disk | 48 B/object — 45.8 MiB per million |

The per-object figures move around because a Go map's capacity grows in powers of two, so
where `n` falls between two of them matters more than `n` does. **118 B/object** is the
worst of the three and the one to plan with — against 32 bytes of actual entry, the rest
being the map's overhead and not something to tune away.

Three numbers decide the design. An index is **memory proportional to live objects**,
which is a different shape of cost from anything else in this gateway — every other
structure is O(chunk size) or O(one prefix). A read pays **279 ns, 0.2 % of the 0.13 ms**
the gateway already costs, which is to say nothing. A write pays **21 µs**, almost all of
it the amortised fsync, which is the same order as the 18 µs per request ADR-016 accepted
for audit checkpoints at the same interval — and is in any case paid behind a network
round trip to the provider.

Syncing every record instead costs 3.69 ms, and buys less than it looks like. A lost tail
costs *detection* for the objects in it and nothing else, so the durability of this file is
not the durability of data; that is why the default amortises it.

## Decision

### A local index per instance, because ADR-002 rejected something else

The rejection in ADR-002 is of *a shared index that a read's correctness depends on*. A
local freshness index is neither of those things, and that is what makes it affordable:

- **It is not shared.** Each instance keeps its own, exactly as
  [ADR-016](ADR-016-audit-log.md) gives each instance its own chain. No coordination, no
  serialising writer, no round trip on a path measured at 0.13 ms. Adding an instance
  adds an index.
- **It is not on the correctness path.** An empty index never makes a correct read fail —
  it only fails to detect. Losing the file loses *detection*, not data, and never plaintext.
  ADR-002's "consistency problem between index and object" is a problem because an index
  that disagrees with the object would break reads; here a disagreement is the output.

That asymmetry is the whole decision. This is the same shape as
[ADR-017](ADR-017-listing-order-under-name-encryption.md), where the state a buffered
listing appeared to need turned out not to be needed for correctness: the cost that made
the feature look impossible was a cost of a different design.

### Trust on first use, and a mismatch means "not what I saw" — not "older"

An index that has never seen an object can say nothing about it. The first read of an
unknown object records what it saw and returns it. Every later read of that object is
checked.

The limit this leaves has to be stated plainly rather than discovered by an operator.
The tag is **opaque**: it identifies a write, but it carries no order. A reader that finds
a tag other than the one it recorded knows the object changed since it last looked — it
does **not** know in which direction. A rollback by the provider and a legitimate write by
*another instance* are, to a local index, the same observation.

So the guarantee has a shape, and it is not "rollback is detected":

- **Single instance, or an object only ever written through one:** every rollback of a
  write this instance has seen is detected. This is the strong case and the one the
  feature is for.
- **Several instances writing the same objects:** a mismatch is ambiguous, and treating
  it as an attack would refuse legitimate reads. Detection there needs a shared index,
  which is a deployment's choice and not this default.

The interface is therefore a `Store`, with a local one shipped, in the same shape
[ADR-013](ADR-013-root-key-sources.md) gave root-key sources — so a shared backend is an
operator's decision later rather than a rewrite. And, like name encryption, this is
**off by default**: it changes the memory profile of the process and narrows what a
multi-instance deployment may do, and neither should arrive by upgrade.

### A detected rollback refuses the read

`known && tag ≠ recorded` returns an error and releases no plaintext. Detecting a
rollback and serving it anyway would make the feature a log line, and
[ADR-004](ADR-004-fail-closed.md) already settled the direction to be wrong in. The check
happens where ADR-014's salt check happens — when the header is read, before any
plaintext of the object is out.

A **lost index is not an outage.** Every object becomes unknown and trust-on-first-use
starts over, and the gateway says so at startup rather than failing closed. This is
deliberately the opposite of `audit.fail_closed`, and for a reason: an empty audit log is
an attacker's goal, while an empty freshness index cannot be used to *cause* anything —
it can only fail to notice. Refusing every read after a disk replacement would buy no
security and cost an outage.

### A delete leaves a tombstone

Otherwise the provider can simply ignore a `DeleteObject` and keep serving the object,
and a tag check would find the recorded tag and agree. A delete records that the key is
gone; a read that finds an object where the index recorded a tombstone is refused with
the same error as any other rollback.

Tombstones are the one entry that does not shrink with the bucket, so they carry a
configurable retention rather than living forever.

### Names in the index are hashed, not encrypted and not in clear

Each entry keys on `HMAC-SHA256(K_idx, lp(bucket) || lp(key))[0:16]`, with `K_idx`
derived from the keyring by HKDF under its own `info` string, as ADR-016's keys are.

In clear is not an option: [ADR-015](ADR-015-object-name-encryption.md) encrypts names in
the bucket and ADR-016 encrypts them in the log, and an index writing them plainly would
put on the gateway's own disk precisely what both of those hide. It is also measurably
larger — 132 B/object against 84.

Hashed rather than encrypted, unlike ADR-016, because the two are asked different
questions. The audit log has to be *readable during an incident*, so it needs a reversible
construction. This index is only ever asked "is this the write I recorded", and it can
answer that without being able to name a single object it holds. It inherits ADR-015's
one standing cost anyway: determinism does not hide equality, so whoever holds the index
and guesses a name can confirm the guess.

## Alternatives considered

**A shared, strongly consistent index** — DynamoDB, etcd, a SQL row per object. Strictly
stronger: it closes the multi-instance ambiguity above and survives the loss of a host.
Rejected as the default, not on principle but on what it drags in: a network round trip
on every read and every write of a path that costs 0.13 ms, an availability dependency
that turns a storage outage into a gateway outage, and the shared mutable state G5 exists
to avoid. It stays reachable as a `Store` implementation, where the operator paying those
costs is the one who decided to.

**Folding the index into the audit chain of ADR-016.** Tempting — that chain already
appends per request, already hashes, already signs checkpoints, and already records
bucket and key. Rejected because the two have different lifetimes. The audit log is
sized by *request volume* and rotated at 128 MiB; the index is sized by *live objects*
and must not be rotated away at all, since dropping an entry silently disables detection
for that object. Coupling them would mean either an audit log that cannot be rotated or
an index that expires for reasons that have nothing to do with the bucket.

**A hash chain and signed checkpoints over the index**, as ADR-016 has. Rejected on the
grounds ADR-016 itself used to reject per-entry signatures: it would prove nothing against
the attacker it would be for. The audit log is chained because its adversary is someone who
reaches *the log file*; this index's adversary is the storage provider, and `THREAT_MODEL`
§3 already concedes that anyone who controls the gateway host controls everything on it,
this file included. What the index does carry is a CRC per fixed-width record, which
catches the failure that actually happens — a process killed mid-append — and lets the
replay keep every record before the tear instead of discarding the file.

**A signed root object in the bucket:** a Merkle root over all keys and tags, stored
upstream, signed by the gateway. Survives the loss of a host, which a local file does not.
Rejected on two counts. Every write becomes a read-modify-write of one object, which is a
serialisation point in front of a gateway whose entire design avoids one — worse under
concurrency than the shared index above, not better. And the root is itself an object the
provider holds, so it can be rolled back too; anchoring it requires remembering its hash
locally, which is the local index again with an extra round trip in front.

**Provider-side versioning with S3 Object Lock in compliance mode.** No gateway state at
all, and the provider enforces that an old version cannot be reinstated. Genuinely useful,
and worth documenting as a deployment pattern — but it is not this. Object Lock defends
against a *compromised credential*; the attacker in `THREAT_MODEL` A2 is the provider
itself, which is the party enforcing the lock. It narrows the attack surface without
closing the row.

**A monotone write counter in the segment header**, so that a mismatch would carry
direction and the multi-instance ambiguity above would disappear. Rejected: the counter
would have to be allocated somewhere, and an allocator shared across instances is the
shared state again — with a format change on top. A wall-clock timestamp instead of a
counter avoids the allocator but not the problem, since the provider chooses which
signed-and-timestamped version to serve and an old one is genuinely old.

## Consequences

**Positive.**

- The last **No** in the `THREAT_MODEL` risk table becomes a bounded **Yes**, and the
  bound is written down rather than implied.
- No format change. Objects written by every previous version are covered the moment an
  index records them, and objects written under this feature are readable by a gateway
  without it.
- No coordination, no round trip, no shared writer. Statelessness in the sense G5 means —
  an instance can be added, lost or replaced without any other instance noticing.
- A check costs 0.18 % of a request, so the feature is a memory decision and not a
  latency one. Operators can make it with the table above.
- Losing the index loses detection, never data and never plaintext.

**Negative.**

- **Memory is proportional to live objects**, ~118 B each — 112 MiB per million. Every
  other structure in this gateway is bounded by a chunk or a prefix, and this one is not.
  Ten million objects is 897 MiB, and that is the practical ceiling for a local index.
- **Trust on first use**: the first read of an object after an index is created or lost
  cannot be checked, and a rollback served at exactly that moment is recorded as the truth.
- **A mismatch carries no direction.** In a deployment where several instances write the
  same objects, a local index cannot separate a rollback from a peer's write. That is why
  it is off by default and why the shared `Store` exists.
- Tombstones do not shrink with the bucket, so deletes leave a retention setting behind.
- `blindbucket rotate` is unaffected by design — it does not move ciphertext, so salts and
  therefore tags are unchanged — but anything that *re-encrypts* an object would have to
  update the index, and no such operation may be added without doing so.
- One more secret derived from the keyring, one more file an operator has to know about,
  back up and not copy between instances.

## Corrections this implementation forced

Two figures in the table above replaced earlier ones, and the earlier ones were mine.

The memory numbers were first measured against a prototype whose entry held only the tag.
The real one holds the tag, a kind and a timestamp — the kind because a tombstone has to be
distinguishable from an object, the timestamp because tombstones expire — and Go pads that
to 32 bytes against the prototype's 16. The cost per object rose from 84 B to 118 B, and
the ten-million ceiling from 640 MiB to 897 MiB. The shape of the argument did not change;
the number an operator would have planned with was 30 % too low.

The on-disk figure moved the same way and for the same reason: 32 B/object became 48, once
a record had a kind, a timestamp and a checksum rather than just a hash and a tag.

The write cost is new. The prototype measured no writes at all, so nothing in the first
draft said what a `PutObject` would pay. It is 21 µs at the default sync interval, and
naming it is the difference between a reader being able to check this decision and having
to take it.

## What this does not claim

It does not detect a rollback of an object this index has never seen. It does not detect
anything after the index is lost until each object is read once. It does not give a global
view: two instances have two indexes and no opinion about each other. And it does not
change `THREAT_MODEL` §3 — an attacker who controls the gateway host controls the index
too, and the property claimed here is against an attacker who controls the *provider*.
