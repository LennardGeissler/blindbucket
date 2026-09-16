# ADR-015 — Object name encryption: deterministic, per path segment

**Status:** Proposed
**Date:** 2026-09-12
**Milestone:** M6
**Would implement:** `internal/crypto/names`, `internal/proxy` (every operation), `internal/manifest`

## Context

`THREAT_MODEL` §4 lists what the storage provider still sees, and object keys are
the first entry. For most of the list there is a reason it cannot be helped —
sizes follow from a length-deterministic format, timestamps and access patterns
from the provider doing its job. Names are different: they are the one item on
that list that is hidden by construction elsewhere, and the M6 stretch goals
have carried "deterministic name encryption, per path segment, so prefix
listing keeps working" since the beginning.

It is also the largest remaining piece of work in the project, and the one with
the most ways to be quietly wrong. This ADR is written before any code, because
three of its conclusions constrain everything that would follow and one of them
was not obvious.

## What the design has to satisfy

**A point lookup must not need an index.** A client asks for `GET /bucket/a/b/c.txt`.
The gateway has to turn that into exactly one upstream key, with no lookup, no
listing and no round trip — otherwise every read gains a search.

This single requirement settles more than it looks. It means the mapping from
plaintext key to stored key is a *function of the key alone*: **fully
deterministic, every segment, including the last**. Any scheme that randomises
the leaf name — which would be strictly better for confidentiality, because it
hides equality — makes the stored key unfindable and is therefore out. That
rules out the most attractive option before the primitive is even chosen.

**Prefix listing must keep working**, which is why the encryption is per segment
rather than over the whole key: `a/b/` has to remain a prefix of `a/b/c.txt`
after encryption, so each segment is encrypted on its own and the `/` separators
survive.

**Encrypting the same segment under different parents should differ.** `E("x")`
appearing under both `photos/` and `invoices/` would say that the two
directories contain something with the same name. The path so far is therefore
associated data of each segment's encryption, which costs nothing and removes a
whole class of correlation.

## Decision

### Layout

```
StoredKey = Enc(s₁) || "/" || Enc(s₂) || "/" || … || Enc(sₙ)
```

for a plaintext key split on `/` into segments `s₁ … sₙ`, where each segment is
encrypted deterministically with the preceding path as associated data and
rendered in an S3-safe, order-insensitive encoding.

### Primitive: the SIV construction over stdlib, not a dependency

Deterministic encryption needs a synthetic IV derived from the plaintext. The
standard answer is AES-SIV (RFC 5297). Three ways to get it, and the choice is
less obvious than it should be:

`x/crypto` has no SIV. The usual Go library, `github.com/secure-io/siv-go`, has
**no release tags at all**, its most recent commit is from **2018**, and it pulls
in `github.com/aead/cmac` from **2016**. Taking three untagged, long-unmoved
modules as the core primitive of the project's newest security feature is worse
than either alternative.

So: build the construction from the standard library, as
`IV = HMAC-SHA256(K_prf, aad || plaintext)[:16]` followed by AES-CTR under
`K_enc` with that IV, storing `IV || ciphertext`. Decryption recomputes the
HMAC and compares, which makes it authenticated as well as deterministic.

**This is consistent with the project's rule rather than an exception to it.**
The project's rule is "an established construction, no own primitives", and the
segment format already is exactly that: STREAM, a published construction,
composed from stdlib AES-GCM. SIV is likewise published, and HMAC-SHA256 in
place of AES-CMAC as its PRF is a documented variant. What is being written is
composition, not a primitive — the same category of act, held to the same
standard: known-answer vectors, and coverage by the independent Python decoder,
which is this project's existing answer to "did you get the composition right".

Integrity from this cipher is in fact surplus. An object's wrapped data key is
associated data-bound to its bucket and key (FORMAT §6.1), so a provider that
moves an object to another name produces something that will not unwrap. Name
integrity already rides on that. The comparison on decrypt is kept because it is
free and turns a corrupt name into an error rather than a garbled one.

### The name key does not rotate with the KEKs

The key that encrypts names cannot be a KEK version. Rotation replaces the
active KEK, and if names were keyed by it, `blindbucket rotate` would change
every object's stored name — a rename of the entire bucket, and an unreadable
one until every object had been rewritten.

So the keyring holds a dedicated **name key**, generated once at `keygen` and
untouched by rotation. This is a real asymmetry in the key hierarchy and worth
stating plainly: KEK rotation is cheap and routine, name-key rotation is a
rewrite of every object's key and is the same operation as the migration below.
A deployment that has to rotate the name key is doing a bucket-wide copy, and
should know that before it enables the feature rather than after.

### Canonical encoding is mandatory, not cosmetic

Base32 encodes 17 bytes — a 16-byte IV and one byte of name — into 28
characters, which carry 140 bits against the 136 in use. A decoder that ignores
the four spare bits accepts sixteen spellings of the same segment, and each of
them is a *different stored key naming the same object*. The gateway would
believe it had seen one object twice, and a check performed against the
canonical spelling could be walked past with another.

Found by the round-trip fuzz target within seconds of it existing, before any
of this was wired into the proxy. A decoder MUST therefore re-encode what it
decoded and refuse anything that does not match, and `FORMAT.md` would have to
say so normatively — it is the same requirement the segment decoder already
carries for its own inputs, and the same reason.

## What this buys, and what it does not

| | |
|---|---|
| **Hidden** | Every segment of every object name |
| **Still visible: equality of full paths** | Unavoidable. A point lookup with no index means one plaintext key maps to one stored key, forever. |
| **Still visible: equality of sibling names** | Two objects called `report.pdf` under the same directory are visibly the same name. Under different directories they are not. |
| **Still visible: segment lengths** | Ciphertext length tracks plaintext length. Padding is a separate M6 item and would apply here too. |
| **Still visible: tree shape** | Depth, and how many children each directory has. |
| **Confirmable guesses** | The one that matters. Determinism means an attacker who suspects an object is called `payroll/2026-q1.xlsx` can encrypt that name — if they have the key — or, without the key, can confirm a guess by watching whether a name they caused to be created collides. Deterministic encryption never hides equality, and equality is what confirms a guess. |

That last row is the cost of the feature, and it is not a footnote. It should go
into `THREAT_MODEL` §4 in the same words before any of this ships, because a
reader who assumes "names are encrypted" means "names are unguessable" has been
misled by an omission.

## What degrades

These are S3 behaviours that get worse, and they are the reason this is weeks of
work rather than days.

**Listing order — measured, and worse than expected.** S3 returns keys in
lexicographic order of the *stored* key. Encrypted names sort differently from
plaintext ones, so the gateway returns correct names in an order that is
arbitrary to the client.

This was measured against the AWS CLI with a stub endpoint that serves the same
eight keys sorted and unsorted, everything else held equal:

| Destination listing | `aws s3 sync local s3://bucket --delete` |
|---|---|
| sorted | 0 deletes — correct, every local file exists remotely |
| unsorted | **7 deletes of objects that do exist locally** |

The CLI's comparator is a merge-join over two sorted streams. Fed an unsorted
one it concludes that present objects are absent. In the upload direction with
`--delete`, that is the gateway causing a client to delete data out of the
encrypted bucket — no error, no warning, and the objects are gone.

**This is not a documentation problem.** A footgun that silently destroys data
is not something a tool whose argument is safety can ship behind a note in a
compatibility matrix, and the gateway cannot refuse the dangerous case because
`--delete` is client-side logic it never sees.

So the feature needs an answer to listing order before it can ship, and every
answer costs something:

- **Buffer and sort per prefix.** The gateway lists the whole prefix upstream,
  decrypts, sorts, and serves pages from that. Correct, and it holds memory
  proportional to the number of keys under the prefix — roughly 100 MB for a
  million-object prefix, against a design whose headline is `O(chunk size)`.
- **Re-scan per page**, carrying the last plaintext key in the continuation
  token. Bounded memory, but `O(n)` upstream work per page and `O(n²/1000)` for
  a full walk. Fine at ten thousand objects, unusable at a million.
- **A bound with a refusal.** Sort up to a configured key count and answer
  anything larger with an error rather than a wrong order. Honest, and it makes
  the limit visible instead of latent.
- **Ship name encryption without ordered listings** and accept that sync with
  `--delete` corrupts. Rejected on the grounds above.

The choice among the first three is open and is the next decision this ADR
needs. It is also the reason the effort estimate for this feature was wrong:
the encryption was the easy half.

**Partial-segment prefixes.** `prefix=photos/2026` is a prefix of the segment
`2026-01`, not a whole segment, and a partial segment has no encrypted prefix to
match. Serving it means listing the whole parent and filtering on decrypted
names, which breaks the relationship between `max-keys` and what comes back.

**Delimiters other than `/`.** The segment structure is built on `/`. A client
asking for `delimiter=-` cannot be served from the stored layout.

**Key length — one number will not do.** Each segment grows by a 16-byte
synthetic IV and then by base32's 1.6×. This section first quoted the 1.6× alone
and put the usable key length near 600 bytes, which is the *best* case rather
than the case: the IV is charged per **segment**, so the expansion is driven by
how many segments a key has and not by how long it is.

Measured by `BenchmarkKeyExpansion`, as the longest plaintext key of each shape
that still encrypts to a legal 1024-byte S3 key:

| Key shape | Longest plaintext key | Expansion |
|---|---:|---:|
| one long segment | 624 B | 1.64× |
| realistic tree, long leaf (`photos/2026/03/14/…`) | 560 B | 1.83× |
| segments of 8 | 214 B | 4.79× |
| segments of 4 | 128 B | 8.00× |

So 600 bytes was right for a key that is one long segment, and wrong by a factor
of nearly five for a deep path of short ones. The usable length is somewhere
between **128 and 624 bytes**, and which end a deployment gets is a property of
its naming convention rather than of this design.

A separate figure, for storage overhead rather than for the limit: over keys of
typical length and depth — mean 34.4 bytes, `BenchmarkMeanKeyLength` — the mean
expansion is 5.3×, because short segments pay the full 16-byte IV each. Those
keys are nowhere near the limit; the two numbers answer different questions and
should not be quoted for each other.

The limit is hard, clients will hit it, and it must be an explicit error rather
than a truncation.

**Migration.** Objects already stored under cleartext names stay that way; the
gateway would have to read both. Switching a bucket over means rewriting every
key, which is a copy per object — `blindbucket rotate`'s machinery does exactly
this shape of work and would be the place for it.

## Alternatives considered

**Randomised leaf, deterministic directories.** Hides sibling-name equality,
which is the worst leak above. Rejected: the stored key would no longer be
computable from the plaintext key, so every `GET`, `HEAD` and `DELETE` would
need a lookup. An encrypted gateway that turns every read into a search is not
the same product.

**Hash the directory path, randomise the leaf** (`HMAC(dir)/E_rand(leaf)`).
Hides more still, and point lookups work for the directory part. Rejected:
sub-directories become undiscoverable, because `HMAC("a/b")` and `HMAC("a/b/c")`
are unrelated — listing a directory would not reveal what is under it. Fixing
that means maintaining directory index objects, which is a filesystem, not a
gateway.

**Encrypt the whole key as one blob.** Simplest and hides the tree shape.
Rejected: prefix listing stops working entirely, and prefix listing is how every
S3 client navigates.

**`github.com/secure-io/siv-go`.** The obvious dependency. Rejected on the
evidence above: untagged, 2018, with a 2016 transitive dependency.

**Order-preserving encryption** to keep listing order. Rejected: it leaks the
order relation of every pair of names, which for sorted data is close to leaking
the names.

## Consequences if accepted

- A format version change, `FORMAT.md` gaining a section on the key mapping, and
  known-answer vectors for it.
- The Python reference decoder gains the name mapping, which is also the check
  that the SIV composition was written down correctly.
- A per-bucket or per-deployment switch, off by default, and a documented
  migration that is a rewrite of every object's key.
- `THREAT_MODEL` §4 changes substantially — and gains a paragraph on confirmable
  guesses that is more important than the feature's headline.
- Manifest paths (`FORMAT.md` §10.1) already hash the object key; they would hash
  the stored key, so nothing there changes shape.
- The compatibility matrix gains a row per degraded behaviour above, each
  measured rather than predicted.
