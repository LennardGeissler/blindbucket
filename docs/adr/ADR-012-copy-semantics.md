# ADR-012 — Copy semantics: re-wrap and keep the ciphertext, re-encrypt for part copies

**Status:** Accepted
**Date:** 2026-09-12
**Milestone:** post-M5 (deferred from M5)
**Implements:** `internal/objcopy`, `internal/proxy` (`CopyObject`, `UploadPartCopy`)

## Context

`CopyObject` was deferred out of M5 and recorded in the README as planned. What
made it worth returning to is not the operation itself but what clients do with
it: `aws s3 cp s3://a s3://b`, `aws s3 mv`, and every sync tool's rename path go
through it, and all of them were answered `NotImplemented`.

Three things make a copy more than a forwarded request.

**The data key is bound to the object's identity.** The wrapped key's associated
data is `"blindbucket/v1/dek" || lp(kid) || lp(bucket) || lp(key)` (FORMAT §6.1).
Forwarding a copy to the provider unchanged would move the wrapped key verbatim
to a new key, where it can no longer be opened — and nothing would notice until
somebody read the object. The failure is silent, delayed, and total.

**A multipart object is more than its bytes.** Its part boundaries live in a
signed manifest, its manifest id is in its metadata, and the plaintext size a
listing reports is recovered from the part count in the ETag suffix (FORMAT
§7.2). A copy that flattened it into one part would read back correctly and
report the wrong size.

**A part is not a slice of an object.** Each part is its own segment, with its
own 32-byte header, its own salt, and chunk counters that start at zero
(FORMAT §4). Two segments over the same plaintext under different salts share no
bytes.

## Decision

### Copying an object keeps its data key and re-wraps it

`CopyObject` unwraps the data key under the source's identity and wraps it again
under the destination's. The ciphertext is copied inside the provider with
`UploadPartCopy`, part by part where the source has parts, and never travels
through the gateway. A copy of a terabyte costs what a copy of a megabyte costs.

This is the same operation `blindbucket rotate` performs, with a destination
that differs from the source rather than a key id that differs from the source's.
Both go through `internal/objcopy`, which also owns the manifest lifecycle rules
R1–R3 that [ADR-010](ADR-010-manifest-lifecycle-under-concurrency.md) records and
`spec/tla/Multipart.tla` checks. One implementation, because the rules are an
ordering of three writes and two orderings would eventually differ — and only one
of them was the one the model checked.

**Keeping the data key is safe, and this is the part worth stating precisely.**
The copy has the same key, the same salt and therefore the same nonces as the
source. That is nonce reuse in the literal sense, and it is harmless here for a
reason specific to this operation: the two segments encrypt *identical
plaintext*. The keystream is reused to produce exactly the ciphertext the
provider is already holding, so the copy reveals nothing the provider did not
have. What AES-GCM does not survive is the same key and nonce over *different*
plaintexts, and that cannot arise: an object is immutable, and overwriting one is
an ordinary PUT with a freshly generated data key.

The consequence to accept is that two objects now depend on one data key.
Compromising it exposes both — but both are the same plaintext, so the exposure
is the same exposure.

### Copying a part re-encrypts, and cannot do otherwise

`UploadPartCopy` reads the requested plaintext range of the source, decrypts it,
re-encrypts it as a new segment under the destination's data key, and uploads it.
The bytes cross this process. Memory stays at `O(chunk size)`, and the part's
ciphertext length is known before the first byte moves, so nothing is spooled.

There is no server-side alternative. The destination's part *n* is a segment with
the destination's key and a fresh salt; the source's ciphertext for the same
plaintext was produced under a different key and salt. No byte range of the
source is a valid byte range of the destination.

This matters more than it sounds, because it is the path that carries real work:
the AWS CLI uses `UploadPartCopy` for any server-side copy above its 8 MiB
multipart threshold. Implementing only `CopyObject` would have made
`aws s3 cp s3://a s3://b` work for small objects and fail for the ones this
gateway exists for.

### Object tags are refused on write and forwarded on read

*Decided again by [ADR-037](ADR-037-encrypted-object-tags.md): tags are stored sealed, in a
sidecar bound to the object version, and a tag set never reaches the provider in plaintext.*

Answering `GetObjectTagging` became necessary because the AWS CLI asks for the
source's tags before a server-side copy. It is forwarded to the provider, which
is where tags live; the gateway writes none, so for anything it stored the answer
is an empty set.

Writing tags — `PutObjectTagging`, `DeleteObjectTagging`, and `x-amz-tagging` on
an upload — is refused with a message that says why: a tag is a key and a value
the provider stores in the clear. A gateway whose whole claim is that the
provider sees only ciphertext must not accept plaintext through a side door, and
silently dropping tags would be worse still, because a client would believe its
object carries them.

## Alternatives considered

**Re-encrypt the whole object under a fresh data key.** Clean key separation: the
copy shares nothing with its source. Rejected because it costs a full read and a
full write of every byte through the gateway, which is the cost a server-side
copy exists to avoid, and because the separation buys nothing — the two objects
have identical plaintext, so a key that opens one reveals only what the other
already is.

**Forward `CopyObject` to the provider and patch the metadata afterwards.** The
cheapest possible implementation. Rejected because there is no "patch the
metadata" call in S3; the only way to change metadata is to write the object. It
also leaves a window in which the destination exists with a wrapped key bound to
the wrong identity.

**Keep the source's manifest id for a copied multipart object.** Saves writing a
manifest. Rejected by rule R1: two object versions sharing a manifest is the
state the model produces its first counterexample from — deleting either version
takes the other's manifest with it.

**Special-case an aligned `UploadPartCopy` into a server-side copy.** When a
requested range covers exactly one whole part of a multipart source *and* the
destination's part number equals the source's, the source's segment bytes are a
valid destination part. Rejected for now: the condition depends on the client
choosing a part size that matches the source's original layout, which the AWS CLI
derives from the plaintext size and not from the source, so the fast path would
fire rarely and unpredictably while adding a second code path through the most
security-sensitive code in the project. It is recorded here rather than dropped.

**Accept object tags and store them at the provider.** Would make the CLI's
`--copy-props` work fully. Rejected: tags are plaintext, and the headline claim
is that the provider never sees plaintext. An option to enable them would move
the claim from "true" to "true unless configured otherwise", which is the kind of
footnote a security property does not survive.

## Consequences

- `aws s3 cp s3://a s3://b`, `aws s3 mv` and server-side copies in `mc` and
  rclone work, at any size. Verified against MinIO with a 1 GiB object copied
  through 128 part copies, returning an identical SHA-256.
- A copy below the client's multipart threshold moves no data: measured at
  1.2 KB over the wire for a 600 KB object.
- A copy above it moves the object twice through the gateway, once decrypting and
  once encrypting. That is inherent, and it is stated in
  [docs/COMPATIBILITY.md](../COMPATIBILITY.md) rather than left for a user to
  discover from a throughput graph.
- `internal/rotate` lost its own copy of the republish logic to `internal/objcopy`.
  The rotation integration tests, including the replay of the I2 counterexample,
  cover the shared path unchanged.
- Object tags are refused rather than ignored. A client that relies on them gets
  an error naming the reason.
- Copying a specific `versionId` is refused: this build does not implement
  versioned reads, and copying the current version instead of the one asked for
  would be the wrong kind of helpful.
