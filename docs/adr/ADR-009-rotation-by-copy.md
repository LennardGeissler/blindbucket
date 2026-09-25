# ADR-009 — Rotation by copy, preserving part structure, with conditional writes

**Status:** Accepted
**Date:** 2026-09-12
**Milestone:** M5
**Implements:** `internal/rotate`, `internal/upstream` (`CopyObject`, `UploadPartCopy`)
**Amended by:** [ADR-020](ADR-020-conditional-writes-measured.md) — both guards are measured
before a run, and a small single-part object with nothing to guard is copied with `CopyObject`

## Context

A key-encryption key has a lifetime. It expires, or it is suspected, and then
every object wrapped under it has to move to a new one. The three-level hierarchy
of [ADR-002](ADR-002-key-hierarchy.md) is what makes that affordable: an object's
data key is wrapped under the KEK, so changing the KEK means rewriting 60 bytes
of metadata, not re-encrypting the object.

Affordable in principle. In practice three things get in the way.

**The metadata is bound to the object.** The wrapped key's associated data is
`"blindbucket/v1/dek" || lp(kid) || lp(bucket) || lp(key)` (FORMAT §6.1). The key
id is *in* it, so a re-wrap is not a substitution of one field: the old wrapping
must be opened with the old id as associated data and the new one sealed with the
new id. Get that wrong and every rotated object becomes unreadable at once.

**Metadata cannot be changed in place.** S3 has no "set metadata" call. The only
way to change an object's metadata is to write the object — which for a gateway
that must not move ciphertext means a server-side copy.

**Clients keep writing.** Rotation reads an object and writes it back some time
later. If a client replaces the object in between, writing back the pre-rotation
version destroys that write. This is invariant **I2**, and
the model in [`spec/tla/`](../../spec/tla/) produces a six-state counterexample
for the version without a guard: rotation reads, a client puts, rotation
completes, the client's data is gone.

## Decision

Rotate by copying the object onto itself through a multipart upload, and make the
write conditional.

**Every object goes through a multipart upload, single-part ones included.** A
plain `CopyObject` would be enough to change a single-part object's metadata, and
it is not used, for two reasons. `CompleteMultipartUpload` is where the
conditional write lives. And a multipart source must be copied part by part
anyway — a flat `CopyObject` of a multipart object produces a single-part result
whose ETag loses the `-M` suffix, and the listing arithmetic of FORMAT §7.2 reads
that suffix to recover the plaintext size. One code path for both shapes is
simpler than two, and with `M = 1` the size arithmetic is identical to a
single-part object's.

**Part boundaries are preserved.** For a multipart object the manifest is loaded
and verified first, each part's ciphertext range is computed from the recorded
plaintext sizes, and each is copied with its own `UploadPartCopy`. The copy is
the same shape as the original, which is what keeps the manifest describing it.

**The manifest rules apply.** A rotation makes a new object version visible, so
rule R1 gives it a fresh manifest id and its own manifest, R2 writes that manifest
before the completion, and R3 deletes exactly the manifest id observed
beforehand — the same order as a multipart completion, checked by the same model.

**Two windows, two guards.** A client can replace the object between the HEAD and
the copy, or between the copy and the completion. `x-amz-copy-source-if-match`
covers the first, `If-Match` on the completion covers the second. Both answer 412,
and both mean the same thing: leave the client's version alone, count the object
as skipped, and let a later run pick it up. Because a run skips objects already
wrapped under the target key, "a later run" is simply the same command again.

**`--allow-unconditional` is the escape hatch, and it is loud.** Providers without
conditional writes cannot offer the second guard. The flag drops it, prints a
warning to stderr naming exactly what is given up, and the documentation requires
that nothing writes to the prefix meanwhile. `MCUnconditionalRotate` in the model
is the counterexample that justifies both the warning and the requirement.

## Alternatives considered

**Re-encrypt the objects.** Conceptually cleaner — a new data key per object, so a
compromised DEK is also rotated — and it moves every byte through the gateway. For
a bucket of any size that is hours of transfer and a provider bill, to solve a
problem the design does not have: the DEK never leaves the gateway wrapped or
unwrapped, and the threat rotation addresses is a compromised or expiring *KEK*.
ADR-002 already records that the DEK stays; this is where the consequence lands.
It is also why the CLI help says plainly what rotation does not protect against.

**Plain `CopyObject` for everything.** Fewer calls and no upload to abort on
failure. It flattens multipart objects into single-part ones, which breaks the
size arithmetic permanently and silently — `ls` would report the wrong size for
every rotated multipart object, with no error anywhere. It is also capped at
5 GiB, so it cannot copy large objects at all.

**Write unconditionally and accept the race.** The window is short and rotation is
rare, so the argument goes. The model needs six states to lose a client's write,
and "short window, rare operation" is exactly the reasoning that produced the two
race conditions in design version 0.1. The conditional write costs one header.

**Lock the prefix during rotation.** Correct, and it makes rotation an outage:
writes to a prefix fail while it runs. It also needs a lock store, which the
design does not otherwise have (ADR-006 removes the last piece of shared state).
The conditional write gets the same guarantee with no coordination at all.

**Rotate the manifest separately from the object.** It would avoid rewriting the
manifest for an unchanged part list. But the manifest is bound to the manifest
id, which R1 requires to be fresh for the new version — so a "separate" rotation
would either share a manifest between versions, which R1 forbids for reasons the
model checks, or write a new one anyway.

## Consequences

- Rotation moves no object data. Measured on 1000 objects of 64 KiB: 62.5 MiB of
  payload rotated in 1.5 seconds while 1.4 MiB crossed the wire — about 1500
  bytes per object, and that figure does not change with object size, which is
  the actual invariant.
- A rotated single-part object becomes a multipart object of one part at the
  provider: its ETag gains a `-1` suffix. Nothing else changes — the segment is
  byte-identical, it carries no manifest, and `OpenedSizeSegments(S, C, 1)` is
  the same arithmetic as the single-part case.
- A run is idempotent and resumable. Objects already on the target key are
  skipped, so an interrupted rotation is restarted by repeating the command, and
  objects skipped for a conflict are picked up by the next one.
- Objects the gateway did not write are counted and left alone. A bucket shared
  with other producers does not break a rotation.
- Rotation is only half of retiring a key. It re-wraps the objects and leaves the
  old KEK in the keyring, still able to open everything it ever wrapped;
  `blindbucket keys remove` is the other half, and against a compromised KEK a
  rotation without it has bought nothing. It is a separate command because only
  an operator can know that no object references the key any more: this side can
  see the keyring, not the bucket.
- The upstream client gains `CopyObject` and `UploadPartCopy`. Rotation uses only
  the latter; both are now also used by the S3 `CopyObject` operation, which
  [ADR-012](ADR-012-copy-semantics.md) added on the same machinery — rotation is
  a copy whose destination is its source.
- MinIO enforces both `x-amz-copy-source-if-match` and `If-Match` on completion.
  That was an open question at design time and is now a measured entry in
  `COMPATIBILITY.md` rather than an assumption.
