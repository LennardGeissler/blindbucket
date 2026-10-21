# ADR-037 — Object tags, sealed in a sidecar bound to the object version

**Status:** Proposed
**Date:** 2026-10-21
**Milestone:** M14
**Implements:** [#132](https://github.com/LennardGeissler/blindbucket/issues/132)
**Builds on:** [ADR-010](ADR-010-manifest-lifecycle-under-concurrency.md), [ADR-012](ADR-012-copy-semantics.md), [ADR-014](ADR-014-part-salts-in-the-manifest.md)

## Context

Object tags are refused today. `PutObjectTagging`, `DeleteObjectTagging` and
`x-amz-tagging` on an upload answer `501`, because the provider would store tags in
plaintext ([ADR-012](ADR-012-copy-semantics.md)). `GetObjectTagging` is forwarded
and answers an empty set. A client that sets tags fails. #132 asks whether tags can
be stored encrypted, and where.

### What tags are for, and what encryption leaves of it

An S3 tag set holds up to ten tags, each a key of up to 128 characters and a value
of up to 256. Most of what makes tags useful happens at the provider: lifecycle
rules that expire or transition by tag, replication filters, IAM conditions on
`s3:ExistingObjectTag`. **None of that can work on an encrypted tag**, wherever it
is stored, because the provider cannot read it. What encrypted tags serve is a
client that writes tags and reads them back: annotations that belong to the object,
travel with copies and disappear with it.

So the question is narrower than it looks: whether that use is worth what storing
tags costs. This ADR answers yes, at a cost it states.

### An asymmetry, stated

User metadata (`x-amz-meta-*`) reaches the provider **as the client sent it**, and
[`THREAT_MODEL.md`](../THREAT_MODEL.md) §4 lists it among what the provider sees.
Tags are refused for the same exposure. The difference is history, not principle:
nearly every client sends `Content-Type` and many send metadata, so refusing them
would have broken everything, while tags could be refused at little cost. This ADR
does not extend the compromise to tags; it gives them the protection metadata does
not have.

### Where tags could live

- **In the object's metadata, sealed.** One request for every read, and atomic with
  the object. But S3 caps user metadata at 2 KB in total, and a full tag set is up to
  about 3.8 KB before encryption. And `PutObjectTagging` would have to rewrite the
  object's metadata, which S3 can do only by copying the object onto itself. That
  changes its `Last-Modified`, changes the ETag of a multipart object, and for a
  large one copies every part.
- **In the provider's tags, each one encrypted deterministically** like a name
  segment ([ADR-015](ADR-015-object-name-encryption.md)). A lifecycle rule could
  then name a tag's ciphertext. But a synthetic IV and base64 leave keys of about 80
  bytes and values of about 176, below S3's limits; equal tags look equal across
  objects; a provider can move a tag from one object to another undetected; and
  Garage has no tagging at all.
- **In an object of their own, sealed**, next to the object, as manifests are
  ([FORMAT.md](../FORMAT.md) §10). No size limit beyond S3's own, any provider, and
  it can be bound to the object version. It costs a request on every tag operation,
  and something has to remove sidecars that no longer belong to anything.

## Decision

**Tags are stored sealed, in a sidecar object per object version.** No tag reaches
the provider in plaintext, and there is no plaintext opt-in.

### Placement and binding

```
.blindbucket/t/<hex(SHA-256(StoredKey))>/<BindingID>

BindingID = base64url(SHA-256(bb-dek)[0:16])     // bb-dek as stored, the 80 characters
```

The prefix is the manifests' (`.blindbucket/`), with `t/` for tags. Clients are
refused access to it, and listings omit it, as they do now.

`BindingID` is derived from the wrapped data key in the object's metadata. Every
write mints a new data key, so every object version has its own sidecar name, and
anything that can read the object's metadata can compute it, `gc` included,
without the keyring. The wrapped key is not secret; its hash reveals nothing the
metadata does not.

### Sealing

```
TagKey = HKDF-SHA256(ikm = DEK, salt = "", info = "blindbucket/v1/tags", L = 32)
AAD    = "blindbucket/v1/tags" || lp(bucket) || lp(key)
Body   = "BBT1" || Nonce(12) || AES-256-GCM.Seal(TagKey, Nonce, TagSet, AAD)
TagSet = uint8(n) || for each tag, sorted by key: lp(key) || lp(value)
```

`key` is the key the client named, as in the data key's own associated data
([FORMAT.md](../FORMAT.md) §6.1), so the seal reads the same with names encrypted or
not.

The key comes from the object's data key, so **a sidecar opens only for the object
version it belongs to**. One moved to another key fails on the associated data. One
left over from an earlier version of the same key fails on the key. A KEK rotation
rewraps the data key without changing it, so the seal survives rotation. The
`info` label separates this key from the segment subkeys, which the same data key
derives with a different label (§4.2).

A sidecar that is present under the current `BindingID` and does not open is
**tampering, and is refused** as any integrity failure is
([ADR-004](ADR-004-fail-closed.md)). It is not taken for "no tags": the name already
says which version it belongs to, so a failure cannot be a stale leftover.

### Operations

| Operation | Requests to the provider |
|---|---|
| `GetObjectTagging` | HEAD the object, then GET its sidecar; none is an empty set |
| `PutObjectTagging` | HEAD the object, then PUT its sidecar |
| `DeleteObjectTagging` | HEAD the object, then DELETE its sidecar |
| `PutObject`, `CreateMultipartUpload` with `x-amz-tagging` | PUT the sidecar **before** the object, then the object as now |
| `CopyObject`, tagging directive `COPY` (the default) | GET the source's sidecar, PUT the destination's before the copy publishes it |
| `CopyObject`, directive `REPLACE` | PUT the destination's sidecar from `x-amz-tagging` before the copy publishes it |

The sidecar is written before the object, for the reason rule R2 writes a manifest
before its object ([ADR-010](ADR-010-manifest-lifecycle-under-concurrency.md)): the
object must never be visible without the tags it was written with. A write that
fails after its sidecar leaves an orphan for `gc`, and the client gets the failure.

The gateway checks a tag set against S3's rules before it stores one: at most ten
tags, unique keys, a key of 1 to 128 characters and a value of up to 256, S3's
character set, and no `aws:` prefix. A set that breaks one is refused with
`InvalidTag`, as S3 refuses it.

`GetObject` and `HeadObject` do not report `x-amz-tagging-count`. It would cost a
request on every read.

### What carries a sidecar along

Anything that writes a new `bb-dek` or a new stored key for an object that keeps
its tags writes the new sidecar **first**:

- **`rotate`** rewraps the data key, so `bb-dek` changes and with it the
  `BindingID`. It copies the sidecar to the new name before it rewrites the object.
  The seal is unchanged, so this is a server-side copy of the sidecar.
- **`migrate-names`** moves an object to its encrypted key, so the hash in the
  sidecar's path changes. It copies the sidecar the same way, before the move.
- **A server-side copy** writes the destination's sidecar, as in the table above.

All three go through `internal/objcopy`, which is where the step belongs.
`encrypt-existing` still leaves objects with provider tags in place
([ADR-034](ADR-034-encrypting-existing-objects.md)). Moving their tags into
sidecars could follow, and is not part of this decision.

### Orphans and `gc`

A sidecar becomes an orphan when its object is overwritten or deleted, or when a
write fails after its sidecar. Orphans hold no plaintext and cost only storage.
`gc` collects them as it collects manifests, with the same order and the same
minimum age: list a key's sidecars, skip the key while an upload is open, HEAD the
object for the `BindingID` in use, and delete the others that are older than the
minimum age. The age is what keeps `gc` from deleting the sidecar of a write that
has not made its object visible yet. The ordering is the one
[`spec/tla/Multipart.tla`](../../spec/tla/Multipart.tla) checks for manifests. The
model will gain sidecars before the code does.

### Concurrency

A sidecar is per object version, so tag writes for one version do not touch
another's. `PutObjectTagging` racing an overwrite tags the version its HEAD saw.
That version is then replaced, and the new one has no tags, as on S3. Two
`PutObjectTagging` on one version: the last one wins, as on S3.

### FORMAT.md first

This adds a format section, `BBT1`, as audit `v1` and names `v1` were added: it adds
an object type next to the segment and manifest formats, and changes neither. It
comes first, with test vectors, in its own PR.

## Alternatives considered

**A plaintext opt-in for some tag keys**, stored as real provider tags so that
lifecycle rules can use them. Rejected for now. It would leak exactly those tags,
keep each object's tags in two places, and do nothing on Garage, which has no
tagging. A deployment that needs lifecycle by tag can usually use lifecycle by
prefix instead.

**Tags in the object's metadata**: above. The 2 KB cap is below S3's tag limits,
and `PutObjectTagging` would copy the object onto itself.

**Deterministic encryption into provider tags**: above. Limits below S3's, equality
visible, tags movable between objects, and no Garage.

**One sidecar per key, not per version.** No `gc` work for overwrites, because
the next write replaces it. Rejected for a race: `PutObjectTagging` on the old
version can overwrite the sidecar that a tagged `PutObject` of the new version has
just written, leaving the new version without its tags. Per version, they cannot
meet.

**Bind to the plaintext data key, not the wrapped one.** It would survive rotation
without a copy. Rejected because `gc` would then need the keyring to tell a current
sidecar from a stale one, and today it runs without it.

**Keep refusing.** Rejected, not by much. The use is narrow, but the cost is mostly
paid already: the gateway has the sidecar pattern, the reserved prefix, the
ordering and the model.

## Consequences

**Positive.**

- Clients that set tags work, and the tags never reach the provider in plaintext.
- A provider cannot read, forge or move a tag set between objects or versions.
- No size limit below S3's, and any provider will do.
- KEK rotation, copies and name migration keep tags.

**Negative.**

- **No provider-side feature works on these tags**: no lifecycle rule, replication
  filter or IAM condition. The README and COMPATIBILITY.md have to say so
  prominently.
- **A provider can drop a tag set**, by deleting its sidecar, or serve an earlier
  tag set of the same version. Both look like a client's own change. Rollback
  detection ([ADR-018](ADR-018-rollback-detection.md)) does not cover sidecars.
- **Every tag operation costs a HEAD**, and `CopyObject` costs a GET of the
  source's sidecar, mostly a `404`.
- **An object type more** under `.blindbucket/`. A bucket lifecycle rule without a
  prefix filter would expire sidecars along with manifests (FORMAT.md §10.7).
- `rotate`, `migrate-names` and `gc` each gain a step, and the model gains the
  sidecar.

## Implementation order

1. FORMAT.md §17, `BBT1`, with test vectors.
2. The model: sidecars in `spec/tla/Multipart.tla`, with `gc`'s minimum age.
3. The tag operations, `x-amz-tagging` on writes and the copy directive, with tests
   for a provider that swaps, drops or replays a sidecar.
4. `objcopy` carrying sidecars: `rotate`, `migrate-names`, copies.
5. `gc` collecting orphaned sidecars.
6. Docs: COMPATIBILITY.md, THREAT_MODEL §4 and §5, the README, and ADR-012 linking
   here.
