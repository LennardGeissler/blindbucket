# ADR-008 — Part sizes as multiples of the chunk size

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M4
**Implements:** `internal/manifest` (`PartsFromUpstream`)

## Context

`ListObjectsV2` reports a size per object and reads nothing but the listing. For a
single-part object the conversion from stored size to plaintext size is exact
arithmetic: the format is deterministic in length, so `S = 32 + P + 16·⌈P/C⌉`
inverts (FORMAT §7.2).

A multipart object is a concatenation of `M` segments, and the same inversion
needs the per-part sizes — which live in the manifest, which a listing does not
read. In general `S = 32·M + P + 16·Σ⌈P_i/C⌉`, and the sum depends on where the
part boundaries fall, not only on the total. Two objects of the same plaintext
size split differently have different stored sizes.

Without something to pin this down, a listing would have to fetch one manifest per
object, turning a single request into hundreds — or report ciphertext sizes and be
wrong for every multipart object a client ever looks at.

## Decision

Require that **every part except the last has a plaintext size that is an exact
multiple of the chunk size**, and refuse a `CompleteMultipartUpload` that breaks
it with `InvalidRequest` and a message naming the fix.

Under that rule each non-final part contributes exactly `P_i/C` chunks with no
remainder, so the chunk counts sum to `⌈P/C⌉` for the whole object regardless of
where the boundaries are:

```
S = 32·M + P + 16·⌈P/C⌉
```

`M` comes from the `-M` suffix S3 appends to a multipart ETag, so a listing has
everything it needs and the conversion stays one line of arithmetic.

Two further rules come with it:

- **The last part must not be empty.** An empty final segment is one chunk of zero
  bytes, which is legal for an empty *object* but would make the inversion
  ambiguous here. The validator also rejects empty non-final parts; no position
  permits an empty part. Both `UploadPart` and `UploadPartCopy` now refuse it on
  arrival, while completion keeps its check ([ADR-026](ADR-026-empty-parts-refused-on-arrival.md)).
- **A part's ciphertext must not exceed 5 GiB**, which is S3's own limit, capping
  the plaintext of a part at about 5 GiB − 1.25 MiB. This is checked when the part
  arrives rather than only at completion, so a client learns on the part it sent.

**The rule costs real clients nothing.** The default part sizes of the AWS CLI and
boto3 (8 MiB), rclone and `mc` (5 and 16 MiB) are all multiples of every permitted
chunk size, because the chunk size is at most 1 MiB and all of those are multiples
of 1 MiB. A test enumerates that across the whole permitted range so the claim
stays true rather than remaining a comment.

**Sizes come from the provider, not from the client.** `CompleteMultipartUpload`
carries a part list, but only part numbers and ETags. The sizes the manifest
records are read back with `ListParts`, because a client that could name them
could make an object list at any size it liked.

## Alternatives considered

**Read the manifest during listings.** Correct without any rule on part sizes, and
it turns one request into one per multipart object in the page. A listing of 1000
objects would make 1000 extra round trips; `aws s3 ls` on a large bucket would be
unusable.

**Record the plaintext size in the object's metadata.** One field, no rule, no
extra request — and the provider can rewrite metadata, so the number would be
whatever the provider says. Sizes derived by arithmetic from the stored size are
not authenticated either, but they are at least *consistent* with what is stored,
and a lie about them is detected on read. A metadata field would simply be
believed. It also does not remove the rule: the range mapping still needs to know
where part boundaries fall.

**Accept any part sizes and report ciphertext sizes in listings.** Every `ls`
would show numbers larger than the file, `aws s3 sync` would treat every object as
changed, and the gateway would stop being transparent — the property the whole
project is for.

**Re-chunk parts as they arrive, so boundaries always land on the grid.** The
gateway would have to buffer the remainder of each part until the next one
arrives, which reintroduces per-upload state (ADR-006 removes it) and buffering
(the streaming design refuses it). Parts also arrive out of order, so "the next
one" is not a thing that exists.

**Pick a chunk size that divides every plausible part size, and hope.** That is
the current rule without the check. A client with a 5.5 MiB part size would
produce objects that list at the wrong size for ever, silently. Refusing at
completion is the same rule made honest.

## Consequences

- A client using a part size that is not a multiple of the chunk size cannot
  upload. The error names the chunk size and says what to change, because a part
  size setting is the only thing the client can do about it.
- The chunk size becomes an operational constraint and not just a performance
  knob: raising it above a deployment's smallest client part size would break
  that client. At the 1 MiB maximum every common default still works.
- The whole-object plaintext size is recoverable from `(S, M)` alone, which keeps
  `HeadObject` and `ListObjectsV2` at one request each.
- `UploadPartCopy` (M5) must preserve the original part boundaries when copying a
  multipart object, or the copy would break the rule. The copy path is already
  specified that way.
