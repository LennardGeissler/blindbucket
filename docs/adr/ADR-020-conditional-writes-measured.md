# ADR-020 — Conditional writes are measured before a rotation, not assumed

**Status:** Accepted
**Date:** 2026-09-25
**Milestone:** M7
**Implements:** `internal/probe`, `internal/rotate`, `internal/objcopy`

## Context

`blindbucket rotate` reads an object and writes it back a moment later, and
[ADR-009](ADR-009-rotation-by-copy.md) guards the two windows in between with a
conditional write each:

| Guard | Header | Closes |
|---|---|---|
| 1 | `x-amz-copy-source-if-match` on `UploadPartCopy` | the source replaced between the HEAD and the copy |
| 2 | `If-Match` on `CompleteMultipartUpload` | the object replaced between the copy and the completion |

Both were measured against MinIO and nothing else. `docs/COMPATIBILITY.md` said
so, and issue #8 put the risk in one sentence: a provider that *rejects* these
headers is safe, because rotation refuses; a provider that *silently ignores*
them is dangerous, because rotation looks like it worked while losing a write.

The first run of the integration suite against a second provider found exactly
that. Measured against Garage v2.4.1 on 2026-09-25, with the AWS CLI and no
gateway involved:

| Request | Garage v2.4.1 |
|---|---|
| `UploadPartCopy` with a wrong `x-amz-copy-source-if-match` | **412** — enforced |
| `CopyObject` with a wrong `x-amz-copy-source-if-match` | **412** — enforced |
| `CompleteMultipartUpload` with a wrong `If-Match` | **200 — ignored**; the object is replaced |
| `PutObject` with a wrong `If-Match` | **200 — ignored** |
| `UploadPartCopy` from a source under 5 MiB | 400, even as the only part; precondition checked first |

So on Garage guard 2 does nothing, and nothing said so. A client write landing
after the copy and before the completion is replaced by the pre-rotation
version — invariant I2 broken, the counterexample `spec/tla/` already has.

Guard 1 being ignored would be worse still. The rotation would copy the
client's new ciphertext under the metadata it read from the old version, so the
object would carry a data key that does not open its own bytes, and the client's
data key would be gone. That is not a lost update but a destroyed object. Garage
does enforce it; the point is that nothing checked.

The size limit is a separate finding with a separate consequence. ADR-009 sends
every object through a multipart upload, single-part ones included, because the
completion is where guard 2 lives. Garage refuses to copy a source under 5 MiB
into a part, where AWS allows it for the last part of an upload, so every copy
and rotation of a small object failed there.

## Decision

### Measure both guards before every rotation

Before it touches an object, a rotation asks the provider, and proceeds only if
both guards are **enforced**. `internal/probe` does it with one object of its
own, under the reserved prefix where no client can reach and no listing or `gc`
run looks (`.blindbucket/probe/`):

1. `PutObject` a few bytes; its ETag is the one the conditions will not match.
2. `CreateMultipartUpload` on the same key.
3. `UploadPartCopy` from the object onto itself with a wrong
   `x-amz-copy-source-if-match` — guard 1.
4. `UploadPart` a few bytes, then `CompleteMultipartUpload` with a wrong
   `If-Match` — guard 2.
5. Abort the upload if it is still open, delete the object.

Each guard comes out as one of three answers: **enforced** (412), **ignored**
(the request succeeded), or **refused** (any other error — the provider does
not implement it). Only enforced is safe; refused would fail every object
anyway, and saying so once, up front, beats saying it once per object.

A rotation that is not safe is refused before it starts, with what was
measured and the way out:

```
rotate: the provider behind backups does not enforce the conditional writes rotation relies on:
  If-Match on CompleteMultipartUpload: ignored
A client write during the rotation could be lost. Rotate with --allow-unconditional once nothing writes to the prefix (ADR-020).
```

**`--allow-unconditional` skips the probe.** It already is the operator's
statement that nothing writes to the prefix, which is the one condition under
which neither guard matters, and it already prints the warning that says so.

**A dry run probes too.** The question a dry run answers is whether a real run
would go through, and this is now part of the answer. It writes one object under
the reserved prefix and removes it, which is the same exception the manifests
already are to "a dry run changes nothing".

**Every run measures, nothing is cached.** Six or seven requests against a run
that touches every object under a prefix. A cached answer would be about the
provider as it was, and the endpoint in a config file can be pointed at a
different provider, or the same one upgraded, without anything here noticing.

### Copy a small single-part object with `CopyObject` when nothing needs guarding

When the source is a single-part object under 5 MiB **and** the publishing
write carries no condition, the object is copied with one `CopyObject` instead of
a one-part multipart upload. That is every plain `CopyObject` through the
gateway, and every rotation under `--allow-unconditional`. A guarded rotation
keeps the multipart path, because guard 2 lives in the completion; on a provider
like Garage it is refused by the probe before the size matters.

`CopyObject` keeps guard 1 — `x-amz-copy-source-if-match` is sent the same way —
and the size arithmetic: a single-part copy has an ETag without the `-M` suffix,
which FORMAT §7.2 reads as one segment, the same answer `-1` gives. The rule is
a size rather than a fallback on error, so it behaves the same on every
provider and needs no error string matched.

## Alternatives considered

**A row in `COMPATIBILITY.md` and nothing else.** Issue #8 ruled this out in its
own acceptance criteria: a provider that ignores a precondition needs a guard in
`rotate`, not a footnote. Documentation is read by the operator who looks; the
probe answers the one who does not.

**A table of known providers.** It would be right for the versions measured and
silent about everything else, and "any S3-compatible store" is exactly
everything else. It also ages: Garage may enforce `If-Match` in its next
release, and the table would keep refusing it.

**Probe once, at `serve` startup.** The gateway's request path uses no
destination conditions, so it would be measuring something it does not need;
rotation is the consumer. The package is shaped so that it can also answer on
its own, and `blindbucket probe` does: the same measurement, without the
rotation, exiting non-zero where a guarded rotation would be refused.

**Detect the lost write afterwards.** There is nothing to compare. The completion
produces a new ETag whether or not a client wrote in between, and once the
provider has replaced the client's version, the client's version is gone.

**Fall back to `CopyObject` when `UploadPartCopy` fails.** Garage answers
`InvalidRequest`, a code that covers dozens of unrelated refusals, so the
fallback would either match too much or match one provider's wording. A size
threshold is decided before any request is sent.

**Emulate guard 2 on Garage.** HEAD the object just before the completion and
refuse if the ETag moved. That narrows the window to a round trip without
closing it, and a rotation that is mostly safe is the "looks safe" failure this
ADR exists to remove.

## Consequences

**Positive.**

- A rotation on a provider that ignores a guard is refused with the reason,
  instead of losing writes quietly. That was the case on Garage until now.
- Guard 1 is checked on every run rather than once against MinIO, which matters
  more than its twin: its failure destroys an object rather than reverting it.
- Copies and unguarded rotations of small objects work on Garage, and cost one
  request instead of three everywhere.
- The TLA+ model needs no change. A rotation now runs with both guards, which
  `Multipart.tla` checks, or under `--allow-unconditional`, which
  `MCUnconditionalRotate` already models.

**Negative.**

- Six or seven more requests per rotation run, and one short-lived object under
  `.blindbucket/probe/` a crash can leave behind. It holds no data and nothing
  reads it; deleting the prefix is always safe.
- On Garage a rotation now needs `--allow-unconditional`, which means a window
  in which nothing writes to the prefix. That is not new — it was always true on
  Garage, and now it is enforced rather than unknown.
- The probe measures one object at one moment. A provider that enforces
  conditions only sometimes, or differently per bucket, would pass it; that
  would be a provider bug this cannot see.
