# ADR-025 — On AWS a completion is not a publication: writes rank by when they began

**Status:** Accepted
**Date:** 2026-10-03
**Milestone:** post-1.0
**Implements:** `internal/proxy` (completion step 5), `internal/objcopy` (`YieldToUploads`), `internal/rotate`, `internal/migrate`
**Amends:** [ADR-010](ADR-010-manifest-lifecycle-under-concurrency.md), [ADR-009](ADR-009-rotation-by-copy.md), [ADR-022](ADR-022-migrating-to-encrypted-names.md)
**Checked by:** [`spec/tla/Multipart.tla`](../../spec/tla/Multipart.tla), [`spec/tla/Migrate.tla`](../../spec/tla/Migrate.tla)

## Context

ADR-010's rules rest on an assumption the model took as given: a
`CompleteMultipartUpload` that succeeds makes its object the one the key holds.
Rule R3 builds on it. A completion deletes the manifest of the version it saw at
step 2, because that version has just been replaced. ADR-010 listed the upstream
assumptions and said of them: "AWS S3 guarantees them."

The manual AWS workflow, run for v1.1.0 on 2026-10-03, found otherwise.
`TestIntegrationRaceParallelUploadsWithGc` passed in the first run and failed in
the second ([37128592691](https://github.com/LennardGeissler/blindbucket/actions/runs/37128592691)):
after two uploads to one key, the object read as `IntegrityCheckFailed`, its
manifest gone. AWS documents why, under
[concurrent multipart upload operations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html#distributedmpupload):
in a versioned bucket the current version "is determined by which upload started
most recently", and without versioning "any other request received between the
time when the multipart upload is initiated and when it completes … might take
precedence". The completion is still answered as a success.

Measured against the test bucket, unversioned, with one-byte objects, and against
the providers CI runs:

| | AWS S3 | MinIO RELEASE.2026-09-22 | Garage v2.4.1 |
|---|---|---|---|
| Upload A created, then upload B; B completes, then A | A acknowledged, **B** kept (3 of 3) | **A** kept (3 of 3) | A refused, `NoSuchUpload`; **B** kept |
| Upload A created, then a PUT; then A completes | A acknowledged, **PUT** kept (3 of 3) | **A** kept (3 of 3) | A refused, `NoSuchUpload`; **PUT** kept |
| A 512 MiB PUT starts; during it an upload is created and completed; the PUT finishes ~36 s later | **PUT** kept (2 of 2) | — | — |

So AWS ranks an upload by when it was created and a PUT by when its body has
arrived, and acknowledges a completion it then discards. MinIO keeps what lands
last. Garage ranks like AWS but says so: the outranked completion fails.

Three things followed from the assumption, and each fails on AWS:

1. **R3 deletes the manifest of the object that stays visible.** Upload A is
   created, then B; B completes; A's step 2 sees B; A completes, is discarded, and
   deletes B's manifest. B is what every reader gets, and every read of it fails.
   Two overlapping uploads of one key are all it takes. `MCAwsOrder` reaches it in
   twelve states.
2. **Rotation loses a client upload.** A client upload created before the
   rotation's copy and completed after it is discarded in the copy's favour: the
   client was told its write succeeded, and the key holds the rotated older
   version. `If-Match` cannot catch it, because the client's object is not
   visible when the copy completes. I2 as ADR-009 stated it — no overwrite of a
   write the rotation did not read — did not cover a write the provider throws
   away. `MCAwsRotate` violates the widened I2.
3. **`migrate-names` loses one the same way.** A client upload to `E(P)` created
   before the migration's copy and completed after it is discarded; `If-None-Match`
   sees nothing at `E(P)` and lets the copy through. `MCMigrateAwsOrder` violates
   NoLostWrite.

## Decision

### A completion deletes what it replaced only once it has seen the replacement

Step 5 of the completion order becomes a HEAD and then the delete. The manifest
observed at step 2 is deleted only if the HEAD shows that version gone: another
manifest id, a single-part object, or nothing at all. If the HEAD shows the
observed version, the provider discarded this completion, and the manifest stays.
If the HEAD fails or the metadata does not parse, the manifest also stays. A
manifest kept by mistake is an orphan for gc; one deleted by mistake is an object
nobody can read. A version once replaced never becomes visible again, so the
HEAD and the delete need no further guard. The model checks that with the two as
separate steps.

The freshness index is written after that check. A completion the HEAD shows
discarded is not recorded. Recording it would make the next read of the key
report `RollbackDetected`.

### Rotation and migration give way to an open upload

Before it completes, after its own upload exists, a copy made by `rotate` or
`migrate-names` lists the open uploads of its destination key and is abandoned if
there is any other (`objcopy.YieldToUploads`). Checking after its own creation is
what makes the check complete. An upload created earlier and still open is
listed. One that has completed meanwhile is visible, and `If-Match` /
`If-None-Match` refuse the copy. One created later outranks the copy anyway.
PUTs need no check, because a PUT is ranked when it lands.

`rotate` counts such an object as `conflicted`, as after a 412. The client's
version stands, and a later run rotates it. `migrate-names` reports it as
`failed` with the reason, and exits 1. The next run finds the client's object
at `E(P)` and `P` obsolete. A client's own `CopyObject` does not yield. It is a
client write, and between two client writes the provider's rule is S3's rule.

### The models take the provider's ordering as a parameter

Both models gain `Ordering`: `"completion"`, `"initiation"`, and `"either"`, in
which an upload completing after a newer write may be kept or discarded. The
configurations for the design use `"either"`, so the rules hold whatever a
provider does with it. The rank is kept as the order of the uploads in flight
rather than a clock. A clock made states that differed only in its value count
twice, and the first version of the model ran past 100 million states before it
was stopped. The counterexamples ADR-010 records keep `"completion"`, the
assumption they were found under.

## Alternatives considered

**`If-Match` on the client's completion, with the ETag seen at step 2.** If the
completion succeeds, the observed version was current when it landed. That is
not the same as being replaced. In the second row above, the PUT was the current
object when A completed, so `If-Match` on its ETag would have been met. Whether
AWS would then keep A or still keep the PUT was not measured. A rule resting on
that would rest on behaviour AWS does not document. The condition would also
turn two concurrent uploads, which S3 allows, into a 412 for one of them.

**Treat it as AWS's problem and document it.** The cost is an object every
client is told was written and no client can read. That is the failure invariant
I1 exists to rule out.

**A lock per key.** The gateway is stateless by design (ADR-006), and its
instances share nothing but the provider.

**Yield to an open upload only on providers that discard.** That would mean
measuring the ordering before every run, as `probe` measures the conditions.
The check costs one `ListMultipartUploads` per object and is right on every
provider, so it runs everywhere.

## Consequences

- A completion that replaces a multipart object makes one more request, a HEAD.
  A rotated or migrated object costs one `ListMultipartUploads`, and both
  commands now need `s3:ListBucketMultipartUploads`, which `gc` already did.
- An upload a client abandons without aborting blocks the rotation and the
  migration of its key until a lifecycle rule for incomplete uploads aborts it,
  or the operator does. Each run reports that key. A bucket without such a rule
  keeps the upload, and pays for its parts, indefinitely.
- Two `migrate-names` runs over the same objects at once, or two rotations, now
  get in each other's way. An open upload cannot be told apart from a client's,
  so each run takes the other's copy for one and gives way to it. Where they
  meet, both leave the object and report it, and a later run finishes it.
  `TestIntegrationMigrateTwoRunsAtOnce` holds two runs to losing and duplicating
  nothing. It used to hold them to finishing every object between them.
  Yielding only to an upload created earlier would have kept that. But it needs
  the creation times a listing reports to order two uploads made moments apart,
  and that is not documented and was not measured.
- A completion AWS discards still answers the client 200, as AWS answers it.
  The gateway logs it and keeps the manifest, which gc collects. Garage refuses
  the completion, and the client gets `NoSuchUpload`.
- Two limits remain. A small object rotated with `--allow-unconditional` is
  copied with one `CopyObject` and not checked; that mode already requires
  nothing to write to the prefix. And with rollback detection on, a discarded
  completion that replaced a single-part object or nothing is not seen as
  discarded, because no HEAD is made, and is recorded. The next read reports
  `RollbackDetected`. That is the limit THREAT_MODEL §5.1 states for several
  writers on one key.
- `TestFaultDiscardedCompletionKeepsTheVisibleManifest`,
  `TestIntegrationRotateYieldsToAnUploadInProgress` and
  `TestIntegrationMigrateYieldsToAnUploadInProgress` pin the three decisions on
  MinIO and Garage. The first simulates the discard, because neither provider
  produces it. Each fails with its change taken out. The AWS workflow meets the
  real thing.

## What building it found

- **The same AWS run found a second defect.** AWS delivers a failed condition
  inside a `200`, once a completion has started streaming, and the client gave
  every such error a 500. `probe` then measured an enforced condition as
  refused. Fixed separately in #62.
- **MinIO and Garage disagree with AWS and with each other.** Neither the
  integration suite nor the model could have found this without a provider that
  discards. The model had the assumption written down and the suite ran against
  providers that do not discard.
