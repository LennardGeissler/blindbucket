# ADR-022 — Migrating a bucket to encrypted names: switch first, then copy and delete

**Status:** Accepted
**Date:** 2026-10-02
**Milestone:** post-1.0
**Implements:** `internal/migrate`, `internal/probe`, `internal/objcopy`, `internal/upstream`, `blindbucket migrate-names`
**Checked by:** [`spec/tla/Migrate.tla`](../../spec/tla/Migrate.tla)
**Amended by:** [ADR-025](ADR-025-writes-rank-by-when-they-began.md) — the copy gives way to an
open upload of `E(P)`, which AWS would otherwise discard in the copy's favour

## Context

[ADR-015](ADR-015-object-name-encryption.md) made object-name encryption a
switch that is not a toggle. With `names.encrypt` on, an object lives at the
encrypted form of its key, so turning it on hides everything written before,
and the CHANGELOG has carried the consequence as a known limitation since
`v0.4.0`: *there is no migration command; moving an existing bucket across is
a rewrite of every object's key.* ADR-015 pointed at rotation's machinery as
the place for it.

That machinery fits better than the remark promised, for three reasons the
format already settles:

- **The data key does not move.** An object's wrapped data key is bound to the
  key the *client* names (FORMAT §6.1, §15.4), and that name does not change. A
  migration is a rename at the provider, not a re-encryption, and it moves no
  object data: [`objcopy`](../../internal/objcopy/objcopy.go) copies segments
  inside the provider, as for rotation.
- **The manifest does move.** A manifest is bound to the *stored* key and lives
  under its hash (FORMAT §10.1), so a multipart object needs a new one under
  its new key. `objcopy` already writes it, under R1 and R2.
- **Rollback detection does not notice.** The freshness tag is a hash over the
  segment salts (ADR-018), and a copy keeps the ciphertext and therefore the
  salts. A migrated object reads as fresh.

What is genuinely open is the question every migration of live data has: what
do clients see while it runs? An object's key in clear, `P`, and its encrypted
key, `E(P)`, are two different objects to the provider, and a gateway serves
from exactly one of them.

## Decision

### Switch first, then migrate

**Every gateway instance serves with `names.encrypt: true` before the
migration starts.** From then on, clients read, write and delete at `E(P)`,
and `P` is reached by nothing but the migration. `migrate-names` refuses a real
run when its own configuration does not encrypt names, since that is the one
instance it can see; a dry run works either way, so that it can be run before
the switch.

What that costs, and it is the price of having no transitional mode in the
gateway:

- **An object not yet migrated is invisible** until the run reaches it. For
  reads, a migration is a maintenance window as long as the run.
- **A delete of an object not yet migrated does not reach it**, and the
  migration brings it back. `MCMigrateClientDelete` is the counterexample, and
  the documentation states it in those words.
- **An instance still serving names in clear loses writes** made through it
  during the run (`MCMigrateStaleWriter`). It loses them to its clients anyway
  — no switched instance can read them — and the migration then makes the loss
  permanent. No request header prevents it, because the run that deletes `P`
  has read the version it deletes; it is a precondition, not a guard.

What it does not cost: **a client write during the migration is never lost.**
That case is the one the gateway cannot avoid, because it keeps serving, and
it is guarded (below).

### Per object

The steps, named as `Migrate.tla` names them and as `internal/migrate`'s hooks
are named:

1. **`migHeadPlain`** — HEAD `P`. A key that already decrypts is skipped: it is
   at its encrypted name. A key whose encrypted form would exceed 1024 bytes is
   reported as `too_long` and left (FORMAT §15.5). An object without the
   gateway's metadata is `foreign` and left, as rotation leaves it.
2. **`migHeadEnc`** — HEAD `E(P)`. If something is there, go to step 4.
3. **`migCopy` … `migComplete`** — `objcopy` from `P` to `E(P)`: same identity,
   same KEK, a new manifest under `E(P)`, `x-amz-copy-source-if-match` on the
   ETag from step 1, and **`If-None-Match: *` on the completion**. A 412 there
   means something reached `E(P)` meanwhile: read it again (step 2). A source
   that changed or vanished — another run finished it — means start the object
   over (step 1).
4. **`migDelete`** — delete `P`, unconditionally.
5. **`migManifestDel`** — delete the manifest observed in step 1, and nothing
   else (R3). A run that dies before this leaves an orphan under `P`, which `gc`
   collects like any other: it works in the provider's namespace and needs no
   name key.

The KEK is kept. A migration that rotated as a side effect would be two
operations reported as one, and rotation already has a command.

### An object at `E(P)` makes `P` obsolete

Under the precondition there are two ways for something to be at `E(P)` when a
run looks: a copy published by a run that died before deleting `P` — the case
the model was extended for — or a client's write through the switched gateway.
The first is `P` itself, the second is newer than `P`. **Either way `P` is
obsolete and is deleted.** `MCMigrateLeaveOnResume` is what happens otherwise:
a restart that only deletes what it copied itself never finishes the abort it
was started to finish, and leaves the name in clear at the provider for good.

The run compares the two data keys to say which case it was — `resumed` or
`superseded` — and that is the comparison's only role. It needs no new
metadata: `objcopy` keeps the data key (ADR-012), every client write generates
a new one, so equal data keys mean the same version.

Two exceptions, both outside what the model assumes:

- **An object at `E(P)` the gateway did not write** is a `conflict`, and `P` is
  left.
- **An object at `E(P)` with another data key that is not newer than `P`** by
  the provider's `Last-Modified` is a `conflict` too. The model starts with
  nothing at `E(P)`, which is what the precondition promises; a bucket that had
  encryption switched on once before, then off again, breaks that promise, and
  this turns it into a report rather than a deletion of the newer object. Equal
  timestamps count as not newer.

A conflict is left for the operator, and the run exits non-zero.

### Which guards, measured

| Guard | Load-bearing | Evidence |
|---|---|---|
| `If-None-Match: *` on the completion | **yes** — a client write between the run's HEAD of `E(P)` and its completion | `MCMigrateNoCreateGuard` violates NoLostWrite without it |
| `x-amz-copy-source-if-match` on the copy | not under the precondition — nothing writes `P` | sent anyway: `objcopy` always sends it, and the probe already measures it for rotation |
| `If-Match` on the delete of `P` | **no** | `MCMigrate` holds without it; `MCMigrateStaleWriter` fails with it |

Measured on 2026-10-02 with the AWS CLI, outside the gateway:

| Request | MinIO `RELEASE.2026-09-22T19-25-18Z` | Garage v2.4.1 |
|---|---|---|
| `CompleteMultipartUpload`, `If-None-Match: *`, object exists | 412 — enforced | **200 — ignored** |
| `PutObject`, `If-None-Match: *`, object exists | 412 — enforced | **200 — ignored** |
| `DeleteObject`, wrong `If-Match` | **204 — ignored**, object deleted | **204 — ignored**, object deleted |

So the one guard the model requires is the one MinIO enforces, and the one it
does not require is ignored by both. The model came first; the measurement is
why that order matters — a design that leaned on a conditional delete would have
been a guard on paper.

**The probe measures the new guard**, as ADR-020 measures the two rotation
relies on: a third check, `If-None-Match` on `CompleteMultipartUpload`, with the
same three outcomes. `migrate-names` refuses to start unless it is enforced, and
`--allow-unconditional` skips the measurement along with the condition — the
operator's statement that nothing writes to the prefix while the run lasts,
which is the one condition under which the guard has nothing to catch. Under it,
a small single-part object is copied with one `CopyObject`, by ADR-020's rule.

The probe's interface does not change meaning. ADR-021 holds `probe`'s exit code
and `probe --json`'s `guarded` field to what they said in 1.0: whether a
rotation is guarded. The new measurement is a new field, `migration`, with its
own checks and its own `guarded`, and it does not move the exit code.

### The command

`blindbucket migrate-names --config <file> s3://<bucket>[/<prefix>]`, with
`--dry-run`, `--json`, `--concurrency`, `--allow-unconditional` and `-v`, as
`rotate` has them. A dry run probes too, as a rotation's does: whether a real run
would go through is part of what it answers. It also lists every key too long to
migrate, which is the reason to run one before the switch — after it, those
objects are out of reach.

`--json` prints, with every count always present:

```json
{"bucket":"backups","prefix":"","dry_run":false,"unconditional":false,
 "started":"2026-10-02T10:00:00Z","duration_seconds":12.5,
 "scanned":1000,"migrated":990,"resumed":4,"superseded":3,
 "conflicted":0,"foreign":2,"too_long":1,"failed":0}
```

The document joins the Tier 2 interfaces of ADR-021 under its rules. The exit
code is `1` when `conflicted`, `too_long` or `failed` is above zero: **exit `0`
means every object the gateway wrote under the prefix is at its encrypted
name** — or, for a dry run, would be.

## Alternatives considered

**A transitional gateway mode.** `names.migrating`: read `E(P)` and fall back to
`P`, delete both, list both and merge. It would remove the window of invisible
objects and the undone deletes. Rejected for now, not for good: it reaches into
every read and every delete for the length of a migration, and the merged
listing is the expensive part of ADR-017 twice — two upstream walks of a prefix,
sorted and de-duplicated, under the same latency budget. A deployment can live
with a maintenance window far more cheaply than the gateway can carry that mode.
Nothing in this command would have to change if it arrived later.

**Copy first, switch later, delete last.** Copy every `P` to `E(P)` while the
gateway still serves names in clear, switch, then delete the `P`s. No window of
invisible objects. Rejected because the window does not go away, it moves: a
client write or delete at `P` after its copy is made and before the switch is
lost at the switch, and nothing at the provider tells a stale copy from a newer
write without the history the copy phase would have to keep.

**Offline only.** Stop the gateway, migrate, start it with encryption on. Simple,
and correct without any guard. Not rejected so much as included: an operator who
stops clients gets exactly this from the same command. Making it the *only* way
would refuse the case the guard makes safe — clients writing during the run.

**A conditional delete of `P`.** The obvious guard for step 4, and the one the
first plan for this command had. The model shows it is not load-bearing under the
precondition and not sufficient without it, and both providers measured ignore
it. It would have been a header that looked like safety.

**Mark copies with metadata** (`bb-migrated-from: <etag>`), to recognise a copy
left by a run that died. It changes what an object carries at rest, which ADR-021
puts in Tier 1, to answer a question the data keys already answer.

**Leave `P` when `E(P)` exists.** The cautious-looking rule: delete only what this
run copied. `MCMigrateLeaveOnResume` is its counterexample — an aborted run's `P`
is never deleted by any later run.

**Plain `CopyObject` for everything.** As in ADR-009: it flattens multipart
objects, stops at 5 GiB, and has no completion to carry the guard.

## Consequences

**Positive.**

- An existing bucket can move to encrypted names, and the known limitation since
  `v0.4.0` is closed.
- A run is idempotent and resumable, including after the abort between the copy
  and the delete: the next run finishes it and says so (`resumed`).
- No object data moves, and the KEK, the data key and the freshness tag are
  unchanged. Per object it costs two HEADs, an upload of as many part copies as
  the object has parts, a manifest write for a multipart object, and two
  deletes.
- The model is in CI with the other one, and its counterexamples are integration
  tests.

**Negative.**

- A maintenance window for reads, and deletes during it that do not reach objects
  not yet migrated. Both are stated, and both are pinned by tests so that the
  statement cannot quietly stop being true.
- The precondition — every instance switched — is the operator's to establish.
  The command can check only its own configuration.
- On Garage v2.4.1 a migration needs `--allow-unconditional` and nothing writing,
  as a rotation does.
- Every probe, and so every rotation, makes three or four more requests for the
  third measurement.
- While a migration is under way, listings through the gateway log a warning for
  every key in clear they skip, and `rotate` skips those keys too. Migrate first,
  rotate afterwards.
- On a bucket with versioning, deleting `P` adds a delete marker, and the earlier
  versions keep the name in clear until a lifecycle rule or the operator removes
  them. The command does not delete versions: that is a decision about the
  bucket's retention, which is the operator's.
- It moves objects from names in clear to encrypted ones under the keyring's one
  name key. Moving them from one name key to another — the re-keying ADR-015
  calls the same operation — is not covered: it would need a run that holds two
  name keys, and nothing yet asks for one.

## What building it found

The design held: the order the model checked is the order the code has, and each
counterexample became an integration test that passes against MinIO, with the
unguarded ones passing against Garage too. Two things came out of writing it
that the model could not have said, because both are about bytes rather than
order:

- **A migrated object keeps every header the gateway stored with it**, not only
  `Content-Type` and `Cache-Control`. `Content-Disposition`,
  `Content-Encoding` and `Content-Language` are read from the HEAD and carried
  across, and a test holds the migration to it. Rotation, written earlier,
  carries only the first two, which is a defect of its own and not this ADR's.
- **Telling a client's write from an older object takes the provider's clock**,
  whose `Last-Modified` has a resolution of a second. A real switch takes longer
  than that, so the rule costs nothing in practice; the tests that exercise it
  wait out the second.
