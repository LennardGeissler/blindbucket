# Formal models of the manifest coordination and the name migration

[`Multipart.tla`](Multipart.tla) models the coordination described in
[ADR-010](../../docs/adr/ADR-010-manifest-lifecycle-under-concurrency.md) and
[ADR-009](../../docs/adr/ADR-009-rotation-by-copy.md): what order the proxy makes its
upstream calls in when several requests work on the same key at the same time, possibly on
different instances, and any of them may die at any point.

[`Migrate.tla`](Migrate.tla) models `blindbucket migrate-names`
([ADR-022](../../docs/adr/ADR-022-migrating-to-encrypted-names.md)), which moves an object
from the key it was stored under in clear to its encrypted key. It is a module of its own
because it is the one operation that spans two stored keys; it has
[a section of its own](#migrating-names--migratetla) below.

It exists because those rules — R1 to R4 — were derived by *reasoning*. Version 0.1 of the
design contained two race conditions that were also derived by reasoning, and they survived
being written down, read again, and reviewed. Argument is not evidence, so the rules are
checked here before M4 turned them into Go.

## What is modelled, and what is not

| In the model | Not in the model |
|---|---|
| The visible object version for one key | Anything cryptographic: data keys, segments, chunk tags |
| The set of manifest sidecar objects | Part contents, part sizes, `ListParts` |
| Open multipart uploads at the upstream | More than one key — manifests and gc are per key |
| Two to three concurrent uploads, a single-part PUT, a `DeleteObject`, a rotation, one `gc` pass | The minimum-age condition in R4 step 4 (see below) |
| A crash of any process after any step, losing that process's local state | Network retries: a retried call is a repeat of the same step |
| The bucket lifecycle rule aborting an open upload at any time | |

**Why the minimum age is left out.** R4 step 4 only deletes manifests older than the
lifecycle window plus 24 hours. That threshold is a guard against the *upstream assumptions*
failing — it does nothing if they hold, and the model assumes they hold. Modelling it would
therefore make R4 look safe for a reason that has nothing to do with its ordering, which is
the part that was never checked. The ordering argument stands on its own here, and the
threshold remains a second line of defence rather than the first.

**The upstream assumptions themselves** are assumptions of the model, not results of
it: read-after-write consistency for HEAD, LIST and `ListMultipartUploads`, and a completed
or aborted upload id never making an object visible again. For AWS S3 these are guaranteed;
for MinIO and R2 they belong in the compatibility matrix, not in TLC.

## Invariants

- **I1** — every visible multipart object has a manifest with its manifest id. An object
  that fails I1 is not lost (the ciphertext and the data key are still there) but every GET
  against it fails.
- **I2** — rotation never replaces a newer version of an object with an older one.

The liveness property listed as optional — that orphaned manifests eventually disappear
under fairness — is **not** modelled. It would need a `gc` that loops rather than making one
pass, plus fairness on the lifecycle rule, and liveness checking costs far more than the
safety run. Both invariants above are safety properties, and orphaned manifests are a
cleanup concern rather than a correctness one: they hold no plaintext, and an object that
keeps one around is still perfectly readable.

## Configurations

Four of the five configurations of `Multipart.tla` are expected to **fail**, and four of the
five of `Migrate.tla` (listed [with that model](#migrating-names--migratetla)). A model that cannot reproduce the
two races the design already knows about is too coarse to be evidence about the races it
does not know about, so "no counterexample" is a failing result for those four.

| Configuration | Rules | Expected |
|---|---|---|
| `MCFixed` | R1–R4, conditional rotation, 3 uploads | no counterexample |
| `MCLegacyCleanup` | completion deletes *every other* manifest of the key (v0.1) | **I1 violated** |
| `MCLegacyGc` | `gc` never checks for open uploads (v0.1) | **I1 violated** |
| `MCGcOrder` | R4 with steps 1 and 2 swapped | **I1 violated** |
| `MCUnconditionalRotate` | `rotate --allow-unconditional` | **I2 violated** |

The three I1 configurations run with `RotateMode = "off"`, so their counterexamples contain
only operations that M4 itself implements and can replay as integration tests.

## Running it

```sh
make tla-tools     # downloads tla2tools.jar into .tools/ (not committed)
make tla           # runs all ten configurations of both models
make tla-translate # re-run the PlusCal translator after editing an algorithm
```

`check.sh` takes configuration names if only some are wanted:

```sh
./check.sh MCLegacyGc MCGcOrder
```

`MCFixed` explores about 38.5 million distinct states — roughly 21 CPU-minutes, so about
three minutes on eight cores. `MCMigrate` explores about 3.1 million in well under a
minute, and the other eight finish in seconds. The CI job runs on changes to
`spec/tla/` or to the coordination code rather than on every push.

One caveat worth stating plainly, since "exhaustive" is doing a lot of work above: TLC
recognises a state it has already seen by a 64-bit fingerprint, so at tens of millions of
states there is a small chance two distinct states collide and one subtree goes unexplored.
TLC estimates that probability itself and `check.sh` prints it — for `MCFixed` it lands
between 1e-4 and 3e-3 depending on the run. That is a property of the hash width, not of the
machine, so more memory does not move it; rerunning with a different `-fp` seed and getting
the same answer is what buys extra confidence. The four counterexample runs are unaffected: a
trace TLC prints is a trace that exists.

Each checked-in module contains both its PlusCal algorithm and its translation. CI re-runs
the translator and fails if the result differs, so the two can never drift apart.

## The counterexamples

Each trace below is what TLC prints, with the incidental steps of uninvolved processes left
out; `./check.sh` regenerates them in full. Each is a scenario for the M4 integration tests,
where test hooks hold a request at a named point until another request has passed its own.

### 1. Cleanup against a concurrent upload — `MCLegacyCleanup`

The version 0.1 rule for step 5 of the completion order was "delete the other manifests of
this key". TLC reaches an unreadable object in eleven states.

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` — a single-part object is visible | |
| 2 | u1, u2 | `CreateMultipartUpload` on the same key | two uploads open |
| 3 | u1 | HEAD — the visible object is single-part | observed: none |
| 4 | u1 | write manifest `u1` | manifests: `{u1}` |
| 5 | u1 | `CompleteMultipartUpload` | **visible: multipart `u1`** |
| 6 | u2 | HEAD — sees `u1` | observed: `u1` |
| 7 | u2 | write manifest `u2` | manifests: `{u1, u2}` |
| 8 | u1 | cleanup: delete every *other* manifest | manifests: `{u1}` ← **`u2` is gone** |
| 9 | u2 | `CompleteMultipartUpload` | **visible: multipart `u2`**, manifest missing |

Step 8 is the bug: u1's own completion finished three steps earlier, but the request had not
got around to its cleanup yet, and by then u2 had written a manifest that u1 knows nothing
about. R3 fixes it by licensing a request to delete exactly one id — the one it observed at
step 2 — and nothing else.

**M4 integration test:** `TestIntegrationRaceCleanupAgainstConcurrentUpload`. It holds u1
between `CompleteMultipartUpload` and the manifest delete, lets u2 run its HEAD and write its
manifest, releases u1, completes u2, and requires the object to read back as u2's.

### 2. `gc` against an upload in flight — `MCLegacyGc`

Version 0.1's `gc` listed the manifests, read the current manifest id, and deleted the rest.

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` — a single-part object is visible | current manifest id: none |
| 2 | u1 | `CreateMultipartUpload`, HEAD, write manifest `u1` | manifests: `{u1}`, upload open |
| 3 | gc | list manifests | listed: `{u1}` |
| 4 | gc | HEAD — the visible object is single-part | current: none |
| 5 | gc | delete every listed manifest that is not current | manifests: `{}` ← **`u1` is gone** |
| 6 | u1 | `CompleteMultipartUpload` | **visible: multipart `u1`**, manifest missing |

`gc` was right about every fact it observed. `u1` really was not the current manifest id at
step 4 — it just was not current *yet*. R4 step 2 closes this by asking
`ListMultipartUploads` first and skipping the key entirely while an upload is in flight.

**M4 integration test:** `TestIntegrationRaceGcAgainstUploadInFlight`. It holds a
`CompleteMultipartUpload` after its manifest write, runs a whole `gc` pass with the age guard
switched off, releases the upload, and requires both that the object reads back and that the
pass reported the key as skipped — otherwise the open-upload check never fired and the test
would pass for the wrong reason.

### 3. R4 with its first two steps swapped — `MCGcOrder`

This one is not a bug from version 0.1. It is a check on R4 itself, and it is the reason R4
fixes an order for two steps that only *read*.

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` — a single-part object is visible | |
| 2 | gc | `ListMultipartUploads` — **nothing open**, carry on | |
| 3 | u1 | `CreateMultipartUpload`, HEAD, write manifest `u1` | manifests: `{u1}`, upload open |
| 4 | gc | list manifests | listed: `{u1}` |
| 5 | gc | HEAD — still single-part | current: none |
| 6 | gc | delete the listed non-current manifests | manifests: `{}` |
| 7 | u1 | `CompleteMultipartUpload` | **visible: multipart `u1`**, manifest missing |

Swapping two read-only steps is the kind of edit that passes review, because neither step
changes anything. It is still wrong. Listing *first* is what makes the open-upload check
mean something: every manifest in the listing was written before the check ran, so an upload
that could still publish one of them would have been open at the time of the check. Check
first and the listing picks up manifests written afterwards, about which the check said
nothing.

This is the result that pays for the milestone. The argument for R4 is correct, but
nothing in it announces that the order of steps 1 and 2 is load-bearing, and nobody reading
the finished Go code would either.

**M4 integration test:** `TestIntegrationRaceGcOrderingIsLoadBearing`. It holds `gc` after its
listing, runs an entire upload to completion inside that window, and then requires both that
the new object reads back and that an orphan from before the listing was collected — so a pass
that did nothing at all cannot be mistaken for a pass that did the right thing.

### 4. Rotation without a conditional write — `MCUnconditionalRotate`

`blindbucket rotate --allow-unconditional`, the mode permitted on upstreams that have no
conditional writes. Six states:

| # | Who | Step | Result |
|---|---|---|---|
| 1 | rotate | HEAD the object, note its etag | |
| 2 | client | `PutObject` — overwrites the object | **the client's data is the visible version** |
| 3 | rotate | create upload, copy parts, write manifest | |
| 4 | rotate | `CompleteMultipartUpload`, no `If-Match` | **visible: the pre-rotation version** |

The client's write is gone. With `If-Match` the completion fails with 412, rotation reports
the object as skipped, and the client's write stands. I2 holds in every other configuration
because of that one header.

This is not a defect to fix — it is the documented price of the flag, and the model is what
makes the warning in the documentation a measured statement rather than a hedge.

**M5 integration test:** `TestIntegrationRotateDoesNotLoseUpdates`. It holds a rotation after
it has read the object, lets a client replace the object through the gateway, releases it, and
requires the client's bytes to be the ones that survive and the rotation to report the object
as skipped rather than rotated.

With that, all four counterexamples have tests. Running it also answered a question the design left
open: MinIO enforces both guards, and it is the copy rather than the completion that refuses
first — `x-amz-copy-source-if-match` fails before any part is written. Both answer 412, and
both mean the same thing to the caller.

---

## Migrating names — `Migrate.tla`

`blindbucket migrate-names` moves an object stored under its key in clear, `P`, to `E(P)`,
the key the same client name maps to with object-name encryption on. Per object it reads
`P`, reads `E(P)`, copies `P` to `E(P)` if nothing is there, deletes `P`, and deletes the
manifest it observed under `P` (R3). The copy is an `objcopy` multipart upload, so it brings
its own manifest under `E(P)` and obeys R1 and R2 there.

The model holds the gateway in the mode ADR-022 requires: serving with names encrypted on
every instance before the migration starts. Clients therefore read, write and delete at
`E(P)` only, and `P` is reached by nothing but the migration.

| In the model | Not in the model |
|---|---|
| One object identity, at two stored keys: `P` and `E(P)` | More than one object — runs work per object |
| Two migration runs, each able to die after any step: a restart, or two operators at once | The data-key comparison; it decides what a run reports, not what it does |
| A client `PutObject`, a client multipart upload and a client `DeleteObject`, all at `E(P)` | Keys too long to encrypt and objects the gateway did not write — left where they are, and counted |
| One `gc` pass per stored key, and the lifecycle rule | |
| Optionally, an instance still serving names in clear, writing `P` | |

### Invariants

- **I1** — at both keys: every visible multipart object has its manifest.
- **NoLostWrite** — the newest write to the object exists somewhere: at `E(P)`, or at `P`
  while the migration has not reached it. A copy is not a write; it moves a version.
- **NoLostDelete** — an object a client deleted does not come back.
- **Converged** — once every run has stopped and one of them finished cleanly, `P` is gone.
  Without it, a migration that never deletes anything would satisfy the other three.

### Configurations

| Configuration | Variation | Expected |
|---|---|---|
| `MCMigrate` | the design: copy with `If-None-Match: *`, an object at `E(P)` makes `P` obsolete, delete `P` unconditionally | no counterexample |
| `MCMigrateNoCreateGuard` | the copy published without `If-None-Match` | **NoLostWrite violated** |
| `MCMigrateLeaveOnResume` | a run that finds an object at `E(P)` leaves `P` alone | **Converged violated** |
| `MCMigrateStaleWriter` | an instance still serving names in clear writes `P`; the delete of `P` carries `If-Match` | **NoLostWrite violated** |
| `MCMigrateClientDelete` | a client deletes the object while it is still at `P` | **NoLostDelete violated** |

Two of the design's decisions come out of these runs rather than going into them.

**The delete of `P` needs no condition.** `MCMigrate` deletes `P` unconditionally and holds,
because with every instance switched nothing writes `P` any more. `MCMigrateStaleWriter`
gives the delete `If-Match` and still loses a write, because the run reads the stale version
before it deletes it and the condition then matches. So the guard is not load-bearing where
the precondition holds and not sufficient where it does not. Measured on 2026-10-02, MinIO
and Garage v2.4.1 both ignore `If-Match` on `DeleteObject` anyway.

**An object at `E(P)` makes `P` obsolete, whatever it is.** It is either a copy a run
published before dying — the same data key — or a client's write through the switched
gateway, which is newer than anything at `P`. Both mean `P` can go. The code compares data
keys only to report which of the two it was.

### 5. The abort: copy published, `P` not deleted — `MCMigrateLeaveOnResume`

This is the case the model was written for. Eleven states:

| # | Who | Step | Result |
|---|---|---|---|
| 1 | r1 | HEAD `P`, HEAD `E(P)` — nothing there | |
| 2 | r2 | HEAD `P` | |
| 3 | r1 | create the upload, copy, write manifest `r1` under `E(P)`, complete | **`E(P)`: the copy**; `P` still there |
| 4 | r1 | dies before deleting `P` | |
| 5 | r2 | HEAD `E(P)` — finds the copy, leaves `P`, finishes | **`P` stays for good** |

Nothing is lost — the object exists twice — and that is exactly why the bug is easy to
miss: every safety invariant holds. What fails is that the bucket never finishes migrating.
`P` keeps the name in clear at the provider, and every later run finds the same copy and
leaves the same `P`. The rule in `MCMigrate`, that an object at `E(P)` makes `P` obsolete,
is what lets the restart finish what the abort left.

**Integration test:** `TestIntegrationMigrateFinishesAnAbortedRun`. It stops a run after the
copy is published and before `P` is deleted, starts a second, and requires `P` and its
manifest to be gone, the object to read back through the gateway, and the second run to
report the object as resumed.

### 6. Copying over a client write — `MCMigrateNoCreateGuard`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | r1 | HEAD `P`, HEAD `E(P)` — nothing there | |
| 2 | client | `PutObject` through the gateway | **`E(P)`: the client's object** |
| 3 | r1 | create, copy, manifest, complete without a condition | **`E(P)`: the older object from `P`** |

The gateway serves while the migration runs, so this window is open for every object. With
`If-None-Match: *` the completion fails with 412, the run reads `E(P)` again, finds the
client's object and deletes `P` as obsolete. Garage v2.4.1 ignores the header, measured on
2026-10-02 — so there, as for rotation, the run needs `--allow-unconditional` and nothing
writing meanwhile.

**Integration test:** `TestIntegrationMigrateKeepsAClientWrite`. It holds a run after it has
read `E(P)`, lets a client put through the gateway, releases the run, and requires the
client's bytes to survive and the run to report the object as superseded.

### 7. An instance still serving names in clear — `MCMigrateStaleWriter`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | r1 | HEAD `P`, HEAD `E(P)`, create, copy | |
| 2 | stale | `PutObject` to `P` | **`P`: the newest write** |
| 3 | r1 | manifest, complete | `E(P)`: the copy of the *older* `P` |
| 4 | r2 | HEAD `P` — the new version — then HEAD `E(P)`: the copy | |
| 5 | r2 | delete `P` with `If-Match` on the ETag it just read | **the newest write is gone** |

This is ADR-022's precondition, and the reason it is one rather than a header. No condition
on any request helps, because the run that deletes `P` has read the version it deletes. Only
the operator can know that every instance has been restarted with the new configuration, and
`migrate-names` refuses a real run whose own configuration does not encrypt names — the
one instance it can see.

**Integration test:** `TestIntegrationMigrateLosesAWriteInClear`. It pins the limit rather
than a fix: a write to `P` that lands while a run is between its copy and its delete is gone
afterwards, so the documentation's warning cannot quietly stop being true.

### 8. Deleting an object not yet migrated — `MCMigrateClientDelete`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `DeleteObject` through the gateway | reaches `E(P)`, where nothing is |
| 2 | r1 | HEAD `P`, HEAD `E(P)`, create, copy, manifest, complete | **the object is back** |

The price of migrating without a transitional mode in the gateway, which ADR-022 chose. A
delete during the migration reaches only objects already migrated, and the documentation
says so in those words.

**Integration test:** `TestIntegrationMigrateBringsBackAnUnmigratedDelete`, which pins the
limit the same way.

---

## Where the rules ended up in the code

The hook names in `internal/proxy/hooks.go`, `internal/gc` and `internal/migrate` are the
models' action names, so a trace and a test can be read side by side.

| Model process | Go |
|---|---|
| `Up` — the upload steps | `internal/proxy/multipart.go`, `completeMultipartUpload` |
| `Del` | `internal/proxy/object.go`, `deleteObject` |
| `Gc` | `internal/gc/gc.go`, `collectKey` |
| `Put` | `internal/proxy/object.go`, `putObject` — writes no manifest, by design |
| `Rot` | `internal/rotate/rotate.go`, `writeBack` |
| `Mig` (`Migrate.tla`) | `internal/migrate/migrate.go`, `migrateOne` |
