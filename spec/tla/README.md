# Formal models of the manifest coordination, the name migration and tenants

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

[`Tenants.tla`](Tenants.tla) models tenants and their destruction
([ADR-038](../../docs/adr/ADR-038-tenants-and-crypto-shredding.md)): which copies of which
keys exist where, and which objects they still open. It checks a different question from
the other two, and has [its own section](#tenants--tenantstla) below.

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
| Two to three concurrent uploads, a single-part PUT, a `DeleteObject`, a rotation, one `gc` pass | The minimum-age condition in R4 step 4, for manifests (see below) |
| The tag sidecars of ADR-037, and which are younger than `gc`'s minimum age (`Tags`) | `PutObjectTagging` and `DeleteObjectTagging` on a version already visible |
| A crash of any process after any step, losing that process's local state | Network retries: a retried call is a repeat of the same step |
| The bucket lifecycle rule aborting an open upload at any time | |
| Which write the provider keeps when an upload completes after a newer one (`Ordering`) | When a write began, beyond the order: the model keeps the order of the uploads in flight, not a clock |

**Why the minimum age is left out.** R4 step 4 only deletes manifests older than the
lifecycle window plus 24 hours. That threshold is a guard against the *upstream assumptions*
failing — it does nothing if they hold, and the model assumes they hold. Modelling it would
therefore make R4 look safe for a reason that has nothing to do with its ordering, which is
the part that was never checked. The ordering argument stands on its own here, and the
threshold remains a second line of defence rather than the first.

**Why it is in for sidecars.** A tag sidecar is written before the object version it
belongs to, as a manifest is ([ADR-037](../../docs/adr/ADR-037-encrypted-object-tags.md)).
For a manifest, the open upload is what keeps `gc` away in the meantime. A single-part PUT
opens no upload, so for its sidecar the minimum age is the only guard, not a second one,
and the model has to have it. A sidecar starts young and ages once the process that wrote
it is done: that is the assumption the eight days stand for, that no request runs longer.
`gc` records at its listing which sidecars were old, as the listing's `LastModified`
does, and deletes only those. `MCTagsNoAge` is the same model with the age ignored.

Two steps are folded. For an upload, the sidecar and `CreateMultipartUpload` are one
step, and for the rotation the sidecar and the copy's manifest. Between the two real
requests the sidecar is young and its writer still running, so with the age `gc` cannot
take it, and without the age the PUT already shows the race. `PutObjectTagging` and
`DeleteObjectTagging` are left out: they write or remove the sidecar of a version they
have just read, which can only leave an orphan.

**The upstream assumptions themselves** are assumptions of the model, not results of
it: read-after-write consistency for HEAD, LIST and `ListMultipartUploads`, and a completed
or aborted upload id never making an object visible again. For MinIO and R2 they belong in
the compatibility matrix, not in TLC.

One assumption was dropped because it was wrong. The model used to take a successful
completion as making its object the visible one, and this README said AWS S3 guarantees
that. It does not. AWS keeps whichever write *began* last, and answers a completion it then
discards with a success. MinIO keeps the write that lands last, and Garage refuses the
completion it outranks (measured,
[ADR-025](../../docs/adr/ADR-025-writes-rank-by-when-they-began.md)). Which one a
provider does is now the constant `Ordering`. The design's configurations use `"either"`,
in which such a completion may be kept or discarded, so the rules have to hold whatever the
provider does. The counterexamples of ADR-010 keep `"completion"`, the assumption they were
found under.

## Invariants

- **I1** — every visible multipart object has a manifest with its manifest id. An object
  that fails I1 is not lost (the ciphertext and the data key are still there) but every GET
  against it fails.
- **I2** — rotation never replaces a newer version of an object with an older one, and
  never makes the provider discard a client's write in favour of its copy.
- **I3** — every visible object version that was written with tags has its sidecar. An
  object that fails I3 reads as before; its tags are gone. Checked by the `MCTags`
  configurations; with `Tags = FALSE`, as everywhere else, it holds trivially.

The liveness property listed as optional — that orphaned manifests eventually disappear
under fairness — is **not** modelled. It would need a `gc` that loops rather than making one
pass, plus fairness on the lifecycle rule, and liveness checking costs far more than the
safety run. Both invariants above are safety properties, and orphaned manifests are a
cleanup concern rather than a correctness one: they hold no plaintext, and an object that
keeps one around is still perfectly readable.

## Configurations

Nine of the fourteen configurations of `Multipart.tla` are expected to **fail**, and five
of the six of `Migrate.tla` (listed [with that model](#migrating-names--migratetla)), and seven of the eight of
`Tenants.tla` ([with that model](#tenants--tenantstla)). A model that cannot reproduce the
two races the design already knows about is too coarse to be evidence about the races it
does not know about, so "no counterexample" is a failing result for those twenty-one.

| Configuration | Rules | Expected |
|---|---|---|
| `MCFixed` | R1–R4 with R3 deleting only after a HEAD has seen the replacement, rotation conditional and giving way to open uploads, `Ordering = "either"`, 2 uploads | no counterexample |
| `MCFixedFull` | the same with 3 uploads — run only when named, see below | no counterexample |
| `MCLegacyCleanup` | completion deletes *every other* manifest of the key (v0.1) | **I1 violated** |
| `MCLegacyGc` | `gc` never checks for open uploads (v0.1) | **I1 violated** |
| `MCGcOrder` | R4 with steps 1 and 2 swapped | **I1 violated** |
| `MCUnconditionalRotate` | `rotate --allow-unconditional` | **I2 violated** |
| `MCAwsOrder` | R3 as ADR-010 wrote it, on a provider that ranks writes as AWS does | **I1 violated** |
| `MCAwsRotate` | rotation with `If-Match` alone, on the same provider | **I2 violated** |
| `MCEncrypt` | `encrypt-existing` with names in clear: the key starts with a plaintext object and no manifest (`Initial = "plaintext"`), overwritten with rotation's conditional write, `Ordering = "either"`, 2 uploads | no counterexample |
| `MCEncryptUnconditional` | `encrypt-existing --allow-unconditional` | **I2 violated** |
| `MCEncryptAws` | `encrypt-existing` with `If-Match` alone, on a provider that ranks writes as AWS does | **I2 violated** |
| `MCTags` | `MCFixed` with tags (`Tags = TRUE`): every client write tagged, the rotation carrying its source's tags, `gc` deleting only sidecars past its minimum age, 1 upload | no counterexample |
| `MCTagsFull` | the same with 2 uploads — run only when named, see below | no counterexample |
| `MCTagsNoAge` | `MCTags` with 2 uploads and `gc` ignoring the minimum age for sidecars (`TagAge = "ignored"`) | **I3 violated** |

The I1 configurations run with `RotateMode = "off"`, so their counterexamples contain
only operations that M4 itself implements and can replay as integration tests.

**The three `MCEncrypt` configurations** check `blindbucket encrypt-existing`
([ADR-034](../../docs/adr/ADR-034-encrypting-existing-objects.md)) with names in clear. Its
write is a rotation's final write in the same order, so the rotation process stands for it;
what differs is the start. The constant `Initial` makes the key hold a single-part object
with no manifest, written before the gateway, instead of a multipart object the gateway
wrote, and every other configuration sets it to `"gateway"`. The command skips an object the
gateway wrote, where the process rotates one; that only adds behaviours, so what holds here
holds for the command. With `names.encrypt` the command writes the encrypted key and deletes
the plain one, which is `Migrate.tla`'s copy and delete, checked by its configurations as
they are.

## Running it

```sh
make tla-tools     # downloads tla2tools.jar into .tools/ (not committed)
make tla           # runs the twenty-six configurations of the three models
make tla-translate # re-run the PlusCal translator after editing an algorithm
```

`check.sh` takes configuration names if only some are wanted:

```sh
./check.sh MCLegacyGc MCGcOrder
```

`MCFixed` explores about 8.7 million distinct states and `MCMigrate` about 8.1 million,
each in five to seven CPU-minutes, `MCEncrypt` about 2.7 million and `MCTags` about 1.2
million; the other twenty-two, `Tenants.tla`'s eight among them, finish in seconds, and `make tla` takes about two minutes on ten cores. The CI job runs on changes to `spec/tla/` or to the
coordination code rather than on every push.

`MCFixedFull` is not among them. Until ADR-025, `MCFixed` ran three uploads under the
old assumption, in about 38.5 million states. Under `"either"` three uploads outgrow a
laptop: a run passed 112 million distinct states, still without a violation, before it
was stopped. That is evidence, not an exhaustive result. Every counterexample either model
has produced needs at most two uploads, which is what `MCFixed` checks exhaustively. Run
it alone, with time and disk to spare:

```sh
./check.sh MCFixedFull
```

One caveat worth stating plainly, since "exhaustive" is doing a lot of work above: TLC
recognises a state it has already seen by a 64-bit fingerprint, so at tens of millions of
states there is a small chance two distinct states collide and one subtree goes unexplored.
TLC estimates that probability itself and `check.sh` prints it — for `MCFixed` it lands
between 1e-4 and 3e-3 depending on the run. That is a property of the hash width, not of the
machine, so more memory does not move it; rerunning with a different `-fp` seed and getting
the same answer is what buys extra confidence. The twenty-one counterexample runs are unaffected: a
trace TLC prints is a trace that exists.

Each checked-in PlusCal module contains both its algorithm and its translation. CI re-runs
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
| `MCMigrate` | the design: the copy gives way to an open upload of `E(P)` and is published with `If-None-Match: *`, an object at `E(P)` makes `P` obsolete, delete `P` unconditionally; `Ordering = "either"` | no counterexample |
| `MCMigrateNoCreateGuard` | the copy published without `If-None-Match` | **NoLostWrite violated** |
| `MCMigrateLeaveOnResume` | a run that finds an object at `E(P)` leaves `P` alone | **Converged violated** |
| `MCMigrateStaleWriter` | an instance still serving names in clear writes `P`; the delete of `P` carries `If-Match` | **NoLostWrite violated** |
| `MCMigrateClientDelete` | a client deletes the object while it is still at `P` | **NoLostDelete violated** |
| `MCMigrateAwsOrder` | the copy with `If-None-Match` alone, on a provider that ranks writes as AWS does | **NoLostWrite violated** |

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

---

## Writes that rank by when they began — ADR-025

The AWS workflow found these three, not the models: the models had the assumption they
break written down as a premise. With `Ordering = "initiation"` each comes out in a dozen
states, and each has an integration test that fails with its fix taken out.

### 9. A discarded completion deletes the visible manifest — `MCAwsOrder`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | u1, u2 | `CreateMultipartUpload`, u1 first | both open; u2 ranks above u1 |
| 2 | u2 | HEAD (sees `m0`), manifest `u2`, complete | **visible: u2** |
| 3 | u1 | HEAD — sees `u2` | u1 will "replace" `u2` |
| 4 | u1 | manifest `u1`, complete | answered as a success, **discarded**: u2 began later |
| 5 | u1 | step 5 under R3: delete the observed manifest `u2` | **I1 violated** — u2 visible, its manifest gone |

Twelve states, and nothing but two uploads of one key. It is the failure the AWS workflow
reported as `IntegrityCheckFailed` after two parallel uploads. Under `"verify"`, step 4 is
followed by a HEAD that still shows `u2`, and the manifest stays.

**Integration test:** `TestFaultDiscardedCompletionKeepsTheVisibleManifest`. The faulty
provider answers the completion 200 without forwarding it, as AWS's discard looks from
outside.

### 10. A rotation outranks a client's upload — `MCAwsRotate`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `PutObject` | visible: the PUT |
| 2 | rotation | HEAD — reads the PUT's ETag | |
| 3 | u1 | `CreateMultipartUpload` | open, ranked first |
| 4 | rotation | create its upload, manifest, complete with `If-Match` — the PUT is still current | **visible: the rotated copy** |
| 5 | u1 | HEAD, manifest, complete | answered as a success, **discarded**: the copy began later — **I2 violated** |

Eleven states. `If-Match` holds at step 4 because u1 is not visible yet; nothing the rotation
can put on its own write sees an upload still in flight. Listing the key's open uploads after
its own was created does: u1 is open at step 4, and the rotation gives way.

**Integration test:** `TestIntegrationRotateYieldsToAnUploadInProgress`.

### 11. A migration outranks a client's upload to `E(P)` — `MCMigrateAwsOrder`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | client | `CreateMultipartUpload` at `E(P)`, HEAD, manifest | open, ranked first |
| 2 | r1 | HEAD `P`, HEAD `E(P)` — nothing there | |
| 3 | r1 | create the copy, copy, manifest, complete with `If-None-Match: *` | **`E(P)`: the copy of `P`** |
| 4 | client | complete | answered as a success, **discarded** — **NoLostWrite violated** |

Twelve states. The same shape as 10 at the other key, and the same fix.

**Integration test:** `TestIntegrationMigrateYieldsToAnUploadInProgress`.

## Tag sidecars — ADR-037

The tag sidecars of [ADR-037](../../docs/adr/ADR-037-encrypted-object-tags.md) are in
`Multipart.tla` behind the constant `Tags`, so that every configuration above runs exactly
the states it ran before: `MCFixed` explores the same 8,666,276 with `Tags = FALSE`. With
`Tags = TRUE`, `MCTags` holds with one upload in about 1.2 million states and `MCTagsFull`
with two in 55.8 million, and the one rule the sidecars add over the manifests is the one
`MCTagsNoAge` breaks.

### 12. `gc` without the minimum age — `MCTagsNoAge`

Seven states, with nothing in flight but a PUT and a `gc` pass:

1. The PUT writes its sidecar, the step before the object (ADR-037).
2. `gc` lists the key's sidecars, the PUT's among them.
3. No upload is open, because a PUT opens none.
4. `gc` HEADs the key and finds the version before the PUT current.
5. The PUT lands. Its version is now the visible one.
6. `gc` deletes the sidecars it listed that were not current at its HEAD: the PUT's.

The object reads as it should, and its tags are gone. R4's order cannot prevent it: the
listing comes first and the HEAD after it, as R4 requires, and the PUT lands between the
HEAD and the delete. For a multipart upload the open upload covers that window; for a PUT
nothing does. The minimum age is what does. A sidecar listed as younger than eight days
is never deleted, and no PUT takes that long between its sidecar and its object. The code
has to carry the same age check for sidecars that it carries for manifests.

## Tenants — `Tenants.tla`

A tenant is deleted by destroying its keys ([ADR-038](../../docs/adr/ADR-038-tenants-and-crypto-shredding.md)),
so what can go wrong is not a lost request but a key: one that still opens what the
destruction was meant to make unreadable, or one gone that opened something it was not
meant to touch. The model therefore tracks keys, not requests. It is plain TLA+ rather
than PlusCal: its steps are an operator's and a process's, each atomic, and none of them
is a sequence of requests whose interleaving matters.

Keys live in four kinds of place, and the model has all four: the keyring file, which the
operator rewrites, each write a new generation; every earlier generation, as backups and a
Secret's history keep them, opened today with whatever locks still exist; the memory of each
gateway instance, which loaded a generation at its last restart; and the memory of a running
`rotate`.

| In the model | Not in the model |
|---|---|
| One tenant, T, and the default tenant; buckets `x` (has an object, joins T), `z` (joins T empty), `y` (stays in the default tenant) | The requests a write or a rotation makes, and their conditions: `Multipart.tla` checks those, and a rotation step here is atomic |
| Two instances, each serving the generation it loaded at its last restart | A second KEK of the same tenant: it changes which of T's keys an object is on, never whether |
| Client writes through either instance; two `rotate` runs that may die at any point, each with its own snapshot | Names and audit entries: their keys sit in the same sections as the KEKs and share their fate |
| The operator: add, activate, reseal to a second lock, census, tombstone, destroy the locks | |
| Every generation of the file ever written | |

### Invariants

- **Shredded** — once the destruction is over (locks destroyed, every process serving the
  tombstone), no object in T's buckets is on a key that any copy of the file or any running
  process still opens.
- **NoCollateral** — no object outside T's buckets ever becomes unreadable.
- **Abortable** — until the tombstone is written, nothing is unreadable: the destruction can
  still be called off.
- **ReadableEverywhere** — an instance that serves a bucket can read the object in it.

### Configurations

| Configuration | Variation | Expected |
|---|---|---|
| `MCTenants` | the design: add inactive, activate once every instance serves T, a census once no instance and no `rotate` run can still write T's buckets under another key, the tombstone, then every lock T ever had | no counterexample (7,778 states) |
| `MCTenantsNoCensus` | the tombstone without a census | **Shredded violated** |
| `MCTenantsStaleInstance` | the census while an instance still serves T inactive | **Shredded violated** |
| `MCTenantsLockFirst` | the locks destroyed before the tombstone has reached every process | **Abortable violated** |
| `MCTenantsActivateEarly` | T added active | **ReadableEverywhere violated** |
| `MCTenantsMoveBucket` | a bucket may leave T | **NoCollateral violated** |
| `MCTenantsForeignRotate` | `rotate` accepts a key that is not the bucket's tenant's | **NoCollateral violated** |
| `MCTenantsResealedLock` | after a reseal, only the current lock destroyed | **Shredded violated** |

`MCTenantsMoveBucket` and `MCTenantsForeignRotate` leave `ReadableEverywhere` out. An
instance that restarts onto the tombstone no longer opens T's key, so it cannot read the
stranded object either: the same harm, seen from the instance, which TLC would otherwise
report first.

Writing the model corrected the ADR twice before it was merged. A lock destroyed too early
was thought to stop instances from starting; it does not, since a tenant that will not open
is refused rather than fatal, and the harm is `Abortable`'s. And the census waits not only
for instances but for a running `rotate` that loaded an earlier generation, which writes T's
buckets under the default key exactly as a stale instance does.

### 13. A census before every instance serves the tenant — `MCTenantsStaleInstance`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | operator | add T, inactive; both instances restart onto it | |
| 2 | operator | activate T; only i1 restarts | i2 serves T inactive |
| 3 | i1 | write `x` | `x` on `t1` |
| 4 | operator | census: every object of T's buckets on `t1` | passes |
| 5 | operator | tombstone; i1 restarts onto it | |
| 6 | i2 | write `z` — T is inactive in what it loaded | **`z` on `d1`** |
| 7 | i2 restarts; operator destroys the locks | | `z` still opens |

Every check the operator ran was true when it ran. The census counted what was there, and
`z` was written after it, by an instance the census could not see. Rule 2 of ADR-038 is
what closes it: the census waits until the keyring generation every instance and every
running command reports is the one with T active, which the
`blindbucket_keyring_generation` metric makes checkable.

### 14. A reseal, and only the new lock destroyed — `MCTenantsResealedLock`

| # | Who | Step | Result |
|---|---|---|---|
| 1 | operator | add T under lock `L1` | the file of this generation is backed up |
| 2 | operator | reseal T to `L2`; activate | |
| 3 | i1 | write `x` | `x` on `t1` |
| 4 | operator | census, tombstone, every process restarted | |
| 5 | operator | destroy `L2`, the lock the file names | **the backup from step 1 still opens `t1` under `L1`** |

The current file was never the problem. A reseal changes the lock, not the keys
([ADR-023](../../docs/adr/ADR-023-resealing-a-keyring.md)), so every copy from before it
is a second door to the same tenant. The tombstone records every lock T was ever sealed
under, and the destruction names all of them.

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
| `upVerify` | `internal/proxy/manifeststore.go`, `replacedSince` |
| `rotUploads`, `migUploads` | `internal/objcopy/objcopy.go`, `YieldToUploads` |
