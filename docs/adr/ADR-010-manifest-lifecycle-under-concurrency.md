# ADR-010 — Manifest lifecycle under concurrency (R1–R4, checked with TLA+)

**Status:** Accepted
**Date:** 2026-09-11
**Milestone:** M3.5
**Implements:** `spec/tla/Multipart.tla`; binding on `internal/manifest` and the completion,
delete, rotation and `gc` paths in M4 and M5
**Amended by:** [ADR-025](ADR-025-writes-rank-by-when-they-began.md) — on AWS a successful
completion need not replace what step 2 observed, so R3 deletes only after a HEAD has seen
the replacement; "AWS S3 guarantees them" below does not hold for that assumption

## Context

A multipart object is stored as one segment per part. Each segment is authenticated on its
own, but nothing binds the segments into a whole, so a provider could serve an object with
parts missing or reordered and every individual tag would still verify. The manifest closes
that gap: a signed sidecar object listing the parts, named by a manifest id that the object's
own metadata points at (`FORMAT.md` §10.1).

That turns an integrity question into a lifecycle question. The manifest is a second object,
written and deleted by requests that do not coordinate with each other, and the proxy is
stateless and horizontally scaled — so two writes to the same key may be handled by different
instances that never learn of each other, and either may die mid-request.

**Invariant I1: every visible multipart object has a manifest with its manifest id.** An
object that fails I1 is not lost — the ciphertext is intact and the data key still unwraps —
but every `GetObject` against it fails. From the client's side that is indistinguishable from
data loss.

The first version of the design got this wrong twice, in both cases by deleting a manifest that
some other request was about to need: a `gc` pass removing the manifest of an upload
that had not completed yet, and a completing upload deleting "all other manifests of this
key", including those of uploads still in flight. Neither bug is visible in any single
request. Both need two requests interleaved in a particular way, which is exactly what code
review and ordinary integration tests are worst at.

The replacement rules R1–R4 were also derived by reasoning. So was version 0.1.

## Decision

Adopt R1–R4 as specified below, and **check them with a model checker before implementing
them**, rather than after.

- **R1 — fresh manifest id.** Every operation that makes a multipart object visible mints a
  new manifest id and writes its own manifest. Manifests are never shared between object
  versions.
- **R2 — write before visibility.** The manifest is written before the operation makes the
  object visible.
- **R3 — delete only what was observed.** A request deletes at most the manifest whose id it
  read from the visible object *before* its own successful replacement or deletion.
- **R4 — `gc` in a fixed order, per key.** List the manifests under the key's prefix;
  `ListMultipartUploads` and skip the key if anything is open; HEAD for the current manifest
  id; delete the listed manifests that are neither current nor younger than a minimum age.

[`spec/tla/Multipart.tla`](../../spec/tla/Multipart.tla) models the coordination — the
visible object version, the set of manifests, the open uploads — under three concurrent
uploads, a single-part PUT, a `DeleteObject`, a rotation and one `gc` pass, all on the same
key, with a crash possible after every step and the bucket lifecycle rule free to abort any
open upload at any moment. TLC checks I1 and the rotation invariant I2 exhaustively:
about 38.5 million distinct states, no counterexample.

Three further configurations put the flawed rules back and **require** TLC to produce a
counterexample. A model that cannot find the bugs the design already knows about is not
evidence about the ones it does not, so those runs failing to fail is a CI failure.
[`spec/tla/README.md`](../../spec/tla/README.md) has each counterexample written out as a
scenario for the M4 integration tests.

### What the model changed

R4 fixes an order for its first two steps, and both are read-only. `MCGcOrder` runs R4 with
those two swapped, and TLC produces a violation of I1 in twelve states: `gc` checks for open
uploads, finds none, and *then* lists — so the listing picks up the manifest of an upload
created after the check, about which the check said nothing. Listing first is what gives the
check its meaning: every manifest in the listing was written before the check ran.

The reasoning behind R4 is correct, but nothing in it flags that order as load-bearing, and
nothing in the eventual Go code would either. Swapping two calls that only read is the kind
of edit that passes review. `MCGcOrder` is now a regression test against exactly that edit,
and the Go functions for completion, delete, rotation and `gc` carry comments naming the
model actions they implement, so a reordering shows up in review against the model.

### What the model does not cover

- **The cryptography.** The model has no keys, segments or tags. It is about the order of
  upstream calls and nothing else.
- **The minimum age in R4 step 4.** That threshold guards against the upstream consistency
  assumptions failing; the model assumes they hold, so including it would make R4 look safe
  for a reason unrelated to its ordering. It stays a second line of defence.
- **The upstream assumptions themselves**: read-after-write consistency for HEAD,
  LIST and `ListMultipartUploads`, and a completed or aborted upload id never making an
  object visible again. These are inputs to the model. AWS S3 guarantees them; for MinIO and
  R2 they belong in `COMPATIBILITY.md`, which is measurement, not model checking.
- **Object versioning.** Modelled as unversioned buckets, which is what the rules target.

A checked model is evidence about the design, not about the implementation. M4's integration
tests are what connect the two, which is why every counterexample is written up as one.

## Alternatives considered

**Implement M4 first, then model if problems appear.** The cheaper order, and the reason it
was rejected is that the version 0.1 bugs did not "appear" — they were found by rereading the
design, and only after two rereads. A race that the model checker finds in eleven states can
sit in a test suite for months without ever being scheduled into existence. The model also
costs least before the code exists, when changing an order means editing a table.

**Stress tests and a race detector instead.** `go test -race` finds unsynchronised memory
access inside one process. Every race here is between processes, over state that lives at the
provider, and is perfectly race-free in the Go sense. Randomised stress testing can hit these
windows, but it cannot report their absence, and the windows are a few calls wide.

**A distributed lock or a lease per key.** Correct, and it throws away the property that
makes the design worth building: the proxy holds no state, so instances can be added,
removed and restarted mid-upload, and no load balancer needs sticky sessions. It
also adds a store to operate and a new failure mode — lock expiry under load — in exchange
for a problem that turned out to be solvable by ordering four calls correctly.

**Alloy, or a hand-written proof.** Alloy is bounded-scope by nature and would answer a
weaker question. A hand proof answers the strongest one, but the thing being checked is
precisely the reliability of hand reasoning about this design, so it would be the same
instrument twice. TLC exhausts the state space for a fixed configuration, produces a
counterexample as a concrete trace, and runs in CI — the trace is what turns into a test.

**TLA+ without PlusCal.** The rules are a sequence of upstream calls per request, which is
imperative, and writing them as actions by hand would obscure the correspondence between a
model action and a line of Go. PlusCal keeps the algorithm readable next to the code it
governs; the translation is committed alongside it and CI fails if the two drift.

## Consequences

- R1–R4 are binding on M4 and M5. `internal/manifest` and the completion, delete, rotation
  and `gc` paths name the model actions they implement in comments.
- Changing the order of upstream calls on those paths means changing `spec/tla/Multipart.tla`
  and rerunning TLC. The CI job runs on changes to `spec/tla/` or the coordination code.
- M4 inherits four integration test scenarios it did not have to invent, each with a known
  failure to reproduce first.
- Orphaned manifests are normal, not exceptional: a single-part PUT over a multipart object
  leaves one behind deliberately, to save a HEAD on the most common write path, and a crashed
  upload leaves one too. They contain no plaintext, and `gc` is the only thing that removes
  them.
- `rotate --allow-unconditional` demonstrably loses updates — `MCUnconditionalRotate` is a
  six-state counterexample to I2. The flag stays, the documented requirement that no writes
  run against the prefix meanwhile stays, and both are now statements of fact rather than
  caution.
- A second language enters the repository, under reason 3 of ADR-011.
