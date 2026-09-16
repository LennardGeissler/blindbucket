# Architecture Decision Records

Each ADR follows the same shape: **context**, **decision**, **alternatives considered**,
**consequences**. The alternatives section is the point of the exercise — a decision without
rejected options is not a decision, it is a default.

| Nr. | Title | Status | Milestone |
|---|---|---|---|
| [001](ADR-001-segment-format.md) | Segment format: STREAM with AES-256-GCM, 64 KiB chunks, authenticated header | Accepted | M0 |
| [002](ADR-002-key-hierarchy.md) | Key hierarchy: external root key, in-memory KEK ring, one DEK per object | Accepted | M0 |
| [003](ADR-003-upstream-client.md) | A custom upstream client on `net/http` instead of the SDK's S3 client | Accepted | M2 |
| [004](ADR-004-fail-closed.md) | Fail-closed by aborting the connection after response headers are sent | Accepted | M2 |
| [005](ADR-005-checksums.md) | Checksums: verify locally, never forward, withhold the final chunk | Accepted | M3 |
| [006](ADR-006-upload-token.md) | Statelessness via an encrypted upload token | Accepted | M4 |
| [007](ADR-007-manifest-sidecar.md) | The manifest as a sidecar object, with its id in the object metadata | Accepted | M4 |
| [008](ADR-008-part-sizes.md) | Part sizes as multiples of the chunk size | Accepted | M4 |
| [009](ADR-009-rotation-by-copy.md) | Rotation by copy, preserving part structure, with conditional writes | Accepted | M5 |
| [010](ADR-010-manifest-lifecycle-under-concurrency.md) | Manifest lifecycle under concurrency (R1–R4, checked with TLA+) | Accepted | M3.5 |
| [011](ADR-011-languages-outside-the-go-core.md) | Languages and tools outside the Go core | Accepted | M0 |
| [012](ADR-012-copy-semantics.md) | Copy semantics: re-wrap and keep the ciphertext, re-encrypt for part copies | Accepted | post-M5 |
| [013](ADR-013-root-key-sources.md) | Root-key sources: Vault Transit and AWS KMS, unsealing at startup | Accepted | M5 |
| [014](ADR-014-part-salts-in-the-manifest.md) | Part salts in the manifest, carried there by the part ETag | Accepted | post-M5 |
| [015](ADR-015-object-name-encryption.md) | Object name encryption: deterministic, per path segment | Accepted | M6 |
| [016](ADR-016-audit-log.md) | A hash-chained, signed audit log, one chain per instance | Accepted | post-M5 |
| [017](ADR-017-listing-order-under-name-encryption.md) | Listing order under name encryption: buffer and sort, bounded, or refuse | Accepted | M6 |
| [018](ADR-018-rollback-detection.md) | Rollback detection: a local freshness index, trust on first use | Accepted | M6 |
| [019](ADR-019-presigned-urls.md) | Presigned URLs: verified, never issued, and only for reads | Accepted | M6 |

Every entry is Accepted. 018 was Proposed while it was a decision without code, for the
same reason 015 was: its decisions already constrained the code while the code did not yet
use them. 015 and 017 became Accepted together, when name encryption went from a primitive
nothing called to something every operation goes through; 016 depended on 015 in the
meantime -- the audit log encrypts the names in its entries with 015's primitive, which was
its first shipped caller.

The pair is worth reading in order, because each corrected the other. 017 closed the one
question 015 left open, and the measurements it took to do that showed 015's key-expansion
figure was a best case quoted as a rule. Building 017 then corrected 017: the server-side
state it expected to need turned out to be unnecessary, because S3's own pagination
parameters already carry the whole resume state of a listing. Both corrections are in the
documents rather than quietly dropped, which is the point of keeping them.

018 is the decision 002 deferred, and it closes the last **No** in the threat model's own
risk table. 002 rejected a version index in M0 and wrote "the rollback mitigation is
deferred to M6" into its alternatives; 016 then declined to be that mitigation in its own
words, so that a log named "audit" would not be read as one. 018 re-examines what 002
actually rejected -- a *shared* index a read's correctness depends on -- and finds a local,
advisory one is neither.

Building it corrected its own measurements, which is now a habit rather than a coincidence.
018's first table came from a prototype that held only a tag; the real entry holds a kind
and a timestamp as well, so the cost per object was 30 % higher than the figure an operator
would have planned with, and the write cost was missing entirely because a prototype that
never wrote could not report it.

019 closes M6. Its substance is a narrowing rather than an addition: S3 lets a client
presign any operation, and this gateway serves two of them. The argument is the accident
rather than the attacker -- a link preview that issues a GET is a GET, one that issues a
DELETE is data loss with nobody hostile in the story -- and it is the same instinct 012
followed in refusing object tags rather than storing them in clear.

ADR numbers reflect the order the decisions were identified, not the order they are made.
010 and 011 were added in design version 0.2; 011 was decided in M0 because it governs what
may enter the repository from the start, while 010 waited for the model checker in M3.5.
