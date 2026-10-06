# Architecture Decision Records

Each ADR follows the same shape: **context**, **decision**, **alternatives considered**,
**consequences**. The alternatives section is the point of the exercise — a decision without
rejected options is not a decision, it is a default.

## Goals the ADRs cite

Several ADRs argue from goals G1–G7. They were set in the design document the project
was built from, before any code, each with the criterion that would show it met; that
document is gone, so they are kept here.

| Goal | | Criterion | Where it stands |
|---|---|---|---|
| G1 | Confidentiality of object contents against the storage provider | The provider holds only data in the format of [FORMAT.md](../FORMAT.md); plaintext and keys never leave the trusted side | Met |
| G2 | Integrity | Any tampering with content ends in an error, never in wrong plaintext | Met; [THREAT_MODEL.md](../THREAT_MODEL.md) section 3 lists what is and is not covered |
| G3 | Constant memory | Peak RSS for a 10 GiB upload and download under 50 MiB for the proxy and under 20 MiB for the CLI | Met per stream: 0.5 MiB Go heap for 10 GiB, 12 MiB resident for a 5 GiB stream through the proxy. Not met as literally worded: a 10 GiB `aws s3 cp` keeps ten parts in flight and peaks at 82 MiB, and the CLI's ~70 MiB is the one-time Argon2id arena, which [002](ADR-002-key-hierarchy.md) keeps on purpose |
| G4 | S3 compatibility | AWS CLI and boto3 pass the integration suite including ranges and multipart; rclone and `mc` documented | Met; [COMPATIBILITY.md](../COMPATIBILITY.md) |
| G5 | Horizontal scaling | A multipart upload across two instances behind round-robin, without sticky sessions | Met, in CI on every commit |
| G6 | Rotation without re-upload | Changing the KEK of a prefix only through server-side copy operations | Met; [009](ADR-009-rotation-by-copy.md) |
| G7 | Traceability | Format specification with test vectors, a threat model, reproducible benchmarks in the repository | Spec, vectors and threat model met. The network benchmark and the laptop micro-benchmarks have their raw output committed ([`bench/figures/aws/`](../../bench/figures/aws/), [`bench/figures/local/`](../../bench/figures/local/)); the gateway's resident memory with real clients (`bench/gateway-memory.sh`) still does not |

## Records

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
| [020](ADR-020-conditional-writes-measured.md) | Conditional writes are measured before a rotation, not assumed | Accepted | M7 |
| [021](ADR-021-what-1.0-promises.md) | What 1.0 promises: data at rest forever, interfaces per major, the rest not at all | Accepted | M10 |
| [022](ADR-022-migrating-to-encrypted-names.md) | Migrating a bucket to encrypted names: switch first, then copy and delete | Accepted | post-1.0 |
| [023](ADR-023-resealing-a-keyring.md) | Resealing a keyring: verified before it replaces, and no second door | Accepted | post-1.0 |
| [024](ADR-024-aws-credentials-without-the-sdk.md) | AWS credentials without the SDK: a resolver of our own, chosen explicitly | Accepted | post-1.0 |
| [025](ADR-025-writes-rank-by-when-they-began.md) | On AWS a completion is not a publication: writes rank by when they began | Accepted | post-1.0 |
| [026](ADR-026-empty-parts-refused-on-arrival.md) | Empty multipart parts are refused on arrival | Accepted | post-1.0 |

Every entry is Accepted. 025 was Accepted with its code: it corrects an assumption
010 had stated as fact, which the AWS workflow disproved, and amends 009 and 022 for
the same reason. 024 was Proposed until the gateway and the Helm chart
used what it decides. 022 was Proposed between its model and its code, which
landed a day apart. 021 was Proposed until `v1.0.0`: it decides what that
release promises, so it took effect with it. 018 was Proposed while it was a decision without code, for the
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

022 is the migration 015 left as a remark, and the first decision since 010 that
was checked by a model before any of its code existed. The model changed it: the
guard the first plan put on deleting the key in clear turned out to be neither
needed where the precondition holds nor enough where it does not, and measuring
the providers afterwards found both of them ignore it anyway.

023 closes what 013 left open, and corrects what the documentation said in the
meantime: the workaround it offered for changing a keyring's source -- a new
keyring, and a rotation onto it -- could never have worked, because rotation
needs the old keys in the keyring it runs against. Its one real risk is a key
service that seals and will not unseal, so the decision is less about resealing
than about not replacing a file before what replaces it has been opened.

024 is the first decision whose argument is a count of modules. The SDK would
have answered the whole question in one import and twelve modules; the decision
is that a deliberately short dependency list is worth about nine hundred lines
of protocol code, and it differs from the SDK on purpose where the SDK's
convenience is a risk -- a chain that falls through to the node's role.

ADR numbers reflect the order the decisions were identified, not the order they are made.
010 and 011 were added in design version 0.2; 011 was decided in M0 because it governs what
may enter the repository from the start, while 010 waited for the model checker in M3.5.
