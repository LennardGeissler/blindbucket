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
| [015](ADR-015-object-name-encryption.md) | Object name encryption: deterministic, per path segment | **Proposed** | M6 |
| [016](ADR-016-audit-log.md) | A hash-chained, signed audit log, one chain per instance | Accepted | post-M5 |
| [017](ADR-017-listing-order-under-name-encryption.md) | Listing order under name encryption: buffer and sort, bounded, or refuse | **Proposed** | M6 |

Two entries are **Proposed** rather than Accepted, and both belong to name encryption.
015 is the design for a feature that is being built, with its primitive and its leakage
settled and its S3 consequences written down, but not yet wired into the gateway. It is
here because the decisions it records already constrain the code that exists -- and because
016 already depends on it: the audit log encrypts the names in its entries with 015's
primitive, which is its first shipped caller.

017 closes the one question 015 left open, and is the thing that actually blocks the
feature: with encrypted names a listing arrives in an order that is arbitrary to the
client, and an unsorted listing makes `aws s3 sync --delete` delete objects that exist.
It is separate from 015 because it is a decision about S3 behaviour rather than about
cryptography, and because the measurements it rests on corrected 015 rather than
confirming it.

ADR numbers reflect the order the decisions were identified, not the order they are made.
010 and 011 were added in design version 0.2; 011 was decided in M0 because it governs what
may enter the repository from the start, while 010 waited for the model checker in M3.5.
