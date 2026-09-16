# Threat Model

**Status:** Current as of `v0.3.0`, the release that made object names
encryptable ([ADR-015](adr/ADR-015-object-name-encryption.md)) and shipped the
audit log of section 5.8 ([ADR-016](adr/ADR-016-audit-log.md)). Section 4 is the
one that changed most: names can now be hidden from the provider, and what that
does **not** hide is written out there rather than left to the ADR. Revised at
every milestone that adds an attack surface.

Everything below is implemented and covered by the attack tests of section 7 --
the segment format's own guarantees (chunk integrity, ordering, truncation
detection, binding to bucket and key), the HTTP surface, client authentication,
and the multipart path including the manifest and the upload token. Where a
mitigation is deferred rather than present, the entry says so and names the
milestone.
**Last updated:** 2026-09-16

This document states precisely what blindbucket protects against and what it does not.
It is deliberately explicit about residual risk. A security tool that overstates its
guarantees is worse than one that states modest guarantees accurately.

For the same reason this project does not describe itself as "zero trust": that term
denotes an access architecture as defined in NIST SP 800-207, not an encryption scheme.

---

## 1. Assets

| Asset | Where it lives |
|---|---|
| Object plaintext | in flight between client and proxy; transiently in proxy memory |
| Key material — root key, KEKs, DEKs, token keys | KMS/Vault/passphrase; proxy memory; wrapped DEKs in object metadata |
| Client credentials for the proxy | proxy configuration |
| Upstream credentials for the storage provider | proxy configuration; never disclosed to clients |

---

## 2. Actors

| ID | Actor | Capabilities | In scope |
|---|---|---|---|
| A1 | Storage provider, passive | Reads everything stored or transmitted to it | Yes |
| A2 | Storage provider, active | Modifies, truncates, reorders, swaps and deletes objects and metadata; replays old data; lies in listings and response headers | Yes, with the limits in §5 |
| A3 | Network attacker between proxy and provider | As A1/A2, on the wire | Yes — TLS reduces this to A1/A2 |
| A4 | Unauthorised client | Sends requests to the proxy without valid credentials, or with credentials scoped to other buckets | Yes |
| A5 | Attacker on the proxy host, or with access to the KEK or root key | Reads memory, configuration, keys | **No** |
| A6 | Network attacker between client and proxy | Reads and modifies plaintext requests | Only insofar as TLS or sidecar deployment covers it |

A5 is the fundamental boundary: the proxy holds keys and sees plaintext by design. It
must reside in the same trust domain as the clients it serves.

---

## 3. Guarantees

| Property | Guaranteed | Mechanism |
|---|---|---|
| Confidentiality of object content against A1–A3 | **Yes** | AES-256-GCM; keys never leave the trust boundary in the clear |
| Integrity of each chunk | **Yes** | One GCM tag per chunk |
| Chunk ordering | **Yes** | Chunk counter in the nonce |
| Detection of truncation and extension | **Yes** | Final flag in the nonce; for multipart also the manifest |
| Binding of content to bucket and key | **Yes** | Bucket and key as associated data when wrapping the DEK |
| Detection of reordered or missing parts | **Yes** | Part number in the authenticated segment header; MAC-protected manifest |
| Client authentication | **Yes** | SigV4 with proxy-specific credentials, constant-time comparison |
| Tamper evidence of the audit log, once written | **Yes**, with limits | Hash chain and signed checkpoints, §5.8 |
| Rollback to an older genuine version of the same key | **Yes**, with limits | Only with `freshness.index` configured, and only for objects the instance has seen before, §5.1 |
| Confidentiality of names, sizes, timestamps | **No** | §4 |
| Authenticity of sizes reported in listings | **No** | Computed from unauthenticated upstream data, §5.4 |
| Availability | **No** | The provider can delete or refuse access |

---

## 4. What the storage provider still sees

- Bucket names and object keys in cleartext.
- The **exact** plaintext size. The format is length-deterministic, so plaintext size is
  computable from ciphertext size (`FORMAT.md` §7). This is not an oversight; it is the
  property that makes a streaming `Content-Length` and listing sizes possible without
  buffering or extra requests. Size padding is a deferred M6 option.
- `Content-Type`, `Cache-Control` and the client's own user metadata.
- Timestamps of uploads, downloads and deletions.
- Access patterns: which objects, which byte ranges, how often.
- The number of parts of a multipart object.
- The id of the KEK in use — not the KEK itself.
- The chunk size the object was written with (`bb-c`). This is a deployment-wide
  constant rather than a property of the data, and it is recorded so that
  `HeadObject` and listings can report plaintext sizes without reading objects.
  It is a hint only: any read that touches the body takes the chunk size from the
  authenticated segment header and rejects an object whose metadata disagrees.

What the provider does **not** see is object tags, because the gateway does not
accept them. `x-amz-tagging` on an upload and the tagging sub-resource's write
calls are refused with a message naming the reason: a tag is a key and a value
the provider would store in the clear, and the list above is meant to stay a
list of things that cannot be helped rather than one this gateway adds to
([ADR-012](adr/ADR-012-copy-semantics.md)). Refused, not ignored — a client that
sets a tag is told, instead of believing the object carries one.

Content *is* hidden. Metadata is not. For workloads where the object names themselves are
sensitive, this matters, and the option to change it now exists — with limits that have to be
read before it is switched on.

**Object names can be encrypted, and "encrypted" here does not mean "unguessable."**
`names.encrypt` stores each object under the deterministic per-segment encryption of
[ADR-015](adr/ADR-015-object-name-encryption.md), so the provider no longer sees the key a
client used. It is off by default and, at present, serves only the four single-object
operations; listing, multipart and copy are refused rather than served wrongly
([ADR-017](adr/ADR-017-listing-order-under-name-encryption.md)).

What it does *not* hide is the part that matters most, and it follows from the one
requirement the design could not give up — a point lookup must reach one object in one
request, with no index, which forces the mapping to be a pure function of the key:

- **Equality of full paths.** One plaintext key maps to one stored key, forever. An attacker
  who suspects an object is called `payroll/2026-q1.xlsx` can confirm the guess by watching
  whether a name they cause to be created collides. Deterministic encryption never hides
  equality, and equality is what confirms a guess.
- **Equality of sibling names.** Two objects called `report.pdf` in one directory are
  visibly the same name. Under different directories they are not, because the path so far
  is associated data of each segment.
- **Segment lengths**, since ciphertext length tracks plaintext length, and **tree shape** —
  depth, and how many children each directory has.

So this moves object names from "in the clear" to "confirmable by guessing", which is a real
improvement against a provider reading its own storage and close to none against an attacker
who already knows what they are looking for. A reader who takes it for more than that has
been misled, which is why it is written out here rather than left to the ADR.

**The audit log sees the same names, and hides them the same way.** When audit
logging is enabled, the bucket and key of every request are written to a local
file — encrypted with the deterministic per-segment construction of ADR-015, so
that the file can be shipped off the host without giving away what the encrypted
bucket does not. It inherits that construction's leakage exactly: determinism
does not hide equality, so someone holding the log can confirm a guessed name,
and repeated access to one object is visible as repeated access to *something*.
What the log does record in clear is the operator's own vocabulary — the
credential's configured name, the operation, the key id, the status, the byte
count — and, for a rejected request, the access key id that was attempted.

---

## 5. Residual risks

### 5.1 Rollback — mitigated when switched on, with limits

If the provider serves an older but genuine version of the same object — from its own
versioning, for instance — that version is cryptographically valid: the proxy produced it,
and it is bound to the same bucket and key. Nothing in the format distinguishes "current"
from "previous".

Detecting this requires remembering, per object, which write is the current one. Since
`freshness.index` exists, the gateway can ([ADR-018](adr/ADR-018-rollback-detection.md)).
It is **off by default**, and with it off this remains accepted risk exactly as before.

What is remembered is a tag over the object's segment salts, which §4.1 of `FORMAT.md`
already requires to be fresh per write and authenticates as associated data of every chunk.
A provider cannot forge one; it can only serve a whole genuine segment, which is the attack.
The check runs where ADR-014's salt comparison already runs — after the header is
authenticated, before any plaintext is released — and a mismatch is `RollbackDetected`
rather than an integrity failure, because nothing failed authentication. The bytes are
genuine. They are not current.

**The limits are part of the claim, not footnotes to it.**

- **The first read of any object is unchecked.** An index that has just been created, or
  lost, trusts what it is shown and records it. A rollback served at exactly that moment
  is recorded as the truth.
- **A tag carries no order.** It says *which* write, never *which is newer*. So where
  several instances write the same objects, a peer's legitimate write and a provider's
  rollback are the same observation, and a local index cannot separate them. Detection
  there needs a shared index, which this build does not ship.
- **A server-side copy leaves its destination unchecked until it is read once.** The
  destination's ciphertext comes from the source and its salts are never read, so the index
  is told to forget rather than to record.
- **`HEAD` is not checked**, because it reads no body and therefore no salt. It returns no
  plaintext either.
- **Memory is proportional to live objects**, about 112 MiB per million. That is an
  operational cost rather than a security limit, and it is why this is a switch.

What does *not* limit it: `blindbucket rotate` re-wraps metadata without moving ciphertext
(ADR-009), so the salts and therefore the tags are untouched and a rotation costs the index
nothing. That is why the tag covers salts rather than the wrapped data key.

The audit log of §5.8 has nothing to do with this, and is worth naming here because its
name invites the assumption that it does. That log records what the gateway
*served*; it is not consulted on a read, and it is not an authority on which
version of an object is current. The index above is a separate file with a
separate key and a separate lifetime, and ADR-018 explains why folding the two
together was rejected ([ADR-016](adr/ADR-016-audit-log.md)).

### 5.2 Retry substitution within a multipart upload — mitigated

Within one upload, an active provider could substitute part *n* with the bytes of an earlier
transmission attempt of the same part *n*. Both are valid segments produced by the proxy:
the part number is authenticated and equal, the sizes are equal, every chunk tag verifies.

**This is now detected.** The manifest records each part's segment salt, which FORMAT.md
§4.1 already required to be fresh per attempt, and a reader compares it against the
authenticated header before releasing any plaintext of that part
([ADR-014](adr/ADR-014-part-salts-in-the-manifest.md), FORMAT.md §10.6). The salt is
associated data of every chunk, so a provider cannot forge one — it can only substitute a
whole genuine segment, which is exactly what the comparison catches.

Two things about it are worth stating rather than leaving implied. The planned mitigation
was part ETags verified as a ciphertext MD5 on read; that was dropped because it hashes
every byte read and only detects *after* the part has been delivered, which is the
unsatisfactory pattern of §5.3. And objects written before the manifest recorded salts
(`BBM1`) keep the original risk: there is nothing in them to compare against. Copying or
rotating such an object rewrites its manifest and closes the gap, because a finished
object's part headers, unlike an open upload's, can be read.

### 5.3 Partially delivered plaintext

If a corrupted chunk is detected *after* the response status and `Content-Length` have been
sent, the proxy aborts the connection (`http.ErrAbortHandler`). By then the client has
already received authentic plaintext for the preceding chunks. Because `Content-Length` was
set, a correct client detects a short read and discards the result. A client that ignores
short reads keeps a truncated file — that is a client defect, but it is a real consequence
and is documented rather than hidden.

An open design question is whether small ranges should be fully decrypted
into a buffer before the status is sent, trading up to 1 MiB per stream for a clean error
response instead of a connection abort.

### 5.4 Unauthenticated listing sizes

`ListObjectsV2` sizes are converted from the sizes the provider reports. Authenticating them
would cost one request per object. Listings are therefore a hint, not a guarantee; the
authenticated size is established when the object is actually read.

### 5.5 Key material in memory

Go does not guarantee that a buffer can be reliably overwritten — the garbage collector may
copy it. Keys therefore cannot be scrubbed with confidence. Operational mitigations: disable
core dumps, disable or encrypt swap, restrict keyring file permissions to the service user.
The third is the only one this program can see, and every command that opens a keyring warns
when the keyring or a passphrase file is readable beyond its owner. It warns rather than
refuses: a file may be group-readable for a service account on purpose.

Unsealing the keyring with Vault Transit or AWS KMS does **not** change this, and it is
worth being explicit because it is the thing people assume it changes. The service
decrypts the root key at startup and the key is then in the process, exactly as a
passphrase-derived one is. Somebody who can read the gateway's memory gets it either way.

What the services do change is custody. The secret is not a passphrase on an operator's
machine or in a CI variable; access to it is logged by a system the gateway does not
control; and it can be withdrawn — revoking the Transit key locks every instance out at
its next restart, which no passphrase can do once the passphrase is out. Against an
attacker who has the running host, that is worth nothing. Against a leaked keyring file,
a departing operator, or an instance that must be retired, it is the difference between
rotating every KEK and revoking one grant ([ADR-013](adr/ADR-013-root-key-sources.md)).

### 5.6 DEK compromise

Rotation replaces the KEK, not the DEK. A compromised DEK exposes its object until that
object is re-encrypted. "Key rotation" in this project means KEK rotation, and the README
must not imply more.

A rotated-away KEK also keeps working until it is removed from the keyring: rotation
re-wraps the objects, it does not retire the key. `blindbucket keys remove` is what does,
and against a compromised KEK a rotation that is not followed by one has bought nothing.

### 5.7 Side channels on the proxy host

Timing and cache attacks against the proxy host are out of scope (they fall under A5).
AES-GCM uses hardware acceleration with constant-time behaviour on the platforms Go targets
(AES-NI, ARMv8 Crypto Extensions), and signature comparisons use `hmac.Equal`.

### 5.8 Audit log: the truncation window, and the key on the host

Audit logging (`audit.log` in the configuration,
[ADR-016](adr/ADR-016-audit-log.md)) makes a record that an intruder cannot
quietly edit: every entry hashes onto the one before it, and the chain is signed
with Ed25519 at intervals. Editing, reordering, removing or splicing anything
before the last signature changes a hash that signature covers. Verification
needs the public key and nothing else, so an auditor can be given the log without
being given anything that could write one.

Two limits, and both are the interesting part.

**Entries after the last checkpoint are chained but not signed.** Whoever holds
the file can delete them, and what remains verifies perfectly. The window is
bounded by `checkpoint_every` and `checkpoint_interval` and by nothing else.
Closing it means comparing against a checkpoint recorded somewhere the attacker
does not control — which is what `blindbucket audit verify --expect` takes and
why the verifier prints how far the signatures reach instead of only a verdict.
This is **accepted risk**, and narrowing it is an operator's trade against an
fsync per checkpoint.

**The signing key is on the gateway host.** Against A5 — anyone who controls the
proxy host — this proves nothing: they can write entries that verify, and §2
already says they have everything. What the log protects is itself *after it
leaves*: a copy, a backup, an archive, the file an intruder reaches an hour
later. That is a narrower claim than "audit log" usually implies, and it is the
one being made.

A third thing, smaller but real: a record is written once a request's outcome is
known, so a failure to write one cannot withhold the response it describes. With
`fail_closed` the gateway refuses the *next* request instead. Exactly one request
can therefore be served without a record, and the log shows where — the chain
stops.

---

## 6. Non-goals

- Hiding metadata (names, sizes, timestamps, access patterns).
- Protecting against a compromised proxy host or leaked KEK (A5).
- Emulating S3 beyond the documented operation set — IAM, bucket policies, object lock,
  lifecycle and replication remain the provider's concern.
- Compression or deduplication. Compressing before encrypting makes ciphertext length
  content-dependent and opens the CRIME/BREACH class of side channels; cross-object
  deduplication is incompatible with a random key per object.
- Availability.

---

## 7. Verification

Each guarantee in §3 is backed by tests that simulate an active provider (A2) and require an
error rather than plaintext. The catalogue covers chunk-level
tampering, header manipulation, object and metadata swapping, multipart reordering, token
forgery, checksum mismatch and authentication failures.

`blindbucket_integrity_failures_total` is exported as a metric. A sustained increase means
either a bug or an actively misbehaving provider, and should alert. So does
`blindbucket_audit_failures_total` above zero: it counts requests the audit log
could not record, and each one is a gap in it.

The audit log's own guarantees are tested the same adversarial way, in
`internal/audit/attack_test.go`: an entry edited, an entry edited and re-hashed,
an entry removed, two reordered, one duplicated, a genuine entry spliced in from
another chain, a checkpoint moved, a checkpoint re-signed with another key, a
public key swapped in the head, and a whole log forged end to end under an
attacker's key. Each must be rejected. One test asserts the opposite — that
truncation past the last checkpoint is *not* detected — so that §5.8's limit
cannot be quietly lost. `FuzzVerify` covers the verifier against arbitrary
input, which is what a log file is.
