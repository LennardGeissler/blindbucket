# Threat Model

**Status:** Current as of `v1.6.0`, which brings one new adversary and three things this
model now names. The new adversary is whoever holds a presigned upload URL: they can
write one key, bounded in size and time (§5.10). CORS answers a browser's preflight
without authentication (§5.10). Object tags are sealed in sidecars, of which the provider
sees whether there are any and roughly how large, and can drop or replay one of the same
version (§4, §5.11). The dashboard is on loopback and answers only to `localhost` (§5.9).
`v1.5.1` made one guarantee hold that was stated without holding: the bodies of
`DeleteObjects`, `CompleteMultipartUpload` and bucket requests were not checked against
the signature, so `require_signed_payload` did not cover them, and a signed request could
be served with another body
([GHSA-h6g6-fvvh-3r88](https://github.com/LennardGeissler/blindbucket/security/advisories/GHSA-h6g6-fvvh-3r88));
now every body the gateway acts on is. `v1.5.0` added three things this model has to name,
and no mechanism. The audit export
([ADR-033](adr/ADR-033-audit-export.md)) sends every entry to a SIEM, unsigned, with object
names encrypted as in the file: the receiver is a new party that sees which client did
what and when, and that cannot verify what it gets, so verification stays on the file. A
read may now set its own response headers
([ADR-032](adr/ADR-032-response-header-overrides.md)). On a presigned URL they are covered
by the signature, so the holder of a link cannot choose them; the signer can, which gives
a credential holder nothing it could not do by storing the object that way.
`encrypt-existing` ([ADR-034](adr/ADR-034-encrypting-existing-objects.md)) authenticates a
plaintext object as the provider serves it at the moment of the read, checked only
against the provider's own MD5: an active provider (A2) that altered it before the run
gets its version authenticated, the same first sighting §5.1 names for rollback
detection. `v1.4.0` changed no guarantee: `init` and `doctor` set a gateway up and check
it. `v1.3.0` changed one default and added one guarantee.
`UNSIGNED-PAYLOAD` is now accepted by default
([ADR-029](adr/ADR-029-unsigned-payloads-accepted-by-default.md)). For current AWS
clients that leaves A6's reach unchanged, because their uploads over HTTPS were
always unsigned aws-chunked bodies with a CRC trailer. It is new for clients that send
`UNSIGNED-PAYLOAD` over plaintext, `rclone` and `mc` among them.
`require_signed_payload` is the first setting under which A6 cannot alter a body
the gateway accepts, though it can still read it. `scrub` verifies with the read path's
own checks and adds no mechanism. `v1.2.0` changed no guarantee. With `names.encrypt`
off, a provider's `400` on a listing now reaches the client with the provider's own
code and message ([ADR-027](adr/ADR-027-plaintext-listing-provider-errors.md)), so
an active provider (A2) chooses that text -- as it already chooses what a listing
says. `inspect` reads bytes and holds no key, and the release's provenance
attestations concern how a release is built, which this model does not cover.
`v1.1.0` added no guarantee either. Its
`migrate-names` moves objects whose names the provider has already seen, and §4
says what that leaves behind; `reseal` changes what opens a keyring and not what
is in it, and §5.5 says what that does not undo; and the AWS credential chain
changes where the upstream and KMS credentials come from, not who may hold them
(§1, [ADR-024](adr/ADR-024-aws-credentials-without-the-sdk.md)). §4 also names, since
`v1.1.0`, every content header the provider sees, three of which it had left out since
`v0.1.0`. `v1.0.0` changed no guarantee in it: it makes
the existing ones a versioned promise ([ADR-021](adr/ADR-021-what-1.0-promises.md)),
and its one fix lets the root-key credentials be referenced from the environment
instead of written into the configuration file. `v0.6.0` added reporting and
measurement, not a mechanism. `v0.5.0` did not change one either:
its security-relevant change, rotation refusing a provider that ignores
conditional writes, protects client writes against a provider bug rather than
an adversary ([ADR-020](adr/ADR-020-conditional-writes-measured.md)). `v0.4.0` was the release
in which the risk table below stopped having a row that says **No** while
promising a mitigation. Rollback —
a provider serving an older but genuine version of an object — is detectable
since [ADR-018](adr/ADR-018-rollback-detection.md), and section 5.1 now spends
most of its length on the *limits* of that, because they are the part worth
reading: the first sighting of any object is trusted, and a tag says which write
and never which is newer.

Section 4 gained a paragraph in the other direction. A presigned URL
([ADR-019](adr/ADR-019-presigned-urls.md)) carries the object's plaintext key to
whoever holds the link, which is the one thing object-name encryption otherwise
keeps out of sight — a different adversary from the rest of that section, and
still a leak.

Every remaining **No** in the table is a boundary of the design rather than an
open item. Revised at every milestone that adds an attack surface.

Everything below is implemented and covered by the attack tests of section 7 --
the segment format's own guarantees (chunk integrity, ordering, truncation
detection, binding to bucket and key), the HTTP surface, client authentication,
and the multipart path including the manifest and the upload token. Where a
mitigation is deferred rather than present, the entry says so and names the
milestone.
**Last updated:** 2026-10-03

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
| A tenant's keys and the locks that seal them ([ADR-038](adr/ADR-038-tenants-and-crypto-shredding.md)) | the keyring, a section per tenant sealed under the tenant's own KMS key, Transit key or passphrase; proxy memory |
| Client credentials for the proxy | proxy configuration, as references to the environment; a configuration `blindbucket init` wrote has the values in `blindbucket.env` beside it, mode 0600 |
| Upstream credentials for the storage provider | proxy configuration, or resolved from the platform — IRSA, Pod Identity, the instance role ([ADR-024](adr/ADR-024-aws-credentials-without-the-sdk.md)); never disclosed to clients |

---

## 2. Actors

| ID | Actor | Capabilities | In scope |
|---|---|---|---|
| A1 | Storage provider, passive | Reads everything stored or transmitted to it | Yes |
| A2 | Storage provider, active | Modifies, truncates, reorders, swaps and deletes objects and metadata; replays old data; lies in listings and response headers | Yes, with the limits in §5 |
| A3 | Network attacker between proxy and provider | As A1/A2, on the wire | Yes — TLS reduces this to A1/A2 |
| A4 | Unauthorised client | Sends requests to the proxy without valid credentials, or with credentials scoped to other buckets | Yes |
| A5 | Attacker on the proxy host, or with access to the KEK or root key | Reads memory, configuration, keys | **No** |
| A6 | Network attacker between client and proxy | Reads and modifies plaintext requests | Only insofar as TLS or sidecar deployment covers it; `require_signed_payload` stops modified bodies, not reading ([ADR-029](adr/ADR-029-unsigned-payloads-accepted-by-default.md)) |

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
| A destroyed tenant's objects, names and audit names unreadable | **Yes**, with limits | Its keys exist only under its locks, and destroying each lock destroys them, §5.12 |
| Confidentiality of names, sizes, timestamps | **No** | §4 |
| Authenticity of sizes reported in listings | **No** | Computed from unauthenticated upstream data, §5.4 |
| Availability | **No** | The provider can delete or refuse access |

---

## 4. What the storage provider still sees

- Bucket names and object keys in cleartext.
- The **exact** plaintext size. The format is length-deterministic, so plaintext size is
  computable from ciphertext size (`FORMAT.md` §7). This is not an oversight; it is the
  property that makes a streaming `Content-Length` and listing sizes possible without
  buffering or extra requests. Size padding was listed as an M6 option and not built; format 1 has none.
- `Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`,
  `Content-Language` and the client's own user metadata, as the client sent them.
- Timestamps of uploads, downloads and deletions.
- Access patterns: which objects, which byte ranges, how often.
- The number of parts of a multipart object.
- Whether an object version has tags, and roughly how long its tag set is: the sidecar
  holding it ([ADR-037](adr/ADR-037-encrypted-object-tags.md)) is an object of its own,
  of a size that follows the tag set's. Not the tags themselves.
- The id of the KEK in use — not the KEK itself. With tenants, which buckets are whose is
  in the keyring's sealed directory, not at the provider, but a key id names its tenant if
  the operator's key ids do.
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
client used. It is off by default and covers every operation the gateway serves. A
listing is read whole and sorted before any of it is returned, so a prefix beyond
`names.max_listing_keys` is refused rather than answered in an order that can make a
client delete data ([ADR-017](adr/ADR-017-listing-order-under-name-encryption.md)).

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

**A name a client repeats elsewhere is in the clear there.** `names.encrypt` covers the key
and nothing else on the list at the top of this section. A `Content-Disposition` of
`attachment; filename="payroll-2026-q1.xlsx"`, or user metadata that carries the path,
is stored as the client sent it, next to the encrypted key it was meant to hide. Keeping
names out of those headers is the client's part.

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

**A bucket switched over keeps its old names until it is migrated.** Objects
written before `names.encrypt` was switched on stay under their keys in clear,
visible to the provider, until `blindbucket migrate-names` moves them
([ADR-022](adr/ADR-022-migrating-to-encrypted-names.md)). The migration deletes
each key in clear once its object is at the encrypted key, so the name stops
being *stored* — but on a bucket with versioning a delete only adds a marker, and
the earlier versions keep the name until a lifecycle rule or the operator
removes them. What the provider recorded elsewhere, in access logs or backups,
is beyond anything a gateway can reach. A key too long to encrypt is reported
and stays in clear.

**A presigned URL carries the object's name in clear, to whoever holds the URL.**
The signature covers the key the client named, so the plaintext key is in the link
([ADR-019](adr/ADR-019-presigned-urls.md)) — the one thing name encryption otherwise
keeps out of sight. The adversary is a different one from the rest of this section:
not the storage provider, but whoever the link reaches, which is at least the person
it was sent to and at most everyone who sees a browser history, a `Referer` header, a
chat preview or a CI log. A presigned URL is a bearer credential, and what it bears
includes the name. Deployments that encrypt names because the *names* are the secret
should weigh that before handing links out, and `server.presign.enabled: false`
refuses them outright.

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

`blindbucket reseal` moves a keyring to a service, or between services, or to a new
passphrase, and it changes the lock and not the keys: the KEKs inside are the same bytes
before and after ([ADR-023](adr/ADR-023-resealing-a-keyring.md)). Whoever holds the old
source *and* any copy of the old file — a backup, an earlier version of a Kubernetes
Secret, a laptop — therefore still has every key. Resealing is the right response to a
change of custody, and the first step, not the remedy, after a passphrase or root key may
have leaked: the remedy is a new KEK, `rotate` onto it, and `keys remove` for the old one.

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

### 5.9 The admin listener and the dashboard

The admin listener serves `/healthz`, `/readyz`, `/metrics` and, if switched on,
`/debug/pprof/`, over plain HTTP and without authentication. It defaults to loopback,
but the Helm chart binds it to every interface, because the kubelet and Prometheus have
to reach it. **Anyone who can reach the port reads the metrics**: request rates per
operation, error codes, the key IDs in the keyring metrics, and whether the audit log
has failed. None of it is key material or plaintext. All of it is reconnaissance, and
profiles, when on, are memory. The chart's NetworkPolicy narrows the port to the
scraper's namespaces (`networkPolicy.metricsFrom`), and is off by default, because it
needs a CNI that enforces it. Without it, every pod in the cluster can reach the port.
This is **accepted risk**.

**Loopback is not private to a browser.** A web page the operator opens can reach
`127.0.0.1` through DNS rebinding, so the operator's browser can read any loopback
listener on the same machine -- the admin listener included.

The dashboard ([ADR-035](adr/ADR-035-dashboard.md)) shows more than the metrics: what
seals the keyring and where, the audit log's chain and whether it verifies. So it gets
neither of those exposures. It is served on a listener of its own, which the
configuration allows only on loopback, and is reached from elsewhere through `kubectl
port-forward` or an SSH tunnel, whose authentication stands in front of it. It answers
only requests that name a loopback host, which turns a rebinding page away. It renders
no key material, credential or object name, writes nothing and runs no script. Its
audit verification runs on a schedule, never on a request, so it cannot be used to make
the gateway read its whole log on demand.

### 5.10 Presigned uploads

With `server.presign.uploads.max_size` set, a presigned URL can upload
([ADR-036](adr/ADR-036-presigned-uploads.md)). Its holder is by design a browser nobody
vouches for, and is a new adversary for the gateway: not the provider, not a client
with a credential, but whoever the URL reaches. **What the holder can do is write that
one key**, with a body of at most `max_size` bytes, as often as they like until the
URL expires, at most an hour by default. Each write is encrypted like any other, and the
audit log records it under the credential that signed the URL.

What the holder cannot do:
- **Change what the URL binds.** It binds the method, the key and the window, and
  whatever the backend signed: the exact length, a checksum, `If-None-Match: *`.
- **Add an `x-amz-*` header the URL did not sign.** Such a header is refused, as on
  S3, so the holder cannot store metadata the backend never agreed to.
- **Exceed the limit.** It is judged on `Content-Length` before the body is read, and a
  body without one, or an `aws-chunked` one, is refused.

What remains is **accepted risk**:
- **The body is unsigned**, protected by TLS between browser and gateway, and verified
  only if the backend bound a checksum.
- **An unconditional URL overwrites its key on every use.** In a versioned bucket every
  use leaves a version. A backend that wants one use signs `If-None-Match: *`, which
  holds where the provider enforces it, and on Garage v2.4.1 it does not.
- **Uploads cost bandwidth and provider storage**, bounded per request but not per URL.

**CORS** (`server.cors.allowed_origins`) adds the one path the gateway answers without
authentication besides the admin listener: the browser's `OPTIONS` preflight. It says
which methods and headers a listed origin may use, and nothing about buckets or objects;
any other origin gets `403`. Marking responses readable by a listed origin gives a page
on that origin what its requests already return, and nothing else: a request still needs
a signature, and no response allows credentials.

### 5.11 Object tags

A tag set is sealed in a sidecar beside its object version, under a key the object's
data key derives, with the bucket and key in the associated data
([ADR-037](adr/ADR-037-encrypted-object-tags.md)). An active provider (A2) cannot read a
tag, forge a tag set, or move one to another object or another version of the same
object: a sidecar that does not open is refused as any integrity failure is. Two things it
can do are **accepted risk**:
- **Drop a tag set**, by deleting its sidecar. The object then reads as having none.
- **Serve an earlier tag set of the same version**, one the client replaced since. Both
  were sealed for that version, and rollback detection (§5.1) does not cover sidecars.

Either looks like the client's own change.

### 5.12 Tenants and their destruction

A tenant ([ADR-038](adr/ADR-038-tenants-and-crypto-shredding.md)) is a set of buckets
with its own KEKs and name key, sealed in the keyring under a lock of its own: a KMS
key, a Vault Transit key or a passphrase. `blindbucket tenants destroy` takes a census
of the tenant's buckets and writes the keyring without the tenant's keys. Once every
instance serves that keyring and every lock the tenant ever had is destroyed at its
service, **no copy of the keyring opens its keys**, current or old, in a backup or in a
Secret's history. Every object the gateway wrote to its buckets is then unreadable, with
its sealed tags and manifests. So are its encrypted names, in the bucket and in the audit
log. That holds against the provider, against the operator, and against whoever holds
the deployment's root key. The order of the steps, and why the locks come last, is
model-checked (`spec/tla/Tenants.tla`).

It promises nothing beyond what the key services do, and what remains is **accepted
risk**:
- **Before the service has deleted the key.** AWS KMS waits 7 to 30 days and the deletion
  can be cancelled meanwhile. A Vault snapshot or storage backup from before still holds
  a Transit key.
- **A passphrase**, beyond everyone forgetting it, which nothing can check.
- **A tenant under the deployment's lock.** It has keys of its own, but any copy of the
  keyring opens them with the deployment's root key, so its destruction rests on every
  such copy being deleted. `tenants create` warns, and `doctor` and `tenants destroy`
  say so.
- **Objects not under the tenant's keys**, when `--force` overrides the census, which
  otherwise stops a destruction that would leave any. It counts every version a versioned
  bucket keeps: a version written under the default tenant's keys before the tenant was
  active survives its object being replaced, and `rotate` cannot move it, so it has to be
  deleted or expired first.
- **What the provider sees in clear** (§4): sizes, timestamps, access patterns, metadata
  as clients sent it, and, with `names.encrypt` off, the names.
- **Copies.** A client's copy into another tenant's bucket is that tenant's data.
  Plaintext that left the gateway, and the memory of a process that held the keys (A5),
  are beyond any key.
- **Audit entries about a bucket whose tenant an instance did not hold** record their
  names as digests under the audit secret. Those are not reversible, but whoever holds
  the audit secret can test a guessed name against them (FORMAT §14.5).

A destroyed tenant's buckets are refused, `403`, rather than falling back to the default
tenant. Otherwise the first write after a destruction would store new data under keys
nobody means to destroy.

---

## 6. Non-goals

- Hiding metadata (names, sizes, timestamps, access patterns).
- Protecting against a compromised proxy host or leaked KEK (A5).
- Isolating tenants from each other or from the operator. Tenants share one gateway, one
  deployment root key and one audit secret. A tenant is what can be destroyed, not a
  boundary of trust.
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

The same checks run without a client, too: `blindbucket scrub` reads every stored
object through `internal/verify`, the read path's own code rather than a copy of
it, and reports each one that fails ([ADR-028](adr/ADR-028-scrub.md)). That moves
detection from the read to a schedule; it adds no guarantee to §3, and like any
read without `freshness.index` it cannot tell an older genuine version from the
latest.

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
