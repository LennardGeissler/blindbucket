# Changelog

Notable changes per release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html) —
with the caveat that before `1.0.0` the wire format is the thing held stable, not
the Go API.

The **wire format** is versioned separately and independently: the segment format
is version `1` and is specified in [docs/FORMAT.md](docs/FORMAT.md). A change to
it would be a change to that number, announced here, and objects written under
version 1 would keep being readable.

## [Unreleased]

### Added

**Listings under name encryption are paginated, which finishes M6's name
encryption.** The provider orders by the encrypted key, so a prefix is read
whole, decrypted and sorted before any of it is served; pages are then cut out of
that. `names.max_listing_keys` bounds it (default 100 000, about 2.3 seconds to
the first page against a same-region provider) and
`names.max_concurrent_listings` bounds how many run at once, because the memory
is per listing in flight. A prefix past the bound is refused with an error naming
the limit.

**[ADR-017](docs/adr/ADR-017-listing-order-under-name-encryption.md) was wrong
about needing server state, and says so.** It expected a cache keyed by
continuation token, and called that the gateway's first server-side state against
[ADR-006](docs/adr/ADR-006-upload-token.md)'s deliberate statelessness. Building
it showed the state is not needed: S3's own pagination parameters already carry
the whole resume point. v1's `marker` and v2's `start-after` are plaintext keys,
and v2's `continuation-token` is opaque but minted here, so it carries the same
one. The resume state of an encrypted listing is a single string the client
holds, and any instance can answer any page with no prior knowledge.

**A cache remains, and never answers a first page.** That is a correctness rule,
not tuning, and it was learned the hard way: `aws s3 sync` lists its destination
*before* uploading, and the first build served that empty listing again
afterwards, so the next sync saw an empty prefix and uploaded everything twice.
S3 has been strongly read-after-write consistent since 2020 and clients lean on
it. A *continuation* is the opposite case — S3 makes no promise that keys written
mid-walk appear in it — so serving every page of one walk from its own snapshot
is what a client expects. Both halves have a test, each checked by putting the
bug back.

ADR-015 and ADR-017 are now **Accepted**: name encryption went from a primitive
nothing called to something every operation goes through.

**Object-name encryption now covers every operation the gateway serves.**
Multipart -- create, upload, complete, abort, list parts -- and both copy paths,
plus tagging and bulk delete. A 40 MiB file round-trips through the AWS CLI with
an identical SHA-256, and `aws s3 cp s3://a s3://b` copies it server-side.

The upload token stays sealed against the key the *client* named; every request
to the provider carries the key it *stores*. `openToken` hands both back
together, so no handler has to remember the second one -- and changing its
signature is what made the compiler point at the fifth caller nobody had thought
about.

A manifest is bound to the stored key and lives at the hash of it, deliberately
on the other side of that split from the object's data key. That pairing is what
keeps **`gc` free of the name key**: it reads a key out of a manifest and checks
that it hashes back to the directory it was found in, and both halves of that
check live in the provider's namespace. `gc` therefore needed no change at all.

The gate that refused unwired operations is now a whitelist with nothing left
outside it, so it only ever fires for an operation added later -- still the
direction it is safe to be wrong in.

**One bug found this way and worth recording.** `UploadPartCopy` -- what
`aws s3 cp s3://a s3://b` uses above the client's multipart threshold -- read the
source's byte ranges with the key the client named rather than the stored one,
and every part came back `NoSuchKey`. A sweep of the call sites missed it because
the variable there has a different name, and no test went through that path, so
it was found by copying a 40 MiB object with the real client. It now has a
regression test, checked by putting the bug back and watching the test fail.

**Fixed before it shipped: `blindbucket rotate` could not run against a bucket
with encrypted names.** A rotation finds its work by listing the *provider*, so
every key it sees is a stored one -- but the data key it re-wraps is bound to the
key the *client* names. Rotating therefore built its associated data from the
wrong name.

The outcome was a refusal rather than corruption, which is the fail-closed design
working: `objcopy` unwraps the old key before it writes anything, that unwrap
failed on the mismatched associated data, and nothing was written. But key
rotation -- a headline feature -- could not run at all with names on, and said so
with `unwrapping failed` and an encrypted key in the log.

The fix is structural rather than a patch at the call site. `objcopy.Source` and
`objcopy.Dest` each carried one `Key` doing two jobs: the object's **identity**,
which the wrapped data key and the manifest are bound to, and its **address**,
which is what the provider is told. Name encryption pulls those apart, so they
are now two fields, and `objcopy` refuses a request that sets only one rather
than letting a zero value decide. `rotate` maps each listed key back to its
identity, and maps a `--prefix` on the way out the same way a listing does.

One consequence worth recording: a manifest is bound to the **stored** key and
its path is the hash of the same, while the object's data key is bound to the
identity. That pairing is what keeps `gc` free of the name key -- it reads a key
out of a manifest and checks that it hashes back to the directory it was found
in, and both halves of that check live in the provider's namespace.

Found by reading `rotate` before wiring multipart, and reproduced end to end
against MinIO before it was fixed.

**The object name mapping is specified and independently implemented.**
[FORMAT.md section 15](docs/FORMAT.md) now describes the mapping from a client's
object key to the key the provider stores it under, normatively and in enough
detail to build from: the two derived keys, the per-segment SIV with the path so
far as its context, the mandatory canonical base32, the constant-time check on
the recomputed IV, and the length limit. Fifteen known-answer vectors in
`testdata/vectors/names_v1.json` fix the stored key for each case, on the same
footing as the segment vectors of section 13.

`ref/python/names_ref.py` implements it a second time, from that document. It
reproduces all fifteen vectors character for character, and
`ref/python/difftest_names.py` compares the two implementations on both
directions: 5 000 generated keys mapped identically, and 100 000 mutated stored
keys -- flipped characters, truncated segments, swapped segments, non-canonical
base32 -- accepted or rejected the same way by both, with zero disagreements.
Both run nightly.

This closes a promise [ADR-015](docs/adr/ADR-015-object-name-encryption.md) made
when the primitive shipped: "held to the same standard: known-answer vectors,
and coverage by the independent Python decoder, which is this project's existing
answer to 'did you get the composition right'." Until now the mapping had
neither, and it is the one construction this project *composes* rather than
calls -- the argument for building SIV from standard parts instead of taking an
untagged 2018 dependency only holds if the composition is checked by something
other than the code implementing it. Every test it had was a property test
running against itself.

Unlike the segment decoder, the Python side implements both directions. The
mapping is deterministic, so the specification fixes the stored key exactly and
reproducing it is the evidence -- which takes an encoder.

Also fixed: `internal/audit` documented its on-disk format as FORMAT.md section
15, which is the version history. It is section 14.

**Object-name encryption.** With `names.encrypt` on, the provider is addressed
with the encrypted form of an object's key and never sees the key the client
used. `PutObject`, `GetObject` (ranges included), `HeadObject`, `DeleteObject`
and listing are wired;
[ADR-015](docs/adr/ADR-015-object-name-encryption.md) has the construction.

**Off by default, and not a toggle.** An object lives at the encrypted form of
its key, so turning this on hides everything written before it and turning it
off hides everything written since. Moving an existing bucket across is a
rewrite of every object's key, and the documentation says so wherever the switch
appears rather than only in the ADR.

**Listings are served, in the client's order.** The provider orders by the
stored key, and encrypted names sort differently from plaintext ones -- an
unsorted listing is what makes `aws s3 sync --delete` delete objects that exist.
So a listing is decrypted and sorted before the client sees it. This is the
first of the three tiers in
[ADR-017](docs/adr/ADR-017-listing-order-under-name-encryption.md): it serves a
prefix whose whole result arrives in one page, which costs nothing beyond the
page the gateway was already holding and is the overwhelmingly common listing.
Delimiter grouping works because the `/` separators survive encryption, so the
provider's own grouping lines up with the plaintext one.

What this tier cannot sort, it **refuses** rather than answering in an order the
client cannot use: a prefix larger than one page, a pagination token, a prefix
that does not end on a `/` boundary, and any delimiter other than `/`. Each
names its own reason. The buffered tier that would lift the first two is the
open half of ADR-017, and it needs a cache over continuation tokens -- the
gateway's first server-side state.

Verified against the AWS CLI rather than asserted: two consecutive
`aws s3 sync --delete` runs against a gateway with names encrypted upload eleven
files and then do nothing, with zero deletes, while the provider holds eleven
keys in which no plaintext segment appears and whose order is not the plaintext
order.

**Everything else not yet wired is refused, not guessed at.** Multipart, copy
and tagging answer `NotImplemented` with a message naming the operation and why.
The gate is a whitelist, so an operation added to the router later is refused
until somebody decides what its key should be -- the direction it is safe to be
wrong in, because an operation addressing the provider with a plaintext key
while the rest used an encrypted one would write objects nothing could find
again.

**The envelope is unchanged.** The associated data binding an object's wrapped
data key stays over the key the *client* named, not the stored one, so whether
names are encrypted makes no difference to what is inside an object -- only to
where it lives. A provider that moves an object still produces something that
will not unwrap.

**`KeyTooLongError`** for a key S3 would accept whose encrypted form it would
not. Where that starts is a property of the client's naming convention: 624
bytes for a key that is one long segment, 128 for a path of four-character ones.

A gateway configured with `names.encrypt` against a keyring that has no name key
refuses to start and names the command that fixes it, rather than serving with
names in clear.

**An object-name key in the keyring**, the first piece of M6 that the gateway
will need rather than the crypto it already has. `internal/crypto/names` has
been able to map an object key to a stored key since it shipped, but the only
key it was ever handed belonged to the audit log. This is the one
[ADR-015](docs/adr/ADR-015-object-name-encryption.md) actually specifies: one per
keyring, generated at `keygen`, and -- the property the design turns on --
**untouched by rotation**. Rotation replaces the key that wraps data keys; a
rotation that also changed stored names would rename every object in the bucket
at once and leave none of them findable. Changing this key is a migration, not a
rotation, and `keygen` refuses to replace one for that reason.

It is deliberately not the audit log's name key, which `AuditKey` derives for
itself, so that an entry in a log and the name of an object are different opaque
strings for the same object. A test asserts they are not the same bytes, and
another asserts the wrapped key cannot be unwrapped as a KEK or as the audit
secret -- all three are 32 bytes, so domain separation in the associated data is
the only thing that tells them apart.

New keyrings get one. **`keygen --add-name-key`** gives an existing keyring one,
and `keys list` says so when a keyring has none. The keyring format stays at
version 1 and the field is optional, as [ADR-016](docs/adr/ADR-016-audit-log.md)
did for the audit key: a keyring written before this loads unchanged.

Inert until something encrypts names. The proxy does not yet -- that needs
[ADR-017](docs/adr/ADR-017-listing-order-under-name-encryption.md)'s listing
work first.

**A cryptographically verifiable audit log.** The gateway can keep a record of
what it served — which credential, which operation, which object, what came
back — in a form an intruder cannot quietly edit. Every entry carries the hash of
the entry before it, and the chain is signed with Ed25519 at intervals. Editing,
reordering, removing or splicing anything before the last signature changes a
hash that signature covers.

Verification needs the public key and nothing else. An auditor can be handed the
log without being handed anything that could write one, and
`blindbucket audit verify --public-key <key> audit.log` is the whole check.
`--keyring` additionally decrypts the object names, which is a separate
privilege and needs the keyring.

Object names in the log are **encrypted**, with the deterministic per-segment
construction of [ADR-015](docs/adr/ADR-015-object-name-encryption.md) — its first
shipped caller. A log can therefore leave the host without giving away what the
encrypted bucket does not.

Two limits are stated rather than glossed. Entries written after the last
checkpoint are chained but **not** signed: whoever holds the file can drop them,
and what remains verifies. `audit verify --expect <seq>:<hash>` compares against
a checkpoint recorded elsewhere and closes that gap; a test asserts the
undetectability so the limit cannot be lost. And this is **not** rollback
protection — `THREAT_MODEL` §5.1 is unchanged, and nothing here makes a read
consult the log.

Off unless `audit.log` names a path. With `fail_closed` (the default) a gateway
that can no longer record refuses the next request rather than serving on with a
record known to be incomplete. Design, alternatives and measured costs:
[ADR-016](docs/adr/ADR-016-audit-log.md); wire format:
[FORMAT §14](docs/FORMAT.md).

**`blindbucket audit`**, with `verify` and `pubkey`. **`keygen --add-audit-key`**
gives an existing keyring an audit key; new keyrings get one.

**`blindbucket_audit_failures_total` and `blindbucket_audit_broken`.** The
counter above zero means the log has a gap; the gauge means the gateway is
currently refusing traffic over it.

**`blindbucket keys`, with `list` and `remove`.** `list` shows what a keyring
holds and how old each key is — the input to a rotation decision, which until
now could only be had by reading the file. `remove` is the half of rotation that
was missing: `rotate` re-wraps objects under a new KEK and leaves the old one in
the keyring, where it goes on opening everything it ever wrapped, so a
compromised key stayed a working key. Removal needs `--force`, and is refused
for the active key and for the last one — nothing here can see the bucket, so
whether an object still references the key is the operator's to establish, with
a `--dry-run` rotation.

**`blindbucket_keyring_keys` and `blindbucket_keyring_key_created_timestamp_seconds`.**
Key age as a metric rather than as a thing to remember. A timestamp rather than
an age, so that `time() - max(...)` is the age at scrape time and no gauge has
to be refreshed to stay true.

**An AWS KMS encryption context** on the sealed root key: always
`blindbucket=root-key`, plus anything under `keys.awskms.encryption_context`. It
puts a distinguishable value in CloudTrail and lets a key policy narrow a grant
to this use of the key with a `kms:EncryptionContext:blindbucket` condition. The
context is recorded in the keyring's `root_key` object, because decrypting
requires exactly the context that encrypted. Keyrings sealed by earlier builds
carry none and open unchanged; a keyring sealed *with* one cannot be opened by a
build older than this, which is the only direction that breaks. Vault Transit
gets no context and [ADR-013](docs/adr/ADR-013-root-key-sources.md) says why.

**A warning for key files readable beyond their owner.** Every command that
opens a keyring now says so when the keyring or a passphrase file is not mode
`0600`. `THREAT_MODEL` §5.5 asked for this and left it to the reader.

### Fixed

**`keygen --add` asked for the passphrase twice on a terminal**, once to open
the keyring and once to write it back — and the second answer, which was not
confirmed, became the passphrase the keyring was re-sealed under. A typo there
sealed the keyring under something nobody knew, losing every object encrypted
under it. A command now resolves the passphrase once and remembers it for the
rest of the run. Deployments passing `--passphrase-file` or the environment
variable were never affected.

**A keyring that records no creation dates reported today's.** Loading stamped
each key with the time it was read, which made every key in a keyring written
before dates existed look fresh in `keys list` and in the new metric. Such a key
is now reported as unknown, which is what it is.

## [0.2.0] — 2026-09-12

### Added

**Server-side copy.** `CopyObject` and `UploadPartCopy`, the two operations
`v0.1.0` refused, which between them are what `aws s3 cp s3://a s3://b` and
`aws s3 mv` are made of. A copy does not move the object: the data key is
unwrapped under the source's identity and wrapped again under the
destination's — the wrap is bound to bucket and key (FORMAT §6.1) — while the
ciphertext is copied inside the provider. 1.2 KB crosses the wire for a 600 KB
object. Multipart objects keep their part boundaries and get their own manifest
under a new id, by the same rules rotation follows.

`UploadPartCopy` is the exception, and necessarily so: a part is a segment with
its own salt, so the destination's part shares no bytes with the source's
ciphertext even over identical plaintext. That range is decrypted and
re-encrypted on the way through, at `O(chunk size)` memory. It is the path the
AWS CLI takes above its 8 MiB threshold, and a 1 GiB copy through 128 part
copies returns an identical SHA-256.
[ADR-012](docs/adr/ADR-012-copy-semantics.md) records both decisions, including
why a shared data key is not nonce reuse in the sense that matters.

**`GetObjectTagging`**, forwarded to the provider, because the AWS CLI asks for
the source's tags before a server-side copy.

**Vault Transit and AWS KMS as root-key sources**, the last of M5. The keyring
can be sealed by a key service instead of a passphrase: the service decrypts the
root key at startup and never hands out the key that does it. It is asked once —
after that every KEK is in memory and no request pays a round trip, which is the
whole reason the key hierarchy of [ADR-002](docs/adr/ADR-002-key-hierarchy.md)
exists. The keyring file records which source sealed it, so a keyring from
another environment is named as such rather than failing as a decryption error.

The honest limit: the root key is in the gateway's memory afterwards, exactly as
a passphrase-derived one is. What the services buy is custody rather than
runtime secrecy — and revocation, which is verified rather than asserted:
deleting the Transit key stops the next start with `encryption key not found`.
Both clients are hand-written against the services' HTTP APIs, so Vault adds no
dependency and KMS reuses the SigV4 signer already there
([ADR-013](docs/adr/ADR-013-root-key-sources.md)).

**Part salts in the manifest**, closing the last residual risk that had a
planned mitigation (THREAT_MODEL §5.2). A client that retries a part leaves two
valid segments under one part number — same number, same size, every tag
verifying — and the manifest could not say which of them the object was
completed from, so a provider could serve either. It now records each part's
segment salt, which the format already required to be fresh per attempt, and a
reader checks it against the authenticated header *before* releasing any
plaintext of that part.

Getting the salt to the completion is the interesting half: a part of an open
upload cannot be read back, so the gateway cannot look. It travels with the
client instead, sealed into the part ETag that S3 has the client echo back —
the upload token's trick, one level down. Part ETags are therefore no longer
plain hex; the AWS CLI, boto3, `mc` and rclone were each measured accepting and
returning them unchanged ([ADR-014](docs/adr/ADR-014-part-salts-in-the-manifest.md)).

The manifest format moves to `BBM2`. `BBM1` manifests are still read, and
objects written under them keep the original risk — there is nothing in them to
compare against. Copying or rotating such an object rewrites its manifest and
closes the gap, because a finished object's headers can be read where an open
upload's cannot.

**The beginning of object name encryption** (M6): `internal/crypto/names` maps
object keys to the keys the provider sees, deterministically and per path
segment so that prefix listing keeps working. Not yet wired into the gateway —
the design, the primitive and its costs are settled in
[ADR-015](docs/adr/ADR-015-object-name-encryption.md), which is Proposed rather
than Accepted for that reason.

Two things the design work settled that were not obvious. A point lookup must
not need an index, which forces *every* segment to be deterministic, including
the leaf — so the more private option, a randomised leaf that hides sibling
names, is unavailable rather than merely unchosen. And the usual Go AES-SIV
library has no release tags, has not moved since 2018 and depends on a module
from 2016, so the SIV construction is composed from standard library primitives
instead, exactly as the segment format composes STREAM from AES-GCM.

The round-trip fuzz target earned its place immediately: base32 leaves four
spare bits in the final character of a 17-byte segment, so sixteen spellings
decoded to the same bytes — sixteen stored keys naming one object. Canonical
encoding is now enforced and the counterexample is a seed.

### Changed

**Object tags are refused rather than ignored.** `PutObjectTagging`,
`DeleteObjectTagging` and `x-amz-tagging` on an upload answer `NotImplemented`
and say why: the provider would store them in plaintext. Previously
`x-amz-tagging` was accepted and silently dropped, which left a client believing
its object carried tags it did not.

**`internal/objcopy`** now holds the republish logic that `internal/rotate` had
its own copy of. The manifest lifecycle rules R1-R3 are an ordering of three
writes that `spec/tla/Multipart.tla` checks; two implementations would
eventually be two orderings, and only one of them was the one the model checked.

### Known limitations

- **Object names are not encrypted**, and object sizes are visible to the
  provider. The primitive now exists (`internal/crypto/names`) but is not wired
  into the gateway: encrypted names sort differently from plaintext ones, and an
  unsorted listing was measured making `aws s3 sync --delete` delete seven of
  eight objects that exist locally. A gateway whose argument is safety does not
  ship that behind a note, so
  [ADR-015](docs/adr/ADR-015-object-name-encryption.md) stays Proposed until the
  ordering question has an answer.
- **No `blindbucket reseal`.** Moving a keyring between a passphrase, Vault and
  KMS means creating a new keyring and rotating objects onto it
  ([ADR-013](docs/adr/ADR-013-root-key-sources.md)).
- **The root key is in the gateway's memory** after unsealing, whichever source
  sealed it. What Vault and KMS buy is custody and revocation, not runtime
  secrecy — stated plainly because the opposite is easy to assume.
- **The AWS credential chain is not used**; KMS credentials are configured
  explicitly ([ADR-013](docs/adr/ADR-013-root-key-sources.md)).
- **Presigned URLs** answer an error rather than being verified and reissued.
- **Object tags** are refused rather than stored, because the provider would
  hold them in plaintext ([ADR-012](docs/adr/ADR-012-copy-semantics.md)).
- **`ListMultipartUploads`** is refused, and will stay that way: the upload ids
  this gateway issues cannot be reconstructed from the provider's listing.
  `ListParts` works.
- **rclone and `mc`** need `allow_unsigned_payload` on the proxy; `mc` needs it
  only for multipart. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
- **One benchmark cell** — 10 MiB uploads at 64 concurrent clients — runs at 18 %
  of the direct path. The gateway's share is measured at 0.13 ms per request out
  of ten seconds, so the time is the provider's; why it behaves that way under
  this access pattern is not established.

## [0.1.0] — 2026-09-12

The first release. A transparent S3 encryption gateway: point a client at it
instead of the storage provider, and the provider only ever sees ciphertext.

### Added

**The format and the crypto core.** AES-256-GCM in a STREAM-style segment format
with 64 KiB chunks and an authenticated header, one data key per object, and a
three-level key hierarchy with an external root key. Tampering, truncation,
reordering and part substitution are all detected. Specified in
[docs/FORMAT.md](docs/FORMAT.md) before it was implemented, and pinned by ten
known-answer vectors that are a normative part of the specification.

**The gateway.** `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`,
`ListObjects`/`V2`, `DeleteObjects` and the bucket operations, with SigV4
verification in both directions, `aws-chunked` bodies with and without trailers,
checksum verification, range requests over ciphertext, and virtual-hosted-style
addressing. Sizes reported to clients are plaintext sizes.

**Multipart uploads.** Parts arrive in parallel, in any order, on any instance,
and are retried freely. The gateway keeps no state for any of it: the upload id a
client receives is a sealed token carrying the data key and the manifest id
([ADR-006](docs/adr/ADR-006-upload-token.md)). A signed manifest binds the parts
into one object ([ADR-007](docs/adr/ADR-007-manifest-sidecar.md)), and
`blindbucket gc` collects the orphans that ordinary operation leaves behind.

**Key rotation.** `blindbucket rotate` re-wraps data keys under a new KEK without
moving ciphertext: a thousand 64 KiB objects rotate in about 1.5 seconds while
1.4 MiB crosses the wire, against 62.5 MiB of payload. Writes are conditional, so
a client write that lands mid-rotation wins ([ADR-009](docs/adr/ADR-009-rotation-by-copy.md)).

**Operations.** Metrics, `/healthz`, `/readyz` and optional pprof on a separate
admin listener that defaults to loopback. Graceful shutdown. A distroless,
nonroot image and a Kubernetes sidecar example in [deploy/](deploy/).

Transfers have no fixed time limit and no unbounded one either: there is no
global `WriteTimeout`, because it would cut off a large download regardless of
progress, and instead the connection's deadlines are renewed as bytes move. A
5 TiB download may take hours; a connection that has moved nothing for a minute
is closed.

### Verified

**A formal model.** The first version of the design contained two race conditions in the
manifest lifecycle, both ending in an unreadable object. The rules that replace
them are checked in TLA+ before the code implemented them: 38.5 million states,
no counterexample, and four configurations that are *required* to produce one.
Each counterexample is an integration test. The model found a third problem
nobody was looking for — the order of two read-only steps in `gc` is
load-bearing ([ADR-010](docs/adr/ADR-010-manifest-lifecycle-under-concurrency.md)).

**An independent decoder.** [ref/python/](ref/python/) is a second decoder written
from the format specification, agreeing with the Go one on every vector and on
100 000 mutated inputs. Writing it found one ambiguity in the specification,
which is now fixed.

**Measurements, not claims.** 10 MiB objects move at 92–97 % of what the provider
manages without the gateway in the way; 1 KiB objects cost about half a
millisecond per request. 10 GiB streams through at 82 MiB peak resident. Scripts,
figures and the methodology are in [bench/](bench/).

### Known limitations

- **Key providers:** the file-backed keyring only. The `KeyProvider` interface is
  what AWS KMS and Vault implementations will slot into; neither exists yet.
- **`CopyObject`** is refused. The copy machinery is in the upstream client
  because rotation needs it, but the S3 operation is not wired up.
- **`ListMultipartUploads`** is refused, and will stay that way: the upload ids
  this gateway issues cannot be reconstructed from the provider's listing.
- **`UploadPartCopy`** is refused.
- **Object names are not encrypted**, and object sizes are visible to the
  provider. Both are recorded in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) as
  accepted, with the M6 options that would change them.
- **rclone and `mc`** need `allow_unsigned_payload` on the proxy; `mc` needs it
  only for multipart. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
- **One benchmark cell** — 10 MiB uploads at 64 concurrent clients — runs at 18 %
  of the direct path. The gateway's share is measured at 0.13 ms per request out
  of ten seconds, so the time is the provider's; why it behaves that way under
  this access pattern is not established.

[Unreleased]: https://github.com/LennardGeissler/blindbucket/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LennardGeissler/blindbucket/releases/tag/v0.1.0
