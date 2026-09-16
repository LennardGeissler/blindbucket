# blindbucket

**A transparent S3 encryption gateway, written in Go.**
Clients speak ordinary S3. The storage provider only ever sees ciphertext — never plaintext, never keys.

[![CI](https://github.com/LennardGeissler/blindbucket/actions/workflows/ci.yml/badge.svg)](https://github.com/LennardGeissler/blindbucket/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/LennardGeissler/blindbucket)](https://goreportcard.com/report/github.com/LennardGeissler/blindbucket)
[![Release](https://img.shields.io/github/v/release/LennardGeissler/blindbucket?label=release)](https://github.com/LennardGeissler/blindbucket/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

<p align="center">
  <img src="demo/demo.gif" width="880"
       alt="A 1 GiB file uploaded through the gateway with the AWS CLI. mc, talking to MinIO directly, then shows a BLBK header followed by ciphertext at the same offset that reads as text on disk, and the data key wrapped in the object metadata. The download through the gateway returns an identical SHA-256. After one flipped bit in the stored ciphertext, the download fails with IntegrityCheckFailed instead of returning data.">
</p>

<p align="center"><sub>
  A gigabyte through the gateway, what the provider is left holding, and what it gets for
  changing one bit of it. Every command is real — the scripts are in <a href="demo/">demo/</a>,
  as <code>make demo</code>.
</sub></p>

> **Status: `v0.3.0` — usable.** Standard S3 clients round-trip through the
> gateway, multipart included: AWS CLI, boto3, `mc` and rclone all work, and a
> 5 GiB `aws s3 cp` across two instances comes back with an identical SHA-256.
> Key rotation, server-side copy, metrics and health endpoints are in, and the
> keyring can be unsealed by Vault Transit or AWS KMS instead of a passphrase.
> This release adds a signed [audit log](#the-audit-log), `blindbucket keys`, and
> **object-name encryption** — off by default, and worth reading
> [what it does and does not hide](docs/THREAT_MODEL.md) before switching on. See
> [Roadmap](#roadmap), [CHANGELOG.md](CHANGELOG.md) and
> [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

---

## What it is

blindbucket is a reverse proxy that speaks the S3 API. It sits between any S3 client — AWS
CLI, boto3, rclone, `mc`, your own backend — and any S3-compatible store (AWS S3,
Cloudflare R2, MinIO, Backblaze B2). Uploads are encrypted in the stream, downloads are
decrypted in the stream. For the client, only the endpoint changes:

```
aws s3 cp big.tar.zst s3://backups/ --endpoint-url http://localhost:9000
```

```mermaid
flowchart LR
    subgraph T[Your trust boundary]
        C[Client<br/>AWS CLI · boto3 · rclone · mc] -->|S3 API · SigV4<br/>plaintext| P[blindbucket]
        P <--> K[(Keyring<br/>root key · KEKs)]
    end
    P -->|S3 API · SigV4<br/>ciphertext only| S[(S3 · R2 · MinIO · B2)]
```

The boundary drawn around those three is the whole claim: the keyring holds the
key-encryption keys, each object carries its own data key wrapped under one of them, and
the root key that opens the keyring comes from outside the process. None of it ever
crosses the arrow leaving the box.

<details>
<summary>What happens inside a <code>PutObject</code></summary>

The upload is a single pass with no spooling, which constrains the order of
everything else: the body has to be signed, encrypted and forwarded while it is still
arriving, and the client's checksum only verifies once the last byte has been seen. So
the last chunk is held back until it does — the one place where the gateway buffers on
purpose, and the reason a rejected upload leaves nothing readable upstream
([ADR-005](docs/adr/ADR-005-checksums.md)).

```mermaid
sequenceDiagram
    participant C as Client
    participant P as blindbucket
    participant S as Provider
    C->>P: PUT /bucket/key (SigV4, plaintext)
    P->>P: verify signature, generate and wrap a data key
    P->>S: PUT (re-signed, computed Content-Length, wrapped key in metadata)
    loop per chunk
        C-->>P: plaintext
        P-->>S: ciphertext
    end
    P->>P: verify the client's checksum
    P-->>S: last chunk, only once the checksum holds
    S->>P: 200 OK, ETag
    P->>C: 200 OK, ETag, verified checksum
```

</details>

The interesting part is not "AES around S3". It is what breaks when you try: authenticated
encryption for objects up to 5 TiB at constant memory, range requests over ciphertext,
parallel multipart uploads across several stateless instances, SigV4 in both directions, and
the checksum machinery of modern SDKs. Solving those cleanly is the substance of this
project.

| Property | How |
|---|---|
| Confidentiality | AES-256-GCM, a fresh data key per object |
| Integrity | Authenticated per chunk; tampering, truncation, reordering and swapping are detected |
| Constant memory | `O(chunk size)` per active stream, independent of object size |
| Statelessness | No local state; multipart state travels in an encrypted token |
| Drop-in compatibility | Standard clients unchanged, only `--endpoint-url` |
| Key rotation | KEK rotation by server-side copy; 1000 objects move 1.4 MiB, not 62.5 MiB, and `keys remove` retires the old key afterwards |

## Why not just use…

| Approach | Why it is not enough |
|---|---|
| SSE-S3 / SSE-KMS | The provider holds the keys and sees plaintext |
| SSE-C | Key and plaintext go to the provider on every request |
| AWS S3 Encryption Client | Must be built into every application; language-bound; no CLI support |
| rclone crypt | Built for single-user sync, not a stateless multi-instance gateway |

A gateway centralises encryption at one point inside your own trust boundary. Applications
stay unchanged, and the security level does not depend on every team configuring a library
correctly.

## Security posture

The trust boundary is the proxy. Between client and proxy, data is plaintext — so the proxy
must run in the same trust domain as its clients (sidecar, or behind TLS on an internal
network). Anyone who controls the proxy host or the KEK has everything.

Metadata is **not** hidden: object names, exact sizes, timestamps and access patterns remain
visible to the provider. Object names are the one item on that list being worked on —
`names.encrypt` hides them, but it is off by default, serves only single-object operations
so far, and "encrypted" there means *confirmable by guessing* rather than unguessable. The
limits are written out in [THREAT_MODEL.md](docs/THREAT_MODEL.md) section 4, and they are
the point rather than a footnote. Rollback to an older genuine version of an object is not
currently detectable — and the [audit log](#the-audit-log), despite the name, does not
change that.

These are stated up front on purpose. The full analysis, including every residual risk, is
in **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

## Install

```sh
# Container: distroless, nonroot, no shell, 21 MB.
docker pull ghcr.io/lennardgeissler/blindbucket:0.3.0

# Or a binary, with checksums and an SBOM alongside it:
#   https://github.com/LennardGeissler/blindbucket/releases

# Or from source:
go install github.com/LennardGeissler/blindbucket/cmd/blindbucket@latest
```

[deploy/kubernetes-sidecar.yaml](deploy/kubernetes-sidecar.yaml) is the sidecar
deployment worked out: one gateway per pod, listening on loopback, so the
plaintext hop never crosses a network interface.

## Try it today

```sh
docker compose up -d                         # MinIO on :9002, as a stand-in provider
make build

export BLINDBUCKET_PASSPHRASE='...'          # or --passphrase-file, or you are prompted
./bin/blindbucket keygen --out keyring.json --kid 2026-09

cp blindbucket.example.yaml blindbucket.yaml
export UPSTREAM_ACCESS_KEY_ID=minioadmin UPSTREAM_SECRET_ACCESS_KEY=minioadmin
./bin/blindbucket serve --config blindbucket.yaml
```

Then point any S3 client at it. Nothing about the client changes except the
endpoint:

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
aws s3 cp big.tar.zst s3://blindbucket-dev/
aws s3 ls s3://blindbucket-dev/
aws s3 sync ./backups s3://blindbucket-dev/backups/
```

`HEAD` reports the plaintext size, while the provider is holding something else
entirely:

```
$ curl -sI http://127.0.0.1:9000/blindbucket-dev/big.tar.zst | grep -i content-length
Content-Length: 3000000

$ mc stat local/blindbucket-dev/big.tar.zst
Size: 3000768                                # 32 + 3000000 + 16 x 46, exactly
X-Amz-Meta-Bb-Kid: 2026-09
X-Amz-Meta-Bb-Dek: SV7GTp0qCaXps-fpNUvKpsAOltVyKIHHscz6Dpmx14_i...

$ mc cat local/blindbucket-dev/big.tar.zst | head -c 16 | xxd
00000000: 424c 424b 0110 0000 0000 0000 ecd4 7291  BLBK..........r.
```

Change one bit of the stored object and the download stops at that chunk rather
than handing over a plausible-looking file.

Anything over 8 MiB goes through multipart, which every S3 client does on its own.
Each part is its own segment with its own salt, and a signed manifest binds them
into one object so that a provider cannot serve a short one:

```sh
aws s3 cp 5GiB.bin s3://blindbucket-dev/     # 640 parts, in parallel
aws s3 ls s3://blindbucket-dev/5GiB.bin      # 5368709120 — the plaintext size
```

The gateway keeps no state for any of it: the upload id a client gets back is a
sealed token carrying the data key and the manifest id, so parts can be spread
across instances and an instance can restart mid-upload. Orphaned manifests — from
a crashed upload, or from a plain PUT over a multipart object — are cleaned up out
of band:

```sh
./bin/blindbucket gc --config blindbucket.yaml --dry-run s3://blindbucket-dev
```

Retiring a key-encryption key does not mean re-encrypting anything. Each object
keeps its data key; only the key that wraps it changes, so the ciphertext never
leaves the provider:

```sh
./bin/blindbucket keys list --keyring keyring.json                        # what is in there, and how old
./bin/blindbucket keygen --out keyring.json --kid 2026-10 --add          # add the new KEK
./bin/blindbucket rotate --config blindbucket.yaml --to-kid 2026-10 s3://blindbucket-dev
./bin/blindbucket keys remove --keyring keyring.json --force 2026-09     # retire the old one
```

A thousand 64 KiB objects rotate in about a second and a half, moving 1.4 MiB
over the wire for 62.5 MiB of payload — and that per-object cost does not grow
with object size. Clients may keep writing throughout: the rotation's final write
is conditional on the ETag it started from, so a client write that lands in
between wins and the object is skipped until the next run.

The last step is the one that actually retires the key. Rotation moves objects
onto the new KEK but leaves the old one in the keyring, where it goes on opening
everything it ever wrapped — so a compromised key is still a working key until
it is removed. `keys remove` needs `--force` because nothing in the keyring can
see the bucket: run the rotation with `--dry-run` first and confirm it reports
nothing left to move.

### Without a server

The crypto core is also usable on its own, which is the point of having shipped it
first: the format can be reviewed, fuzzed and measured before any HTTP is involved.

```sh
./bin/blindbucket encrypt --keyring keyring.json -i big.tar.zst -o big.tar.zst.bb
./bin/blindbucket decrypt --keyring keyring.json -i big.tar.zst.bb -o restored.tar.zst
```

## Numbers

Measured on an Apple M4 (10 cores, 16 GiB) with Go 1.27.1, against MinIO in a
local VM — client, gateway and provider all on the one laptop, competing for the
same cores and the same disk. Absolute figures would be higher on real hardware;
the comparisons are what the setup is built to measure. Reproduce with
`make bench` and [bench/warp.sh](bench/warp.sh); the scripts and the caveats are
in [bench/](bench/).

| Measurement | Result |
|---|---|
| Encrypt, 64 KiB chunks | 7.2 GB/s |
| Decrypt, 64 KiB chunks | 7.0 GB/s |
| Allocations per chunk, steady state | **0** |
| Allocations per 8 MiB stream | 22 encrypting, 26 decrypting — constant, not per chunk |
| 10 GiB encrypt + decrypt | identical SHA-256, **0.5 MiB peak Go heap** |
| 5 GiB through the gateway, one stream | identical SHA-256, **12 MiB resident** while streaming |
| 5 GiB multipart, 640 parts, two instances | identical SHA-256, **56 MiB peak resident** per instance |
| 10 GiB through the gateway, 10 parts in flight | identical SHA-256, **82 MiB peak resident**, 23 MiB idle |
| 10 MiB objects through the gateway vs direct | 92–97 % of the provider's own throughput |
| 1 KiB objects through the gateway vs direct | 70 % at one client, 89–92 % at 64 — about +0.5 ms per request |

## Clients

Measured by pointing each client at the gateway and running it, not by reading a
specification. Full detail and the exact commands are in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

| Client | Status | Needs |
|---|---|---|
| AWS CLI v2 | works — `cp`, `ls`, `rm`, `sync`, ranges, multipart | nothing |
| boto3 | works — including paginators, delimiters and `upload_file` | nothing |
| MinIO `mc` | works — `cp`, `ls`, `mirror`, `cat` | nothing |
| rclone | works | `--ignore-checksum`, and `allow_unsigned_payload` on the proxy |

One call is deliberately not implemented: `ListMultipartUploads` returns 501. The
upload ids this gateway issues are sealed tokens carrying the data key and the
manifest id, and neither can be recovered from the provider's own listing — so the
honest answer is a refusal rather than a list of ids no client could use.

Two of those needed a fix that only a real client could have found: `mc` sends an
aws-chunked body with no trailer section at all, and rclone attaches an `?x-id=`
parameter that the router was refusing as an unknown sub-resource. boto3 found a
third — user metadata was arriving with Go's canonical header casing, so
`response["Metadata"]["origin"]` came back as `"Origin"` and every lookup missed.

The allocation figures are the interesting ones. They do not change with the
number of chunks, which is the whole of goal G3: memory is a function of how many
streams are in flight, never of how large they are.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/figures/memory-dark.svg">
  <img alt="Gateway resident set while 10 GiB streams through it: about 22 MiB idle, peaking at 82 MiB during the upload and settling back to 23 MiB during the download" src="bench/figures/memory-light.svg">
</picture>

Read that figure with two caveats. The upload is `aws s3 cp`, which splits 10 GiB
into 1280 parts and keeps ten in flight, so the peak covers ten concurrent
streams and not one. And on macOS the resident set does not fall when Go releases
pages, which makes every number on that curve an upper bound — the download half
is flat at 23 MiB because it never had to rise, not because the upload's memory
was reclaimed. The portable per-stream evidence is the Go-heap measurement in the
table above, which watches the heap rather than asking the operating system.

AES-GCM was expected to run well ahead of any network the proxy sits behind, so
the bottleneck should be the upstream and not the cipher. `warp` now says so
rather than the expectation standing on its own: against MinIO on the same
machine, 10 MiB objects move at 92–97 % of what the provider manages without the
gateway in the way.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/figures/throughput-dark.svg">
  <img alt="Throughput comparison across object sizes and concurrency: the gateway tracks the provider closely except for 10 MiB PUTs at 64 concurrent clients" src="bench/figures/throughput-light.svg">
</picture>

Small objects are where a proxy costs something, and it costs about half a
millisecond per request: 1 KiB uploads run at 70 % of direct with a single
client, rising to 89 % at 64 as that fixed cost amortises across concurrency. At
64 clients the p99 is identical to the provider's own, because by then the tail
belongs to the provider rather than to the gateway.

**One cell does not fit that picture**, and it is left standing rather than
dropped: 10 MiB PUTs at 64 concurrent clients run at 18 % of direct. It
reproduces across all three repetitions and is specific to PUT — GET at the same
load is at 95 %.

The gateway is not what is slow, and that is now measured rather than guessed. A
goroutine dump during the run shows every request handler parked waiting for the
provider to answer, none of them on encryption or on a lock. The metrics put a
number on it: across 184 uploads, total request time exceeded time spent waiting
for the provider by 0.024 seconds — **0.13 ms per request**, against a mean of ten
seconds each. Why the provider is slower under this particular access pattern is
still open; the obvious candidate has now failed to reproduce twice.
[bench/figures/results.md](bench/figures/results.md) has the numbers and what
would settle it.

One honest asterisk: the CLI's peak resident memory is about 70 MiB, essentially
all of it the 64 MiB Argon2id arena used once to unlock the keyring. That is a
deliberate trade — memory hardness is the point of Argon2id — and it is why the
constant-memory claim is measured on the Go heap rather than inferred from RSS.
[ADR-002](docs/adr/ADR-002-key-hierarchy.md) records the reasoning.

## Running it

Metrics, health and profiles sit on their own address, away from the S3 port:

```yaml
admin:
  listen: "127.0.0.1:9100"
  pprof: false          # goroutine stacks and heap contents; on only when looking
```

```sh
curl -s localhost:9100/healthz     # the process is up
curl -s localhost:9100/readyz      # the keyring is loaded and the provider answers
curl -s localhost:9100/metrics     # Prometheus
```

`/healthz` deliberately does not touch the provider: a restart loop caused by an
upstream outage is worse than the outage. `/readyz` does, and says which half
failed.

The metric worth an alert is `blindbucket_integrity_failures_total{kind}`. It
counts stored data that failed authentication, which means either a bug here or a
provider modifying objects — and neither should be discovered by a user opening a
file. `blindbucket_audit_failures_total` above zero is the second: it counts
requests the audit log could not record, and each one is a gap in it. The rest
cover requests, upstream latency, bytes by direction and streams in flight;
`blindbucket_active_streams` is the one that should track memory, since memory is
a function of streams in flight and not of object size.
`blindbucket_keyring_key_created_timestamp_seconds` is the input to a rotation
decision — `time() - max(...)` over it is the age of the oldest key still in the
keyring, which is the number a rotation policy is actually written against.

## The audit log

The gateway is the one place where plaintext and identity meet: it knows which
credential asked for which object and what came back, and it is the only
component that does. It can keep that record in a form an intruder cannot quietly
edit.

```yaml
audit:
  log: /var/lib/blindbucket/audit.log
```

Every entry carries the hash of the entry before it, and the chain is signed with
Ed25519 at intervals. Editing, reordering, removing or splicing anything before
the last signature changes a hash that signature covers.

**Verification needs the public key and nothing else** — not the keyring, not a
passphrase, nothing that could also write a log. That is the reason for a
signature rather than a MAC: an auditor can be given the log without being given
the ability to forge one.

```sh
blindbucket audit pubkey --keyring keyring.json      # record this elsewhere, once
blindbucket audit verify --public-key <key> audit.log
```

```
audit.log: chain a004c7464dc442a0, 4 entries, 2026-09-13T11:52:13Z to 2026-09-13T11:52:13Z
  last checkpoint: 4:5932f0b3b93ce8114117efc6f2ccfde2e5729d67c00930617fc18381afd9c811

chain and signatures verified
```

Object names in the log are **encrypted**, so a log can be shipped off the host
without giving away what the encrypted bucket does not. Reading them back is a
separate privilege: `--keyring` decrypts, `--public-key` does not and does not
need to.

```
$ blindbucket audit verify --keyring keyring.json --print audit.log
     1  2026-09-13T11:52:13.284181Z  PutObject     200 backup-job   backups/2026/09/db.sql.zst  1073741824 bytes
     2  2026-09-13T11:52:13.284218Z  GetObject     200 restore-job  backups/2026/09/db.sql.zst  1073741824 bytes
     3  2026-09-13T11:52:13.284224Z  GetObject     403 AKIANOTOURS (rejected) backups/2026/09/db.sql.zst  [SignatureDoesNotMatch]
     4  2026-09-13T11:52:13.284233Z  DeleteObject  204 backup-job   backups/2026/08/db.sql.zst
```

**Two things it does not do**, stated here rather than in a footnote.

Entries written after the last checkpoint are chained but *not* signed. Whoever
holds the file can delete them and what remains verifies perfectly — so the
verifier reports how far the signatures reach, and `--expect <seq>:<hash>`
compares against a checkpoint recorded somewhere the attacker does not control.
A test asserts that this truncation is undetectable, so the limit cannot be
quietly lost.

And it is **not rollback protection**. It records what the gateway served; no
read consults it, and residual risk §5.1 is exactly as open as it was. Turning
this log into a version index is a different feature with a different cost, and
[ADR-002](docs/adr/ADR-002-key-hierarchy.md) has the argument against.

The design, the rejected alternatives — a Merkle tree, an HMAC, signing every
entry, shipping the log upstream — and the measured costs are in
[ADR-016](docs/adr/ADR-016-audit-log.md). An append is 3.6 µs against the 0.13 ms
the gateway already costs per request.

## Documentation

| Document | What it is |
|---|---|
| [docs/FORMAT.md](docs/FORMAT.md) | Normative wire format. An independent implementation should be able to interoperate from this document alone. |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, what is not, and what the residual risks are. |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Which clients work, which settings they need, and what does not work yet. Measured, not assumed. |
| [docs/adr/](docs/adr/) | Architecture decisions, with the alternatives that were rejected and why. |
| [docs/adr/ADR-016-audit-log.md](docs/adr/ADR-016-audit-log.md) | The audit log: what it proves, what it does not, and what it costs. |
| [testdata/vectors/](testdata/vectors/) | Known-answer vectors, normative alongside the format spec. |
| [ref/python/](ref/python/) | A second decoder written from the format spec alone, and the differential test that compares it against the Go one. |
| [bench/](bench/) | Benchmark scripts, the figures they produce, and the methodology notes that came out of getting them wrong first. |
| [demo/](demo/) | The end-to-end demo, as scripts: upload through the gateway, ciphertext at the provider, identical hash back, and `tamper.sh` — the hostile provider, by hand, in one command. |
| [spec/tla/](spec/tla/) | The formal model of the manifest coordination, its five TLC configurations, and the counterexamples written out. |
| [CHANGELOG.md](CHANGELOG.md) | What each release contains, and what it does not. |

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Repo, CI, format specification, threat model, ADR-001/002/011 | **done** |
| M1 | Crypto core (segment encoder/decoder), file keyring, `keygen`/`encrypt`/`decrypt` | **done** |
| M2 | Local proxy: `PutObject`, `GetObject`, `HeadObject`, `DeleteObject` | **done** |
| M3 | S3 compatibility: SigV4 verification, checksums, ranges, listings | **done** |
| M3.5 | TLA+ model of the manifest and rotation coordination, checked with TLC | **done** |
| M4 | Multipart uploads: upload token, manifest, `gc`, multi-instance operation | **done** |
| — | Independent Python reference decoder, differential fuzzing | **done** |
| M5 | `blindbucket rotate`, metrics and health, benchmarks, release | **done** |
| — | `CopyObject` and `UploadPartCopy`, deferred from M5 | **done** |
| — | Vault Transit and AWS KMS as root-key sources, deferred from M5 | **done** |
| — | Cryptographically verifiable audit log, hash-chained and signed | **done** |
| M6 | Stretch: name encryption, presigned URLs, rollback protection | **done** |

M4 is the point the project becomes worth showing: multipart is what "works with real S3
clients" actually means for anything over 8 MiB. M3.5 existed to get its coordination rules
right before the code did — see below.

**What is still missing.** There is no `blindbucket reseal`: moving a keyring from one
root-key source to another means creating a new keyring and rotating objects onto it. The
AWS credential chain is not used — KMS credentials are configured explicitly
([ADR-013](docs/adr/ADR-013-root-key-sources.md)). Object tags are refused rather than
stored, because the provider would hold them in plaintext
([ADR-012](docs/adr/ADR-012-copy-semantics.md)). `ListMultipartUploads` is refused
permanently and says why. Presigned URLs are verified but never issued — presigning
is a computation the client does offline — and they read only: `GET` and `HEAD` are
served, everything else a presigned URL can name is refused, because a URL is where a
bearer credential gets copied ([ADR-019](docs/adr/ADR-019-presigned-urls.md)). Rollback detection is off by default and bounded in three ways
that are stated rather than implied: the first read of any object is trusted, a copied
object is trusted once more after the copy, and a tag says *which* write and not *which is
newer* — so where several instances write the same objects, a peer's write and a
provider's rollback look the same
([ADR-018](docs/adr/ADR-018-rollback-detection.md)). Object-name encryption covers every
operation the gateway serves, with one bound: a listing is read whole and sorted before any of it is served,
so a prefix beyond `names.max_listing_keys` is refused rather than answered in an order
that can make a client delete data ([ADR-017](docs/adr/ADR-017-listing-order-under-name-encryption.md)). The audit log is per instance and has no cross-instance
order, and entries after its last checkpoint are chained but unsigned — both by
design, both in [ADR-016](docs/adr/ADR-016-audit-log.md). And one benchmark cell is
documented as the provider's behaviour rather than explained; the gateway's share of it is
measured at 0.13 ms per request.

**Unsealing the keyring.** The root key can come from a passphrase, from Vault's Transit
engine or from AWS KMS, and the keyring file records which one sealed it — so a keyring
from the wrong environment is named as such rather than failing as a decryption error. The
service is asked once, at startup: after that every KEK is in memory and no request pays a
round trip. That is a deliberate trade, and its limit is stated plainly — the root key is
in the process afterwards either way. What the services buy is custody: the secret is not
a passphrase on somebody's laptop, access is logged elsewhere, and it can be revoked.
Deleting the Transit key stops the next start with `encryption key not found`, which is
verified rather than asserted ([ADR-013](docs/adr/ADR-013-root-key-sources.md)).

**Server-side copy.** `aws s3 cp s3://a s3://b` and `aws s3 mv` work at any size. A copy
does not move the object: the data key is unwrapped under the source's identity and wrapped
again under the destination's, because the wrap is bound to bucket and key, and the
ciphertext is copied inside the provider — 1.2 KB over the wire for a 600 KB object. Above
the client's multipart threshold the AWS CLI switches to `UploadPartCopy`, which *cannot*
stay server-side: a part is a segment with its own salt, so the range is decrypted and
re-encrypted on the way through. Why, and why the shared data key is not nonce reuse in the
sense that matters, is [ADR-012](docs/adr/ADR-012-copy-semantics.md).

## A race in my own design, and the machine that found it

Revising the design turned up two race conditions in the first version's manifest lifecycle.
Both end the same way: a multipart object that is visible but has no manifest. The data is
still there and still decryptable, but the proxy refuses to serve an object it cannot verify
as whole, so every `GetObject` fails. Neither bug lives in a single request — both need two
requests interleaved a particular way, on two instances that never learn of each other.

The fix was four rules, derived by reasoning. So was the bug. Before M4 turned those rules
into Go, [`spec/tla/Multipart.tla`](spec/tla/Multipart.tla) turned them into a model that TLC
checks exhaustively: three concurrent uploads, a single-part PUT, a delete, a rotation and a
`gc` pass on one key, with a crash possible after every step. 38.5 million distinct states,
no counterexample.

Four more configurations put flawed rules back and *require* a counterexample — a model that
cannot find the bugs already known is not evidence about the ones that are not. Here is the
original `gc` bug, from the trace TLC produces, with the incidental steps of uninvolved
processes left out:

```
1  client  PutObject                              a single-part object is visible
2  u1      CreateMultipartUpload, HEAD            upload open; current manifest id: none
3  u1      write manifest u1                      manifests: {u1}
4  gc      list manifests                         listed: {u1}
5  gc      HEAD — the object is single-part       current: none
6  gc      delete listed manifests that are not   manifests: {}   ← u1 is gone
           the current one
7  u1      CompleteMultipartUpload                visible: multipart u1, manifest missing
```

Every fact `gc` observed was true. `u1` really was not the current manifest id at step 5 — it
just was not current *yet*.

The result that paid for the milestone was not one of the two known bugs. Rule R4 fixes an
order for two `gc` steps that both only *read*, and swapping them is the kind of edit that
passes review precisely because neither changes anything. TLC produces an unreadable object in
twelve states: check for open uploads first, find none, then list, and the listing picks up a
manifest written after the check. Listing first is what gives the check its meaning.

That configuration is now a regression test. Each of the four counterexamples is also an
integration test that replays it against a real provider — [spec/tla/README.md](spec/tla/README.md) links each one,
and [ADR-010](docs/adr/ADR-010-manifest-lifecycle-under-concurrency.md) records what the model
does and does not cover.

```sh
make tla        # all five configurations; four must fail, one must not
```

## Development

Requires Go 1.24 or newer (for `crypto/hkdf`) and Docker for the integration tests.

```sh
make build          # build ./bin/blindbucket
make test           # go test -race
make lint           # golangci-lint
make fuzz           # 30s per fuzz target
make bench          # micro-benchmarks
make vuln           # govulncheck
make tla            # model-check spec/tla (needs a JRE; downloads tla2tools.jar)
make demo-setup     # MinIO, keyring, config, gateway and a payload for demo/
make demo           # run the end-to-end demo (see demo/README.md)

docker compose up -d                 # local MinIO on :9002, console on :9091
docker compose --profile keys up -d  # and Vault on :8200, a KMS emulator on :4599
```

The integration tests need a provider and skip without one:

```sh
docker compose up -d
BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/upstream ./internal/proxy

# the root-key sources need their own two services:
docker compose --profile keys up -d
BLINDBUCKET_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
BLINDBUCKET_TEST_VAULT_TOKEN=blindbucket-dev-token \
BLINDBUCKET_TEST_KMS_ENDPOINT=http://127.0.0.1:4599 go test ./internal/rootkey

# and against a running gateway, with a real client:
python3 test/integration/clients/boto3/scenarios.py
```

Production code is Go, without exception. Anything else in this repository — the Python
client tests, the TLA+ model — has a written reason in
[ADR-011](docs/adr/ADR-011-languages-outside-the-go-core.md).

## Reviews welcome

The format was specified before it was implemented precisely so that it can be reviewed,
and [testdata/vectors/segment_v1.json](testdata/vectors/segment_v1.json) fixes every input
so an independent implementation can check itself against it.

That is no longer only an invitation: [ref/python/](ref/python/) is a second decoder
written from the specification, and it agrees with the Go one on every vector and on
100 000 mutated inputs. Writing it turned up one ambiguity — the final-chunk rule is
stated for a streaming decoder, and the natural length comparison for a buffered one can
be read two ways, of which the wrong one is correct for every object whose size is not an
exact multiple of the chunk size. That is now spelled out in the format spec.

Every guarantee is backed by tests that play an actively hostile storage provider and
require an error rather than plaintext: every single-bit flip across all 32 header bytes,
tampered chunk data and tags, swapped and duplicated chunks, truncation at and inside chunk
boundaries, appended bytes, forged chunk sizes, multipart segments served under the wrong
part number, and a part replaced by an earlier upload attempt of the same part — bytes this
gateway itself wrote, which authenticate perfectly and are still the wrong ones
([ADR-014](docs/adr/ADR-014-part-salts-in-the-manifest.md)). A fuzz target additionally requires that anything the decoder accepts
re-encrypts to the identical bytes, which rules out two ciphertexts decoding to one
plaintext.

The same applies end to end. Integration tests against a real MinIO rewrite stored objects
behind the gateway's back — corrupting a chunk, truncating the ciphertext, swapping two
objects' bodies, forging a wrapped key — and require an error rather than plaintext in
every case.

If you find a weakness in [docs/FORMAT.md](docs/FORMAT.md), in the reasoning in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), or an attack the tests miss, that is the most
valuable contribution this project can receive. A weakness in the *reasoning* belongs in a
public issue, where it can be argued with. Anything that gets at plaintext, at key material,
or past an authentication check goes through [SECURITY.md](SECURITY.md) first — GitHub's
private reporting, not an issue.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the setup, what CI checks, and the two conventions
that are not visible from the code: how commits are written, and when a change needs an ADR.
Issues labelled [`good first issue`](https://github.com/LennardGeissler/blindbucket/labels/good%20first%20issue)
are scoped to be finishable without reading the whole codebase.

## License

Copyright 2026 Lennard Geißler

Apache License 2.0 — see [LICENSE](LICENSE).
