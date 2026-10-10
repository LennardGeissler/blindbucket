# Client Compatibility

What actually works, measured by pointing each client at the gateway and running
it. Every result below came from a real client against a real MinIO, not from
reading a specification.

**Measured:** the client matrix on 2026-09-12 against `v0.2.0`, with object names
in the clear. **AWS CLI and boto3 are re-run against every commit** by the
`Client compatibility` CI job, so their rows are current for `v1.2.0`. The other
clients were measured on the date their row gives; rclone has not been re-measured
since `v0.2.0`.

The **object-name encryption** rows were verified on 2026-09-16 with the AWS CLI
against a real MinIO — a 40 MiB multipart round trip and a server-side copy of it
with matching SHA-256, 250 objects listed complete and in order across 13 pages,
and `aws s3 sync --delete` run twice with the second run doing nothing. They are
not a re-run of the whole matrix, and this document does not claim they are.

**Setup:** `docker compose up -d`, `blindbucket serve`, path-style, 64 KiB chunks.

**Providers.** The client matrix is measured against MinIO. The Go integration
suite also runs against **Garage v2.4.1** since 2026-09-25
(`test/providers/garage.sh`), and passes there; what Garage does differently is
under [Conditional writes](#conditional-writes-for-rotation-and-migration) below.

**AWS S3** was measured on 2026-09-26 in `eu-central-1`: the Go integration
suite — upstream, proxy and probe, 238 tests — passes against it, with
virtual-host addressing and the temporary credentials of an OIDC role
([`deploy/aws-test/`](../deploy/aws-test/), run by the manual `AWS` workflow).
From a GitHub runner an ocean away that takes eight minutes rather than
eighteen seconds, and the one test it broke was a test that assumed a fast
provider, not the gateway. On 2026-09-27 the suite passed again, and the
clients went through a gateway deployed as it would be on AWS — keyring sealed
by KMS, upstream the real bucket, every credential a `${VAR}` reference to the
role's session: boto3 1.43.103 ran all fourteen scenarios, and the AWS CLI
round-tripped a 40 MiB multipart object, a range across a part boundary and a
presigned GET, with what the bucket held checked to be ciphertext. R2 and B2 are
not measured yet.

---

## Summary

| Client | Version tested | Status | Last measured | Required settings |
|---|---|---|---|---|
| AWS CLI v2 | 2.36.43 | **Works** | every commit, in CI | none |
| boto3 | 1.43.92 | **Works** | every commit, in CI | none |
| MinIO client (`mc`) | RELEASE.2025-08-13 | **Works** | 2026-09-28, after `v1.0.0` | `allow_unsigned_payload: true` on the proxy, for multipart only |
| rclone | 1.75.1 | **Works with settings** | `v0.2.0` | `allow_unsigned_payload: true` on the proxy; `--ignore-checksum`; `--size-only` for `check` |
| s5cmd | 2.3.0 | **Works** | 2026-10-03, main `8cdb03a` | none, `--endpoint-url` only |

**HTTP and HTTPS are different code paths.** A client chooses how to frame the
body by the endpoint's scheme. Over HTTP the AWS CLI signs the whole body; over
HTTPS it sends `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, aws-chunked with its
checksum in a trailer. Every row above except the next was measured over HTTP,
so until the Helm chart's test put the CLI behind TLS, the HTTPS framing had never
reached the gateway -- and the decoder rejected it
(see [CHANGELOG.md](../CHANGELOG.md)).

| Client | Version tested | Status | Last measured | Required settings |
|---|---|---|---|---|
| AWS CLI v2 over HTTPS | 2.37.4 | **Works** | every commit, in CI (`test/helm/kind.sh`) | none |

Multipart included since M4: each client was run with a file over its own
threshold, so the parts, the manifest and the size arithmetic are all exercised by
the client's own code path rather than by a hand-built request.

---

## AWS CLI v2

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:9000
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
```

| Command | Result |
|---|---|
| `aws s3 cp <file> s3://bucket/key` | works — over HTTP a signed body; over HTTPS aws-chunked with a CRC64NVME trailer |
| `aws s3 cp s3://bucket/key <file>` | works — identical SHA-256 |
| `aws s3 ls s3://bucket/prefix/` | works — reports **plaintext** sizes |
| `aws s3 sync <dir> s3://bucket/p/` | works, both directions, nested directories |
| `aws s3 rm s3://bucket/key` | works |
| `aws s3 rm s3://bucket/p/ --recursive` | works — `DeleteObjects` |
| `aws s3api put-object` | works — returns the verified `ChecksumCRC64NVME` |
| `aws s3api get-object --range` | works |
| `aws s3api head-object` | works — plaintext size, gateway metadata hidden |
| `aws s3 cp` of 40 MiB and 5 GiB | works — multipart, 8 MiB parts, identical SHA-256 |
| `aws s3 ls` of a multipart object | works — plaintext size, 5368709120 for the 5 GiB file |
| `aws s3 cp` across two proxy instances | works — parts spread over both, no affinity needed |
| restarting an instance mid-upload | the upload completes; the client retries the part it lost |
| `aws s3 cp s3://bucket/a s3://bucket/b` (13 bytes) | works — `CopyObject`, no data over the wire |
| `aws s3 cp s3://bucket/a s3://bucket/b` (1 GiB) | works — 128 `UploadPartCopy` calls, identical SHA-256 |
| `aws s3 mv s3://bucket/a s3://bucket/b` | works — copy then delete |
| `aws s3 ls` of a copied multipart object | works — plaintext size, 1073741824 for the 1 GiB copy |

The CLI's default checksum is CRC64NVME, which is verified against the plaintext
at the gateway and echoed back. That the echoed value matches what the CLI
computed is itself a check on the CRC-64/NVME implementation.

## boto3

Scenarios live in
[`test/integration/clients/boto3/scenarios.py`](../test/integration/clients/boto3/scenarios.py)
and are runnable:

```sh
BLINDBUCKET_ENDPOINT=http://127.0.0.1:9000 BLINDBUCKET_BUCKET=blindbucket-dev \
  python3 test/integration/clients/boto3/scenarios.py
```

| Scenario | Result |
|---|---|
| `put_object` / `get_object` round trip at 0, 1, 65535, 65536, 65537, 300000 bytes | works |
| `head_object` and `list_objects_v2` sizes | plaintext sizes |
| `get_object` with `Range`, including suffix and open-ended | works |
| User metadata, `ContentType`, `CacheControl` | preserved; `bb-*` never visible |
| `ChecksumAlgorithm="CRC32"` | verified and echoed |
| A deliberately wrong checksum | refused with `BadDigest`, nothing stored |
| Paginator with `PageSize=3`, `Delimiter="/"` | works |
| `delete_objects` | works |
| Missing object | `NoSuchKey` |
| `upload_file` / `download_file` at 30 MiB, 8 MiB parts | works — multipart, identical SHA-256 |
| `head_object` and `list_objects_v2` on a multipart object | plaintext sizes; the ETag carries the part count |
| `get_object` with `Range` across a part boundary | works |
| `abort_multipart_upload` | works — no object appears |
| A part that is not a multiple of the chunk size | refused with `InvalidRequest`, nothing stored |
| `list_multipart_uploads` | `NotImplemented` — see [Known limits](#known-limits) |
| `delete_object` / `list_objects_v2` on `.blindbucket/` | `AccessDenied`; the prefix is invisible in listings |

## MinIO client (`mc`)

```sh
mc alias set bb http://127.0.0.1:9000 <key> <secret> --api S3v4
```

| Command | Result |
|---|---|
| `mc cp <file> bb/bucket/key` | works |
| `mc cp bb/bucket/key <file>` | works — identical bytes |
| `mc ls bb/bucket/prefix/` | works — plaintext sizes |
| `mc mirror <dir> bb/bucket/p/` | works, nested |
| `mc cat bb/bucket/key` | works |
| `mc cp` of 64 MiB | works with `allow_unsigned_payload`, identical SHA-256 |

`mc` sends `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: aws-chunked with a signature per
chunk and **no trailer section at all**. That shape is what found the bug fixed
in `internal/auth/chunked.go` — the decoder expected a trailer block and rejected
every `mc` upload until a real client was pointed at it.

Its multipart path is different again: `mc` signs single-part bodies but sends
`UNSIGNED-PAYLOAD` for a multipart upload, so a large `mc cp` fails with
*"unsupported payload signing mode"* unless `allow_unsigned_payload: true` is set
on the proxy. Re-measured on 2026-09-28 with the same `mc` release: a 1 MiB
`mc cp` works without the setting, and a 64 MiB one is refused at
`CreateMultipartUpload` before any part is sent; with the setting it completes
with an identical SHA-256. The same caveat as for rclone applies — enable it only behind TLS
or on loopback. Below the threshold `mc` still needs nothing, which is why the
summary row names multipart specifically.

## rclone

rclone works, but needs three things said out loud.

```ini
[bb]
type = s3
provider = Other
access_key_id = ...
secret_access_key = ...
endpoint = http://127.0.0.1:9000
region = us-east-1
force_path_style = true
```

```sh
rclone copy --ignore-checksum <dir> bb:bucket/prefix/
rclone check --size-only <dir> bb:bucket/prefix/
```

| Requirement | Why |
|---|---|
| `allow_unsigned_payload: true` on the proxy | rclone cannot seek its upload body, so it cannot hash it to sign it, and it sends `UNSIGNED-PAYLOAD`. Setting `use_unsigned_payload = false` makes rclone fail with *"failed to seek body to start"* instead. Enable this only behind TLS or on loopback: without it the body between client and proxy is not covered by the signature. |
| `--ignore-checksum` on copy and sync | rclone compares the ETag against the local MD5. The ETag is the MD5 of **ciphertext**, so they never match, and rclone reports *"corrupted on transfer"* for a perfectly good object. |
| `--size-only` for `check` | Same reason. Sizes match exactly, because listings report plaintext sizes. |

With those, `copy`, `sync`, `ls` and `check --size-only` all pass, both
directions, on nested directories.

## s5cmd

s5cmd works with no settings beyond the endpoint. It was measured on 2026-10-03
with s5cmd 2.3.0 against a gateway built from main (`8cdb03a`), with object
names in the clear (`names.encrypt` off, the default), using the setup above.
The requests in the table were read from s5cmd's own `--log trace` output.

```sh
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1
s5cmd --endpoint-url http://127.0.0.1:9000 <command>
```

| Command | Result |
|---|---|
| `s5cmd cp <file> s3://bucket/key` (1 MB) | works, one `PutObject` with the body's SHA-256 in `x-amz-content-sha256` |
| `s5cmd cp <file> s3://bucket/key` (200 MiB) | works, multipart in 50 MiB parts (four `UploadPart`), every part signed with its own SHA-256 |
| `s5cmd cp s3://bucket/key <file>` (1 MB and 200 MiB) | works, identical SHA-256; see range reads below |
| `s5cmd ls s3://bucket/prefix/` | works, `ListObjectsV2` with `delimiter=/`, plaintext sizes, 209715200 for the multipart object |
| `s5cmd ls s3://bucket/` | works, common prefixes shown as `DIR` |
| `s5cmd head s3://bucket/key` | works, plaintext size; on a deleted key the gateway answers 404 and s5cmd reports "not found" |
| `s5cmd rm s3://bucket/key` | works, sent as a `DeleteObjects` request even for one key |
| `s5cmd rm 's3://bucket/prefix/*'` (1005 keys) | works, two `ListObjectsV2` pages, then two `DeleteObjects` requests; nothing left under the prefix |
| `s5cmd mv s3://bucket/a s3://bucket/b` (200 MiB multipart) | works, one `CopyObject` then `DeleteObjects`, identical SHA-256 |
| `s5cmd pipe` / `s5cmd cat` | works, byte-identical round trip |
| `s5cmd sync <dir> s3://bucket/p/` | works, nested directories; a second run lists the prefix and uploads nothing |
| `s5cmd sync 's3://bucket/p/*' <dir>` | works, tree identical to the source |

**Range reads.** s5cmd has no flag to ask for a byte range: neither `cp` nor
`cat` takes one. Every download is ranged anyway. s5cmd downloads through the
SDK's `s3manager` downloader, which issues `GET` with `Range` in `--part-size`
pieces (50 MiB by default) and gets `206 Partial Content` back. The 1 MB object
came back as one `Range: bytes=0-52428799`, and the 200 MiB object as four
ranges ending at `bytes=157286400-209715199`, with an identical SHA-256. So the
gateway's range path, mapping a plaintext range onto its 64 KiB chunks, runs
on every s5cmd download, not only when a range is asked for.

s5cmd joins the AWS CLI and boto3 in needing nothing beyond the endpoint, and
it gets there by signing every body it sends: each `PutObject`, `UploadPart`
and `DeleteObjects` request carries the SHA-256 of its body, so the
unsigned-payload path is never touched. The two behaviours worth knowing are
s5cmd's own, not the gateway's. `head` of a deleted key reports "not found",
and a download `sync` refuses a source without a wildcard (`source argument
must contain wildcard character`) before any request is made.

The SDK is not the one the issue expected. s5cmd 2.3.0 sends
`aws-sdk-go/1.44.298` in its User-Agent, which is the Go AWS SDK v1, not v2.
That is still a signing path neither boto3 nor the AWS CLI exercises, and it
carried every command above with no retries and no error other than the
expected 404. The Go SDK v2 remains unmeasured.

---

## Bugs only a real client found

Three clients needed a fix that only a real client could have found. `mc` sends an
aws-chunked body with no trailer section at all; rclone attaches an `?x-id=`
parameter that the router was refusing as an unknown sub-resource; and boto3 found
the third — user metadata was arriving with Go's canonical header casing, so
`response["Metadata"]["origin"]` came back as `"Origin"` and every lookup missed.

The fourth is the AWS CLI over HTTPS, in the summary above.

## Known limits

These apply to every client.

| Limit | Detail | Arrives |
|---|---|---|
| **`ListMultipartUploads`** | Returns `NotImplemented`, and will keep doing so. The upload ids this gateway issues are sealed tokens carrying the data key and the manifest id (ADR-006); neither can be reconstructed from the provider's listing, so the call could only return ids no client is able to use. Clients that abort their own uploads are unaffected — they hold the token already. | — |
| **The shape of a part ETag** | An `UploadPart` answers with the provider's ETag followed by `.` and a sealed suffix carrying that part's segment salt — the only way a stateless gateway can learn, at completion, which attempt at a part number it is assembling ([ADR-014](adr/ADR-014-part-salts-in-the-manifest.md)). Clients echo it back unchanged, which is all S3 asks of them, and the AWS CLI, boto3, `mc` and rclone were each measured doing so; s5cmd's multipart uploads complete, which the gateway refuses for an ETag it did not issue. A client that assumes a part ETag is 32 hex characters would be surprised; none of the five is. The object's own ETag is untouched. | — |
| **Object tags** | `PutObjectTagging`, `DeleteObjectTagging` and `x-amz-tagging` on an upload return `NotImplemented`: a tag is a key and a value the provider stores in plaintext, and this gateway does not take plaintext through a side door. `GetObjectTagging` is forwarded and answers an empty set for anything the gateway wrote — and an empty set too where the provider has no tagging at all (Garage), because such a provider holds no tags. Refused rather than ignored, so a client never believes its object carries tags it does not ([ADR-012](adr/ADR-012-copy-semantics.md)). | — |
| **Copy cost above the multipart threshold** | A server-side copy of a small object moves no data — 1.2 KB over the wire for a 600 KB object. Above the client's multipart threshold (8 MiB for the AWS CLI) the client switches to `UploadPartCopy`, and that path *cannot* stay inside the provider: a part is a segment with its own salt, so the range is decrypted and re-encrypted on the way through. Correct, and not free ([ADR-012](adr/ADR-012-copy-semantics.md)). | — |
| **Copying a `versionId`** | Returns `NotImplemented`. This build does not implement versioned reads, and copying the current version instead of the one asked for would be the wrong kind of helpful. | — |
| **Part sizes** | Every part but the last must be a multiple of the chunk size (FORMAT §7.3). The defaults of every client above satisfy this; a client configured with, say, 5.5 MiB parts is refused at completion with a message naming the fix. Empty parts are refused by both `UploadPart` and `UploadPartCopy` when they arrive, with `InvalidRequest` and the same empty-last-part explanation as completion. Small nonempty final parts remain valid ([ADR-026](adr/ADR-026-empty-parts-refused-on-arrival.md)). | — |

### Conditional writes, for rotation and migration

`blindbucket rotate` needs the provider to honour two preconditions, and
`blindbucket migrate-names` a third. Measured:

| Precondition | MinIO | AWS S3 | Garage v2.4.1 | Used for |
|---|---|---|---|---|
| `x-amz-copy-source-if-match` on `UploadPartCopy` | **enforced** | **enforced** | **enforced** | rotation: the source changing between the HEAD and the copy |
| `If-Match` on `CompleteMultipartUpload` | **enforced** | **enforced** | **ignored** — completes over whatever is there | rotation: the target changing between the copy and the completion |
| `If-None-Match: *` on `CompleteMultipartUpload` | **enforced** | **enforced** — at times as an error inside a `200`, once the completion has started | **ignored** — completes over whatever is there | migration: a client writing the encrypted key before the copy lands there |
| `If-Match` on `DeleteObject` | **ignored** — deletes regardless | not measured | **ignored** — deletes regardless | nothing — see below |

The third and fourth rows were measured on 2026-10-02 with the AWS CLI against
MinIO `RELEASE.2026-09-22T19-25-18Z` and Garage v2.4.1, with no gateway involved.
The fourth is recorded because the first design for `migrate-names` would have
relied on it; the model in [`spec/tla/Migrate.tla`](../spec/tla/Migrate.tla)
showed it did not need to before the measurement showed it could not have
([ADR-022](adr/ADR-022-migrating-to-encrypted-names.md)). AWS's row for the third
was measured by the AWS workflow on 2026-10-03, twice: enforced both times, and
in the second run delivered inside a `200`, which the gateway read as a provider
error until it gave such an error its condition's status back.

On MinIO both answer `412 PreconditionFailed`, and in practice the copy refuses
first — the rotation never gets as far as the completion. Either way the object
is counted as skipped rather than overwritten, which is invariant I2 holding.

A provider that silently *ignores* a header is worse than one that rejects it,
because rotation would look safe while losing writes — and Garage is that
provider for the second one. So a rotation no longer takes this table on trust:
before touching an object it measures both preconditions against the provider,
with a probe object under `.blindbucket/probe/`, and refuses to start unless both
are enforced ([ADR-020](adr/ADR-020-conditional-writes-measured.md)). On Garage
that means rotating with `--allow-unconditional`, which drops the guard, skips
the measurement, prints a warning, and requires that nothing writes to the
prefix meanwhile. R2 and Backblaze B2 are still unmeasured; the probe answers for
them at the first run, and `blindbucket probe s3://<bucket>` asks without
rotating.

The same probe measures the third row, and a migration refuses to start unless it
is enforced. Its verdict is a separate field in `probe --json` and does not change
`probe`'s exit status, which still answers for rotation alone (ADR-021). On Garage
a migration needs `--allow-unconditional`, with nothing writing to the prefix
while it runs.

Garage also refuses `UploadPartCopy` from a source it stores inline — under 3072
bytes — even as the only part of an upload, where AWS accepts it; the error says
*"minimum part size is 5Mb"*, but from 3072 bytes up the copy works (measured
2026-10-04; the first record said "under 5 MiB", [ADR-020](adr/ADR-020-conditional-writes-measured.md)). A small single-part object with no
condition to carry — every server-side copy, and every rotation under
`--allow-unconditional` — is therefore copied with one `CopyObject` instead,
which keeps the source precondition and works on both.

### Which write a provider keeps

Two writes to one key overlap whenever a multipart upload is open while anything
else writes the key. Providers do not agree on which one the key holds afterwards,
and AWS answers a completion it does not keep with a success
([ADR-025](adr/ADR-025-writes-rank-by-when-they-began.md)). Measured on 2026-10-03,
with one-byte objects and no gateway involved:

| | AWS S3 | MinIO `RELEASE.2026-09-22T19-25-18Z` | Garage v2.4.1 |
|---|---|---|---|
| Upload A created, then upload B; B completes, then A | A answered 200, **B** kept | **A** kept | A refused, `NoSuchUpload`; **B** kept |
| Upload A created, then a PUT; then A completes | A answered 200, **the PUT** kept | **A** kept | A refused, `NoSuchUpload`; **the PUT** kept |
| A 512 MiB PUT starts; during it an upload is created and completed | **the PUT** kept — ranked when its body arrived | not measured | not measured |

So on AWS a client can be told its multipart upload succeeded and find the key
holding another write. That is AWS's rule and the gateway passes it on unchanged.
What the gateway does about it is to keep from making it worse:

- A completion deletes the manifest of the version it replaced only once a HEAD
  has seen the replacement. Before 1.1, two overlapping uploads of one key on AWS
  could leave the object that stayed visible without its manifest, and every
  read of it failed with `IntegrityCheckFailed`.
- `rotate` and `migrate-names` give way to a client's upload of the same key. A
  copy that completed first would outrank an upload the client began earlier,
  and AWS would discard the client's write. Such an object is reported, as
  `conflicted` by `rotate` and `failed` by `migrate-names`, and the next run
  handles it. Both commands therefore need `s3:ListBucketMultipartUploads` on
  the bucket, as `gc` already did.

### Key services

The root key that unlocks the keyring can come from a passphrase, from the
Transit engine of Vault or OpenBao, or from AWS KMS (ADR-013). Measured, not
assumed:

| Service | Version | Result |
|---|---|---|
| Vault Transit | `hashicorp/vault` dev mode, 2026-09 | **Works.** Seal a keyring, start the gateway with no passphrase anywhere, round-trip a 3 MB object with an identical SHA-256. Deleting the Transit key stops the next start with `encryption key not found`. |
| OpenBao Transit | `quay.io/openbao/openbao` 2.7.1 dev mode, 2026-10-04; every commit in CI | **Works**, with `provider: vault` and nothing else changed. A keyring sealed by `keygen`; the gateway started with no passphrase anywhere and round-tripped a 3 MB object and a 40 MB multipart one with identical SHA-256, and read them back after a restart, the provider holding ciphertext; deleting the Transit key stopped the next start with `encryption key not found`. The root-key, `keygen` and `reseal` tests run against it on every commit, including a token allowed to encrypt and not decrypt, which `reseal` refuses before writing anything. |
| AWS KMS | AWS, `eu-central-1`, 2026-09-26 and 27 | **Works.** A root key sealed and opened again; the blob refused under a changed encryption context and under none; a blob sealed without a context, as keyrings before contexts were, still opens. Under a role that may use the key only with blindbucket's context or none. End to end: `keygen` seals a keyring with the key, a configuration naming a passphrase is refused it, the gateway starts with no passphrase anywhere and serves the client matrix against S3, and a restart opens the keyring through KMS again and reads what the first process wrote. **Not measured against AWS:** what a disabled or deleted key does to the next start — the test role may not disable its own key, and should not be given that. |

An AWS account is still not a build dependency. The regular CI runs the KMS
tests against `nsmithuk/local-kms`, which speaks the KMS JSON API and
establishes that the client speaks it correctly; the run against AWS is the
manual one in [`deploy/aws-test/`](../deploy/aws-test/), because it is billed
and measures the service rather than a change.

Both are brought up with the compose profile the tests use:

```sh
docker compose --profile keys up -d
BLINDBUCKET_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
BLINDBUCKET_TEST_VAULT_TOKEN=blindbucket-dev-token \
BLINDBUCKET_TEST_KMS_ENDPOINT=http://127.0.0.1:4599 \
  go test ./internal/rootkey
```

| Limit | Detail |
|---|---|
| **The AWS credential chain** | Resolved without the SDK, for the upstream and for KMS: the environment, a shared profile, web identity, a container endpoint and IMDSv2, named per section with `credential_source` ([ADR-024](adr/ADR-024-aws-credentials-without-the-sdk.md)). Web identity is measured against real STS by the manual AWS workflow, with the job's GitHub OIDC token in IRSA's place; IMDSv2 on EC2 was measured on 2026-10-05: the network benchmark's gateway took its upstream credentials from a c7g.2xlarge's instance role through one pass of about 80 minutes (whether its cache refreshed in that time was not checked). EKS Pod Identity is tested against a stub of its protocol and not measured. Not supported: SSO and `credential_process` in a profile — for a command run by hand, `aws configure export-credentials --format env` and `credential_source: env`. |
| **Changing a keyring's source** | `blindbucket reseal`, in any direction between a passphrase, Vault and KMS. Tested against Vault in dev mode — including a token whose policy allows encrypt and not decrypt, which is refused before anything is written — and the KMS emulator, which has no key policies; against KMS itself only by the manual AWS workflow ([ADR-023](adr/ADR-023-resealing-a-keyring.md)). |
| **Vault authentication** | A token. AppRole, Kubernetes auth and the rest are not implemented; a token from any of them can be configured. |

---

### A note on reverse proxies in front of the gateway

The gateway emits user metadata with lower-case header names on purpose, because
SDKs surface metadata keys exactly as they arrive and boto3 hands the caller
`response["Metadata"]["origin"]`. A reverse proxy that re-canonicalises headers
turns that back into `Origin` and breaks every lookup — Go's own
`httputil.ReverseProxy` does this, and it is worth checking on whatever sits in
front of a deployment. nginx passes them through unchanged, which is what the CI
job uses. The symptom is metadata that round-trips with the wrong casing while
everything else works.
| **ETag ≠ MD5 of plaintext** | The ETag is the provider's, so it is the MD5 of the ciphertext. Anything comparing it against a local hash sees a mismatch. Sizes are fine. | by design |
| **Presigned URLs read only** | `GET` and `HEAD` are served; every other operation a presigned URL can name is refused with `AccessDenied`. A URL is where a bearer credential gets copied — browser history, `Referer` headers, chat previews, CI logs — and a preview that issues a `GET` is a `GET`, while one that issues a `DELETE` is data loss with no attacker anywhere in it. Presigned `PUT`, the browser-upload case, is deferred rather than refused permanently; **presigned POST**, the form-and-policy mechanism, is a different protocol and is not planned. The gateway verifies presigned URLs and never issues them, because presigning is a local computation in the client ([ADR-019](adr/ADR-019-presigned-urls.md)). | writes: later |
| **Presigned URLs must point at the gateway** | Not at the provider, which holds ciphertext under a name the recipient cannot read and no key. `host` is covered by the signature, so the two cannot be confused — but it means the gateway has to be reachable by whoever is given the link. | by design |
| **boto3 presigns with SigV2 unless told otherwise** | botocore still defaults to the older signature format for presigned URLs against a custom endpoint, and this gateway verifies `AWS4-HMAC-SHA256` only. Build the client with `Config(signature_version="s3v4")`. A SigV2 URL is answered with `InvalidRequest` naming the setting, rather than with the first unknown query parameter. The AWS CLI produces SigV4 already. | by design |
| **Listing sizes use the configured chunk size** | A listing carries no per-object metadata, so the conversion assumes the chunk size this deployment is configured with. Correct for everything this deployment wrote; an object written under a different setting is listed with its raw ciphertext size rather than a wrong plaintext one. Not authenticated in any case — see [THREAT_MODEL.md](THREAT_MODEL.md) section 5.4. | by design |
| **Objects not written by the gateway** | Refused with `ObjectNotEncrypted` rather than served. Mixing encrypted and unencrypted objects behind one endpoint would leave a client unable to tell which it got. | by design |
| **Bucket sub-resources** | `?acl`, `?policy`, `?versioning`, `?lifecycle`, `?tagging` all return `NotImplemented`. | not planned |
| **Server-side encryption headers** | Refused. The gateway encrypts already; accepting them would suggest a second layer that is not there. | by design |
| **Object-name encryption (`names.encrypt`)** | Off by default. With it on, every operation the gateway serves is served: single objects, multipart, both copy paths, tagging, bulk delete and listing. `blindbucket rotate` and `gc` work too, and `gc` needs no name key because a manifest is bound to the stored key and lives at the hash of it. A bucket written before the switch is moved across by `blindbucket migrate-names` ([ADR-022](adr/ADR-022-migrating-to-encrypted-names.md)). The remaining limit is which *listings* can be answered — see the row below. | by design |
| **`RollbackDetected` (502)** | Returned only with `freshness.index` configured. The object authenticated, and is not the write this gateway last recorded for that key -- a provider serving an earlier genuine version, or serving an object for a key the gateway deleted. No S3 client knows this code; every one of them treats a 502 as a failed request, which is the intended outcome. Off by default, with its limits in [THREAT_MODEL §5.1](THREAT_MODEL.md) and [ADR-018](adr/ADR-018-rollback-detection.md): the first read of any object is unchecked, a copied object is unchecked until read once, `HEAD` is never checked, and where several instances write the same objects a peer's write is indistinguishable from a rollback. | by design |
| **Provider 400 on a plaintext listing** | With `names.encrypt` off, the client's listing query is forwarded apart from presigning parameters, so a provider 400 is returned as 400 with its code and message. With name encryption on the gateway builds the query, so these errors keep `502 InternalError`. Other operations and statuses keep their existing mappings ([ADR-027](adr/ADR-027-plaintext-listing-provider-errors.md)). | by design |
| **Listings under name encryption** | Served, in the client's order and paginated, for a prefix up to `names.max_listing_keys` (default 100 000). The provider orders by the encrypted key, so the whole prefix is read and sorted before any of it is served — an unsorted listing makes `aws s3 sync --delete` delete objects that exist. A prefix past the bound is refused with `NotImplemented` naming the limit, rather than answered in an unusable order. A prefix not ending on `/` and a delimiter other than `/` are refused permanently: encryption is per path segment, and `/` is the one separator that survives it. | by design |
| **Switching `names.encrypt` on a bucket with objects** | Not a toggle. An object is stored under the encrypted form of its key, so turning it on hides everything written before and turning it off hides everything written since. Moving an existing bucket across rewrites every object's key, which is what `blindbucket migrate-names` does. | by design |
| **Key length under name encryption** | A key S3 accepts can have no legal encrypted form, answered with `KeyTooLongError`. Where the limit sits depends on how many `/`-separated segments a key has: 624 bytes for one long segment, 128 for a path of four-character ones. | by design |

## How to reproduce

```sh
docker compose up -d
make build
export BLINDBUCKET_PASSPHRASE=...
./bin/blindbucket keygen --out keyring.json
# fill in blindbucket.yaml, then:
./bin/blindbucket serve --config blindbucket.yaml
```

The Go integration tests cover the same ground without external clients:

```sh
BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/proxy ./internal/upstream
```
