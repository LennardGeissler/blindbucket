# Client Compatibility

What actually works, measured by pointing each client at the gateway and running
it. Every result below came from a real client against a real MinIO, not from
reading a specification.

**Measured:** the client matrix on 2026-09-12 against `v0.2.0`, with object names
in the clear. **AWS CLI and boto3 are re-run against every commit** by the
`Client compatibility` CI job, so their rows are current for `v0.3.0`; `mc` and
rclone have not been re-measured since, and are marked as of `v0.2.0` below.

The **object-name encryption** rows were verified on 2026-09-16 with the AWS CLI
against a real MinIO — a 40 MiB multipart round trip and a server-side copy of it
with matching SHA-256, 250 objects listed complete and in order across 13 pages,
and `aws s3 sync --delete` run twice with the second run doing nothing. They are
not a re-run of the whole matrix, and this document does not claim they are.

**Setup:** `docker compose up -d`, `blindbucket serve`, path-style, 64 KiB chunks.

---

## Summary

| Client | Version tested | Status | Last measured | Required settings |
|---|---|---|---|---|
| AWS CLI v2 | 2.36.43 | **Works** | every commit, in CI | none |
| boto3 | 1.43.92 | **Works** | every commit, in CI | none |
| MinIO client (`mc`) | RELEASE.2025-08-13 | **Works** | `v0.2.0` | `allow_unsigned_payload: true` on the proxy, for multipart only |
| rclone | 1.75.1 | **Works with settings** | `v0.2.0` | `allow_unsigned_payload: true` on the proxy; `--ignore-checksum`; `--size-only` for `check` |

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
| `aws s3 cp <file> s3://bucket/key` | works — uses aws-chunked with a CRC64NVME trailer |
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
`UNSIGNED-PAYLOAD` for the parts of a multipart upload, so a large `mc cp` fails
with *"unsupported payload signing mode"* unless `allow_unsigned_payload: true` is
set on the proxy. The same caveat as for rclone applies — enable it only behind TLS
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

---

## Known limits

These apply to every client.

| Limit | Detail | Arrives |
|---|---|---|
| **`ListMultipartUploads`** | Returns `NotImplemented`, and will keep doing so. The upload ids this gateway issues are sealed tokens carrying the data key and the manifest id (ADR-006); neither can be reconstructed from the provider's listing, so the call could only return ids no client is able to use. Clients that abort their own uploads are unaffected — they hold the token already. | — |
| **The shape of a part ETag** | An `UploadPart` answers with the provider's ETag followed by `.` and a sealed suffix carrying that part's segment salt — the only way a stateless gateway can learn, at completion, which attempt at a part number it is assembling ([ADR-014](adr/ADR-014-part-salts-in-the-manifest.md)). Clients echo it back unchanged, which is all S3 asks of them, and the AWS CLI, boto3, `mc` and rclone were each measured doing so. A client that assumes a part ETag is 32 hex characters would be surprised; none of the four is. The object's own ETag is untouched. | — |
| **Object tags** | `PutObjectTagging`, `DeleteObjectTagging` and `x-amz-tagging` on an upload return `NotImplemented`: a tag is a key and a value the provider stores in plaintext, and this gateway does not take plaintext through a side door. `GetObjectTagging` is forwarded and answers an empty set for anything the gateway wrote. Refused rather than ignored, so a client never believes its object carries tags it does not ([ADR-012](adr/ADR-012-copy-semantics.md)). | — |
| **Copy cost above the multipart threshold** | A server-side copy of a small object moves no data — 1.2 KB over the wire for a 600 KB object. Above the client's multipart threshold (8 MiB for the AWS CLI) the client switches to `UploadPartCopy`, and that path *cannot* stay inside the provider: a part is a segment with its own salt, so the range is decrypted and re-encrypted on the way through. Correct, and not free ([ADR-012](adr/ADR-012-copy-semantics.md)). | — |
| **Copying a `versionId`** | Returns `NotImplemented`. This build does not implement versioned reads, and copying the current version instead of the one asked for would be the wrong kind of helpful. | — |
| **Part sizes** | Every part but the last must be a multiple of the chunk size (FORMAT §7.3). The defaults of every client above satisfy this; a client configured with, say, 5.5 MiB parts is refused at completion with a message naming the fix. | — |

### Conditional writes, for rotation

`blindbucket rotate` needs the provider to honour two preconditions, and whether
MinIO does was left open at design time. Measured:

| Precondition | MinIO | Used for |
|---|---|---|
| `x-amz-copy-source-if-match` on `UploadPartCopy` | **enforced** | the source changing between the HEAD and the copy |
| `If-Match` on `CompleteMultipartUpload` | **enforced** | the target changing between the copy and the completion |

Both answer `412 PreconditionFailed`, and in practice the copy refuses first —
the rotation never gets as far as the completion. Either way the object is
counted as skipped rather than overwritten, which is invariant I2 holding.

A provider that silently *ignored* these headers would be worse than one that
rejected them, because rotation would look safe while losing writes. That is what
`--allow-unconditional` exists for: it makes dropping the guard an explicit
decision with a warning, rather than something a provider does quietly. Whether
R2 and Backblaze B2 enforce them is still untested.

### Key services

The root key that unlocks the keyring can come from a passphrase, from Vault's
Transit engine or from AWS KMS (ADR-013). Measured, not assumed:

| Service | Version | Result |
|---|---|---|
| Vault Transit | `hashicorp/vault` dev mode, 2026-09 | **Works.** Seal a keyring, start the gateway with no passphrase anywhere, round-trip a 3 MB object with an identical SHA-256. Deleting the Transit key stops the next start with `encryption key not found`. |
| AWS KMS | **the protocol, not the service** | Exercised against `nsmithuk/local-kms`, which speaks the KMS JSON API: `CreateKey`, `Encrypt`, `Decrypt`, SigV4 and all. What that establishes is that the client speaks KMS correctly. It is **not** a test against AWS, and this project has not run one. |

That asymmetry is deliberate rather than an oversight. An AWS account is not a
build dependency, and "supports AWS KMS" without ever having called AWS would be
a claim this document exists to avoid making.

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
| **The AWS credential chain** | Not used. KMS credentials are configured explicitly, so instance roles, web identity and SSO do not apply. A consequence of hand-writing the client rather than taking the SDK (ADR-013). |
| **Changing a keyring's source** | There is no `blindbucket reseal`. Moving between a passphrase, Vault and KMS means creating a new keyring and rotating objects onto it. |
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
| **Presigned URLs** | Query-signed requests are refused. | M6 |
| **Listing sizes use the configured chunk size** | A listing carries no per-object metadata, so the conversion assumes the chunk size this deployment is configured with. Correct for everything this deployment wrote; an object written under a different setting is listed with its raw ciphertext size rather than a wrong plaintext one. Not authenticated in any case — see [THREAT_MODEL.md](THREAT_MODEL.md) section 5.4. | by design |
| **Objects not written by the gateway** | Refused with `ObjectNotEncrypted` rather than served. Mixing encrypted and unencrypted objects behind one endpoint would leave a client unable to tell which it got. | by design |
| **Bucket sub-resources** | `?acl`, `?policy`, `?versioning`, `?lifecycle`, `?tagging` all return `NotImplemented`. | not planned |
| **Server-side encryption headers** | Refused. The gateway encrypts already; accepting them would suggest a second layer that is not there. | by design |
| **Object-name encryption (`names.encrypt`)** | Off by default. With it on, every operation the gateway serves is served: single objects, multipart, both copy paths, tagging, bulk delete and listing. `blindbucket rotate` and `gc` work too, and `gc` needs no name key because a manifest is bound to the stored key and lives at the hash of it. The remaining limit is which *listings* can be answered — see the row below. | by design |
| **`RollbackDetected` (502)** | Returned only with `freshness.index` configured. The object authenticated, and is not the write this gateway last recorded for that key -- a provider serving an earlier genuine version, or serving an object for a key the gateway deleted. No S3 client knows this code; every one of them treats a 502 as a failed request, which is the intended outcome. Off by default, with its limits in [THREAT_MODEL §5.1](THREAT_MODEL.md) and [ADR-018](adr/ADR-018-rollback-detection.md): the first read of any object is unchecked, a copied object is unchecked until read once, `HEAD` is never checked, and where several instances write the same objects a peer's write is indistinguishable from a rollback. | by design |
| **Listings under name encryption** | Served, in the client's order and paginated, for a prefix up to `names.max_listing_keys` (default 100 000). The provider orders by the encrypted key, so the whole prefix is read and sorted before any of it is served — an unsorted listing makes `aws s3 sync --delete` delete objects that exist. A prefix past the bound is refused with `NotImplemented` naming the limit, rather than answered in an unusable order. A prefix not ending on `/` and a delimiter other than `/` are refused permanently: encryption is per path segment, and `/` is the one separator that survives it. | by design |
| **Switching `names.encrypt` on a bucket with objects** | Not a toggle. An object is stored under the encrypted form of its key, so turning it on hides everything written before and turning it off hides everything written since. Moving an existing bucket across is a rewrite of every object's key. | by design |
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
