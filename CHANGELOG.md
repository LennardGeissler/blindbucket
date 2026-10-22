# Changelog

Notable changes per release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).
What the version number is about is written down in
[ADR-021](docs/adr/ADR-021-what-1.0-promises.md): data at rest stays readable by
every later release; configuration, CLI, `--json` documents, metrics, admin
endpoints and the gateway's own S3 error codes change incompatibly only in a
major release; the Go API, log lines and human-readable output are not promised.
Before `1.0.0` only the wire format was held stable.

The **wire format** is versioned separately and independently: the segment format
is version `1` and is specified in [docs/FORMAT.md](docs/FORMAT.md). A change to
it would be a change to that number, announced here, and objects written under
version 1 would keep being readable.

## [Unreleased]

### Added

- **The keyring file is specified, with version 2 for tenants.** FORMAT.md §18 writes
  down the keyring as every release has written it, and version 2, which holds tenants
  under locks of their own ([ADR-038](docs/adr/ADR-038-tenants-and-crypto-shredding.md)).
  Twenty-two known-answer vectors pin it, and the Python reference reads them.
- **Tenants in the keyring.** `blindbucket tenants create | assign | activate | list` adds
  tenants with keys of their own under a lock of their own, configured in `keys.tenants`,
  and gives them buckets; `reseal --tenant` moves a tenant to another lock and keeps the
  old one in its history. `keygen`, `keys remove` and `reseal` keep a keyring's tenants,
  and `keys list` gains a `TENANT` column and `tenant` and `opened` in `--json`
  ([#133](https://github.com/LennardGeissler/blindbucket/issues/133)).
- **The gateway serves tenants.** Writes to an active tenant's buckets wrap under its
  keys and, with `names.encrypt`, map names under its name key; an inactive tenant's
  buckets behave as the default tenant's, and reads go by the key each object names. A
  destroyed tenant's buckets answer `403 AccessDenied` and an unopened tenant's `503
  ServiceUnavailable`, reads included, while every other bucket is served.
  `blindbucket_keyring_generation` and `blindbucket_tenant_open{tenant}` show what each
  instance loaded, which is what a rollout waits for.
- **The bucket commands serve tenants, and `tenants census` counts what a destruction
  would miss.** `rotate`, `scrub`, `encrypt-existing` and `migrate-names` open only the
  target bucket's tenant and use its keys and name key; `rotate` refuses a key of
  another tenant, and it and `scrub` report objects off the bucket's tenant's keys as
  `off_tenant`. `migrate-names` moves an active tenant's bucket from the default name
  key to the tenant's. `tenants census` counts, per bucket of a tenant, the objects not
  under its keys, which is the first step of a destruction.
- **`tenants destroy` tombstones a tenant.** It takes the tenant's census and stops on
  any object not under its keys, or not readable, unless `--force`. It then writes the
  keyring with a tombstone in the tenant's place, which keeps its buckets refused and
  its name and key ids from being issued again. It neither needs nor destroys the
  tenant's lock: it says how to roll the keyring out, then how to destroy each lock the
  tenant ever had, and warns about a key that also seals the deployment or another
  tenant.
- **The audit log encrypts a tenant's names under the tenant's key.** Entries about a
  tenant's buckets encrypt bucket and object names under a key derived from its name
  key, active or not, so they become opaque when the tenant is destroyed; the chain and
  signatures verify as before. Entries about a bucket whose tenant is destroyed or not
  open on the instance record the names as digests. `audit verify --print` opens a
  keyring with tenants and decrypts each entry with whichever key it holds opens it.
- **`doctor`, `encrypt` and `decrypt` open a keyring with tenants.** `doctor` opens every
  tenant the configuration can, and a new check, `tenants`, fails for one that does not
  open, since its buckets would answer 503. It warns about a tenant under the
  deployment's lock and about a `keys.tenants` entry the keyring does not have.
  `encrypt` wraps under the default tenant's key, and `decrypt` finds a file's key in
  whichever tenant holds it, naming a tenant that did not open or was destroyed.
- **The status page shows the tenants.** With tenants, it shows the keyring generation
  the instance serves, and per tenant its buckets, the key its writes use, its lock and
  whether it opened here, with why not.
- **A guide to running tenants and destroying one.**
  [docs/guides/tenants.md](docs/guides/tenants.md) gives the order of operations, and
  THREAT_MODEL §5.12 what a destruction promises and what it does not. That includes one
  limit: in a versioned bucket, the census and `rotate` see current objects only.
- **Build details in `blindbucket version`.** The version remains the first line; when
  present in Go's build info, the output also reports the Go version, VCS revision and
  timestamp, modified-tree status, and target platform. Missing metadata is omitted.

### Fixed

- **A bucket's 409 from the provider is the client's answer, not a 502.**
  `BucketAlreadyOwnedByYou` and `BucketAlreadyExists` on `CreateBucket`, and
  `BucketNotEmpty` on `DeleteBucket`, now pass through with their status and code. rclone
  calls `CreateBucket` before every multipart upload and gave up after ten retries on the
  502, so its multipart uploads needed `--s3-no-check-bucket`; they no longer do
  ([#194](https://github.com/LennardGeissler/blindbucket/issues/194)). `BucketNotEmpty`
  says that orphaned manifests and tag sidecars under `.blindbucket/` count, and that
  `blindbucket gc` removes them.

## [1.6.0] — 2026-10-28

**Refusals decided again, and a status page.** Presigned URLs can upload where the
operator sets a size limit, with CORS for the browser pages that use them (ADR-036), and
object tags are stored sealed, in a sidecar per object version (ADR-037): the two things
the gateway refused, decided again (M14). A read-only status page shows a gateway's
health, keys and audit log, on loopback (ADR-035, M13). Tag sidecars are a new object
type next to the segment and the manifest (FORMAT.md §17); the format is still `1`, and
everything is additive under [ADR-021](docs/adr/ADR-021-what-1.0-promises.md).

**Upgrading:** nothing to do for the binaries, the image or the Helm chart, whose new
options are off. Four things answer differently. A client's `If-None-Match` and
`If-Match` on a write now reach the provider, so a conditional write that does not hold
is refused with `412` where it used to overwrite. `x-amz-tagging`, `PutObjectTagging`
and `DeleteObjectTagging` are served where they were refused with `NotImplemented`, and a
copy given `x-amz-tagging` without `x-amz-tagging-directive: REPLACE` is refused with
`InvalidArgument` where the header was ignored. A bucket sub-resource named with the wrong
method is refused where it was served as another operation. And `gc` collects tag
sidecars, with new counts in `gc --json`.

### Added

- **Presigned uploads, where the operator sets a size limit.** With `server.presign.uploads.max_size` set, a presigned URL can `PutObject` or `UploadPart`, so a backend can hand a client a URL to upload one file to. The limit is judged on `Content-Length` before the body is read, and an upload URL's window is capped at an hour unless `uploads.max_expiry` says otherwise. A checksum or `If-None-Match` the URL binds is honoured, `x-amz-*` values in the query are read as headers, and an `x-amz-*` header the URL did not sign is refused. [browser-uploads.md](docs/guides/browser-uploads.md) shows the backend's side, for JavaScript v3 and boto3, and the browser's ([ADR-036](docs/adr/ADR-036-presigned-uploads.md)).

- **CORS for browser pages, from the gateway's own configuration.** With `server.cors.allowed_origins` set, the gateway answers a browser's preflight for a listed origin and marks its responses readable by that origin, the `ETag` included, so a page can upload by presigned URL, in parts too. It never answers `*` or allows credentials, and refuses a preflight for any other origin, method or header. The bucket-CORS sub-resource stays refused, because the provider would store it for an endpoint the browser never reaches ([ADR-036](docs/adr/ADR-036-presigned-uploads.md)).

- **Object tags, sealed.** `PutObjectTagging`, `GetObjectTagging`, `DeleteObjectTagging` and `x-amz-tagging` on uploads are served. The tag set is sealed in a sidecar beside the object version, under a key its own data key derives, so the provider holds no tag in plaintext and cannot move a tag set to another object or version; no provider feature, such as a lifecycle rule, can act on these tags. Copies, `rotate` and `migrate-names` keep an object's tags, a copy follows `x-amz-tagging-directive` as S3 does, and `gc` removes the sidecars of versions that are gone ([ADR-037](docs/adr/ADR-037-encrypted-object-tags.md)).

- **A read-only status page.** With `admin.dashboard.listen` set, the gateway serves one page that says whether it is ready, which keys it holds and what seals them, and whether its audit log is being signed and still verifies, checked in the background every ten minutes. It never shows key material, credentials or object names, runs no script and changes nothing. It has no authentication of its own, so it serves only on loopback and only to requests that name `localhost`, and is reached from elsewhere through `kubectl port-forward` or an SSH tunnel ([ADR-035](docs/adr/ADR-035-dashboard.md)).

- **`encrypt` and `decrypt` open a keyring sealed by Vault or KMS.** Both opened a keyring with a passphrase only and had no `--config`, so an operator who moved their root key to Vault Transit or AWS KMS lost the offline commands entirely — and the error they got was about a passphrase rather than about the flag that was missing. They now take `--config` and open the keyring through the same path as `keys list`, `rotate` and `serve`, so whichever service sealed it is asked. Without `--config` a service-sealed keyring is refused by name, saying which provider it needs and which flag supplies it. The passphrase path is unchanged and still the default ([#46](https://github.com/LennardGeissler/blindbucket/issues/46)).

### Fixed

- **`gc` no longer deletes the manifest of a visible object when a HEAD fails.** It took any failed HEAD of an object for a missing object, so a provider answering one HEAD with a 503 during a pass made gc delete every manifest of that key past the minimum age, the visible object's included, which then could not be read. Only a 404 now means the object is gone; any other failure skips the key and is counted as an error. A `bb-mid` that does not parse skips the key too, rather than leaving its manifests unprotected.

- **A bucket sub-resource named with the wrong method is refused instead of dropped.** `?delete`, `?location` and `?uploads` were recognised only together with the method that serves them, so any other method fell through to the plain bucket request the method alone described: `DELETE /bucket?delete` was carried out as `DeleteBucket`, `PUT /bucket?delete` as `CreateBucket`, and `GET /bucket?delete` was answered with a listing. The sub-resource now decides, and a mismatched method is answered `501` naming the method it takes. A query carrying two of them is refused rather than served as whichever one Go's map iteration happened to yield first, and the whole query is checked before the operation is chosen, so `?uploads&acl` is refused for `?acl` every time instead of roughly one time in seven ([#187](https://github.com/LennardGeissler/blindbucket/issues/187)).

- **Presigned URLs made by the AWS SDK for JavaScript v3 are accepted.** The SDK puts `X-Amz-Content-Sha256=UNSIGNED-PAYLOAD` in the query of every URL it presigns, downloads included, and the gateway refused each one as an unknown sub-resource with `501`, so no presigned URL from JavaScript v3 ever worked. It is now read as one of the signing parameters; only that value is accepted. boto3 and the AWS CLI leave it out and were not affected (measured with v3.1152.0).

- **A client's conditional write is no longer carried out unconditionally.** `If-None-Match: *` and `If-Match` on `PutObject`, `CompleteMultipartUpload` and `CopyObject` were dropped without a word, so "create only if absent" could overwrite an object. They now go to the provider with the write, under name encryption too, and a condition that does not hold is answered `412`. Where the provider ignores them, as Garage v2.4.1 does, the client gets what the provider does ([#168](https://github.com/LennardGeissler/blindbucket/issues/168), [COMPATIBILITY.md](docs/COMPATIBILITY.md#a-clients-own-conditional-writes)).

- **A copy whose ETag matches is no longer refused because of a date.** With both `x-amz-copy-source-if-match` and `x-amz-copy-source-if-unmodified-since` on a `CopyObject` or `UploadPartCopy`, the gateway answered `412` when the source had changed after the date even though the ETag matched, where S3 makes the copy. A matching `if-match` now decides, as the CopyObject reference and RFC 9110 section 13.2.2 describe; a malformed date is still refused. The `if-none-match` and `if-modified-since` pair is unchanged, because S3's answer for a non-matching ETag with a date that fails is not documented and has not been measured ([#90](https://github.com/LennardGeissler/blindbucket/issues/90)). `rotate` and `migrate-names` send `if-match` alone and are not affected.

## [1.5.1] — 2026-10-21

**A security fix.** Three request bodies are now checked against the signature
([GHSA-h6g6-fvvh-3r88](https://github.com/LennardGeissler/blindbucket/security/advisories/GHSA-h6g6-fvvh-3r88)).
Nothing else changes from 1.5.0.

### Security

- **The bodies of `DeleteObjects`, `CompleteMultipartUpload` and bucket requests are checked against the signature.** They were read without being compared to the `x-amz-content-sha256` the signature covers, so a request whose headers were signed was served with any body. Someone able to alter traffic on an unprotected hop between client and gateway, or holding a signed request within its 15-minute window, could change which objects a `DeleteObjects` removed or which parts a completion assembled. These bodies now go through the same verifying reader as an upload, which also checks `Content-MD5` and `x-amz-checksum-*`. Every release from 0.1.0 through 1.5.0 is affected ([GHSA-h6g6-fvvh-3r88](https://github.com/LennardGeissler/blindbucket/security/advisories/GHSA-h6g6-fvvh-3r88)).

## [1.5.0] — 2026-10-19

**Software that cannot be changed, behind the gateway.** Five applications -- Nextcloud,
GitLab, Grafana Loki, Mastodon and Velero -- are measured storing through the gateway,
each with a guide and a CI job, and `blindbucket encrypt-existing` encrypts what a
bucket held before, so an existing installation can move behind it (M12). Audit entries
can be exported to a SIEM, a read may set its own response headers, which GitLab needs,
and there is a Homebrew cask. All of it is additive under
[ADR-021](docs/adr/ADR-021-what-1.0-promises.md), and the format is still `1`.

**Upgrading:** nothing to do for the binaries, the image or the Helm chart. Two things
read differently: a client that closes a download early is logged at INFO rather than
ERROR, and audited without `IntegrityCheckFailed`; and requests carrying
`response-content-disposition` and its siblings, which were refused with
`NotImplemented`, are served. A gateway in front of GitLab needs `presign.max_expiry`
of at least 4h15m, which the `1h` `blindbucket init` writes is not
([docs/guides/gitlab.md](docs/guides/gitlab.md)).

### Added

- **`blindbucket encrypt-existing` encrypts what a bucket held before the gateway, in place.** A gateway refuses such objects with `ObjectNotEncrypted`, so until now an application with existing data could not move behind it. The command reads each plaintext object, encrypts it under a new data key and writes it back where the gateway looks for it, with its headers and metadata; a client writing through the gateway during the run keeps its write, guarded as rotation and `migrate-names` are and checked in TLA+ first. It leaves alone what it cannot rewrite safely -- tagged and locked objects among them -- and refuses a versioned bucket unless `--keep-versions` says the old plaintext versions are handled ([ADR-034](docs/adr/ADR-034-encrypting-existing-objects.md)).
- **Nextcloud measured, with a guide.** Nextcloud 35.0.2 with S3 as primary storage works through the gateway, names in clear or encrypted: uploads including chunked and multipart ones, ranges, copies, versions, shares and deletes, with only ciphertext at the provider. [docs/guides/nextcloud.md](docs/guides/nextcloud.md) says how to set it up and what not to expect: an existing Nextcloud's bucket cannot be read until [#151](https://github.com/LennardGeissler/blindbucket/issues/151). `test/apps/nextcloud` runs it in CI on every change to the gateway and weekly.
- **GitLab measured, with a guide.** GitLab CE 19.5.0 stores job artifacts, LFS objects, uploads and packages through the gateway, names in clear or encrypted, and downloads them through the presigned URLs it redirects to. It needs the `response-*` parameters above, the feature flag `s3_multithreaded_uploads` off, because fog-aws copies large files in parts one byte too long, and `presign.max_expiry` of at least 4h15m. [docs/guides/gitlab.md](docs/guides/gitlab.md) says how to set it up; `test/apps/gitlab` runs it in CI.
- **Grafana Loki measured, with a guide.** Loki 3.7.8 stores its chunks, its TSDB index and its compactor's state through the gateway, names in clear or encrypted: logs come back identical after a restart without a WAL, and the compactor's deletion of a stream lists, rewrites and deletes through the gateway. [docs/guides/loki.md](docs/guides/loki.md) says how to set it up; `test/apps/loki` runs it in CI.
- **Mastodon measured, with a guide.** Mastodon 4.7.3 stores its media through the gateway, names in clear or encrypted, and `tootctl media remove-orphans` lists and deletes through it. Mastodon hands browsers unsigned media URLs, which the gateway refuses, so the setup includes a media proxy that signs, nginx-s3-gateway, behind `S3_ALIAS_HOST`. [docs/guides/mastodon.md](docs/guides/mastodon.md) says how to set it up; `test/apps/mastodon` runs it in CI.
- **Velero measured, with a guide.** Velero 1.18.4 with its AWS plugin backs up a namespace through the gateway, names in clear or encrypted, and restores it identical; its backup sync finds backups by listing the bucket, and deleting a backup leaves the bucket empty at the provider. [docs/guides/velero.md](docs/guides/velero.md) says how to set it up; `test/apps/velero` runs it in kind, in CI.
- **A read may set its own response headers.** `GetObject` and `HeadObject` now serve `response-content-disposition`, `response-content-type` and the other four `response-*` parameters, presigned or not, and set those headers on the gateway's response; the provider never sees them. GitLab sends them with every download, which the gateway refused with `NotImplemented` until now ([ADR-032](docs/adr/ADR-032-response-header-overrides.md)).
- **Audit entries can be exported to a SIEM as they are written.** Besides the file, `audit.export` sends each entry over syslog (RFC 5424 over TLS) or OTLP logs over HTTPS, carrying what the file entry carries, its chain and `seq` included, with object names encrypted as in the file. The export is not signed, and verification still runs on the file with `blindbucket audit verify`; it is a copy for search and alerting, sent in batches from a queue that drops entries rather than making requests wait when a receiver is down or too slow. Dropped entries are counted in `blindbucket_audit_export_failures_total`, alerted on by `BlindbucketAuditExportGap`, and found in the SIEM by gaps in `seq` ([ADR-033](docs/adr/ADR-033-audit-export.md), [#135](https://github.com/LennardGeissler/blindbucket/issues/135)).
- **A Homebrew cask, on macOS and Linux.** `brew install --cask lennardgeissler/tap/blindbucket` installs the binary from the release archive, the one the provenance attestation covers, and the completions for bash, zsh and fish. It is in the tap once a release is published, never while it is a draft, and never for a prerelease.
- **The binary is not notarised by Apple, and the cask says so.** Homebrew quarantines a cask's download, which would stop Gatekeeper from running it, so the cask removes the quarantine from that one file. What protects the download is the cask's SHA-256 and the release's attestation, and the caveat it prints gives the command that checks the archive.
- **The Helm chart describes itself for Artifact Hub.** Chart 0.1.6 carries the image it deploys, a category and links to the documentation, the threat model and the format specification, which `ah lint` accepts, and names its maintainer for `helm show chart`. `make chart` fails when the image named there is not the one `appVersion` deploys.

### Fixed

- **A client that closes a download early is no longer an integrity failure.** Nextcloud, among others, reads the start of an object and closes the connection; the gateway logged each one at ERROR as "an integrity or transport failure" and audited it with `IntegrityCheckFailed`. It now tells the two sides apart: a failed write to the client, or a cancelled request, is logged at INFO, and its audit entry keeps the status and the bytes the client was sent, with no code ([#150](https://github.com/LennardGeissler/blindbucket/issues/150)). A chunk that fails authentication is still ERROR and `IntegrityCheckFailed`, and the integrity metric never counted either case.
- **`doctor` names the right fix for a wrong secret or key on Garage.** Garage answers both with `AccessDenied` and says which in the message, and `doctor` told the operator to grant `s3:ListBucket`. It now reads the message, and the CI job against Garage runs `doctor`'s tests, which would have caught it.
- **A first run from the README no longer stumbles where a walkthrough of it did.** `init`'s summary names the binary as it was run, `./bin/blindbucket` after `make build`, where it said `blindbucket`, which is not on `$PATH` after building from a checkout. The configuration it writes bounds presigned URLs to an hour, as the example does, so that `serve`'s first words are no longer a warning about them. For the local MinIO preset it offers the bucket `docker compose up` creates. The README's quickstart says what it needs, starts from `git clone`, and says that `serve` stays in the foreground.

## [1.4.0] — 2026-10-16

**A first run in three commands.** `blindbucket init` writes a configuration, a keyring
and the credentials they reference; `blindbucket doctor` checks a deployment before
`serve` does and names the fix for everything it finds; every error `serve` can stop on
before it listens now says which setting to change; and bash, zsh and fish complete
every command and flag. All of it is additive under
[ADR-021](docs/adr/ADR-021-what-1.0-promises.md), and the format is still `1`.

**Upgrading:** nothing to do for the binaries, the image or the Helm chart. No
configuration that 1.3 started with is refused: the mistakes now caught when the
configuration loads -- an endpoint without `http://` or `https://`, two clients with
one access key -- stopped 1.3 as well, later and less clearly.

### Added

- **`blindbucket init` sets a gateway up in one step.** It writes a configuration, a keyring and `blindbucket.env` into one directory, asking only what it cannot default: the provider (with presets for MinIO, AWS S3, Cloudflare R2, Backblaze B2 and Garage), the bucket, the provider's credentials, the root-key source and whether names are encrypted. A first run is now `init`, loading the environment file, and `serve` ([ADR-030](docs/adr/ADR-030-init.md)).
- **Nothing is overwritten, and nothing that opens the keyring is stored beside it.** If any of the three files exists, `init` writes none of them. The passphrase, a Vault token and KMS keys stay out of `blindbucket.env`; the summary names what `serve` still needs from the environment. The keyring is written last, so a failed seal removes the other two files and never a keyring.
- **`init --non-interactive` for scripts.** It never asks: a missing answer is an error naming the flag or variable that supplies it, and secrets come from the environment, never from flags. The CI job that runs the AWS CLI and boto3 now starts its gateways from the configuration it writes.
- **`blindbucket doctor` checks a deployment and names the fix.** It runs every check on every run, so one run shows everything that is wrong: the configuration, the listener and its TLS certificate, the keyring opened as `serve` opens it, the keys enabled features need, the audit log and rollback index paths, the provider's credentials, each bucket, the provider's conditional writes, and this host's clock. Each finding says which setting, command or permission to change ([ADR-031](docs/adr/ADR-031-doctor.md)).
- **One read per bucket finds most provider mistakes.** A wrong access key, a secret that does not match it, a wrong region (with the region the provider names), a missing bucket and missing list permission each map to the setting they point at. The clock is read from the provider's `Date` header, a warning from one minute's difference and a failure from fifteen.
- **`doctor` writes one small object per bucket, as `probe` does,** to measure the conditional writes rotation relies on, and removes it. `--no-write` skips that check. A provider that ignores the conditions is a warning, since the gateway still serves. `doctor --json` is a stable document listing every check by name, and the exit code is 1 only when a check failed.
- **Shell completions for bash, zsh and fish.** Commands, the subcommands of `keys` and `audit`, every flag, file paths where a flag takes a file, and the values of `--keys-provider` and `--credential-source`. They are in each release archive under `contrib/completions/`. They are written by hand, and a test fails when they and a command's `-h` disagree, so a new flag cannot be forgotten in them.

### Changed

- **Every startup error names what fixes it.** A keyring that is missing, unreadable or not a keyring, a wrong or missing passphrase, a Vault or KMS that will not unseal, a credential source that gives nothing, a port already taken, an audit log or rollback index that cannot be created, and an unset variable now name the setting, command or environment variable to change, not only the symptom. The original error stays in the message.
- **Some mistakes are caught when the configuration loads, with the setting's path.** An `upstream.endpoint` or `keys.vault.address` without `http://` or `https://`, two clients with the same access key, and a client without a name, key or buckets are reported as `clients[1].access_key_id` and the like. Each of these failed before as well, later and less clearly; no configuration that started before is refused now.
- **A TLS certificate that does not load stops `serve` before it listens.** Before, a missing or mismatched `server.tls` file surfaced only after the gateway had logged that it was listening.

## [1.3.0] — 2026-10-14

**Upgrade recommended** where clients use AWS CLI 2.38 or later, or store objects with
`Content-Encoding: gzip`. Against 1.2 and earlier with the default configuration, the
first can neither download nor upload multipart, and the second cannot read such an
object back -- both fixed here (see Changed and Fixed). 1.3 also adds `blindbucket
scrub`, which verifies every stored object without waiting for a read. All of it is
additive under [ADR-021](docs/adr/ADR-021-what-1.0-promises.md), and the format is still
`1`.

**Upgrading:** nothing to do for the binaries, the image or the Helm chart. One
default changes: `UNSIGNED-PAYLOAD` is accepted unless the configuration sets
`allow_unsigned_payload: false`, which keeps refusing it. A listener whose hop in
front of it is plaintext and not trusted should set `require_signed_payload: true`
([ADR-029](docs/adr/ADR-029-unsigned-payloads-accepted-by-default.md)). Building from
source needs Go 1.26.

### Added
- **`blindbucket scrub` verifies stored objects without waiting for a read.** It reads every object under a prefix from the provider, verifies it exactly as a GET through the gateway does, and discards the plaintext. Each object that fails is listed with the kind of check it failed (`chunk`, `header`, `size`, `manifest`, `dek_unwrap`, `metadata`, `unknown_kid`), and the exit code is 1 if any did. Nothing is written, repaired or deleted ([ADR-028](docs/adr/ADR-028-scrub.md)).
- **Concurrent writes are not reported as damage.** A failure counts only once a HEAD shows the object still at the version that failed; an object replaced during the scrub is verified again, one deleted is counted as vanished. Objects the gateway did not write are counted, not failed.
- **`scrub --json` for automation.** A stable document under ADR-021, with every count always present and both the findings and the unreadable objects listed by key. An unreadable object is not to be taken as benign: a provider that sends less than it announces makes a damaged object unreadable.
- **What scrub cannot see.** It checks the version the provider serves now, so an older genuine version passes; rollback detection stays with `freshness.index`. It reads every byte, which on a provider that charges for egress costs what downloading the prefix costs.
- **`server.require_signed_payload` refuses every body the client did not sign.** Both `UNSIGNED-PAYLOAD` and `STREAMING-UNSIGNED-PAYLOAD-TRAILER` are refused, so a body the gateway accepts is covered by the signature even on an untrusted plaintext hop in front of it. The Helm chart has it as `server.requireSignedPayload`. It is demanding: the AWS CLI meets it only over HTTP with `preferred_transfer_client = classic` ([ADR-029](docs/adr/ADR-029-unsigned-payloads-accepted-by-default.md)).

### Changed

- **`UNSIGNED-PAYLOAD` is accepted by default, so AWS CLI 2.38 works.** 2.38.0 made a transfer client the default that sends it on every download and multipart upload, which a default gateway refused. The refusal protected nothing: the CLI's uploads over HTTPS were always unsigned aws-chunked with a CRC trailer, which no setting refused. An explicit `allow_unsigned_payload: false` keeps refusing it; the startup warning now names `require_signed_payload` when a listener carries plaintext beyond loopback ([ADR-029](docs/adr/ADR-029-unsigned-payloads-accepted-by-default.md), [#114](https://github.com/LennardGeissler/blindbucket/issues/114)).
- **The read path's checks are a package of their own.** They moved from the proxy into `internal/verify`, which the gateway and `scrub` both call, so a scrub cannot pass an object a read would refuse. The gateway's behaviour, error messages and metrics are unchanged.
- **Building from source needs Go 1.26.** The floor now follows Go's own support: the oldest Go release the Go team still patches, so it moves with Go 1.28. `golang.org/x/crypto` v0.57.0 already requires it, and with the default `GOTOOLCHAIN=auto` an older `go install` fetches 1.26 by itself. Released binaries and images are not affected.
- **The provenance travels with the release.** Each release now attaches its attestation of the archives and vectors as `blindbucket_<version>_provenance.intoto.jsonl`, so `gh attestation verify --bundle` works without fetching it from GitHub. It is the same attestation that was already stored with GitHub.
- **The supply chain is pinned further.** Both Dockerfiles pin their base images by digest, and the Python the tests install (`cryptography`, `boto3`) is pinned by hash from `requirements.txt` files that Dependabot keeps current. The release workflow's write permissions moved from the whole workflow to the job that publishes, so the tests that run before it hold a read-only token.
- **CodeQL analyses every change.** The Go, the Python and the workflows are analysed on every pull request and weekly, with findings in the Security tab. `osv-scanner.toml` records, with a reason, the one OSV advisory against `go.mod` that does not reach the code (GO-2026-5932, `x/crypto/openpgp`, which is not imported).

### Fixed

- **Objects stored with `Content-Encoding: gzip` read back again.** Since 0.1.0 a whole-object GET of such an object failed with `502 IntegrityCheckFailed (segment header)` and counted in `blindbucket_integrity_failures_total`, because Go's HTTP client gunzipped the ciphertext the provider returned under the stored header. Nothing was damaged: the objects read back once the gateway is upgraded. Ranged reads and other encodings such as `br` were never affected (#110).

## [1.2.0] — 2026-10-10

**Upgrade recommended.** Every release up to 1.1.0 was built with Go 1.24.0 and so
ships the Go standard library of February 2025: `govulncheck` finds 43 known
vulnerabilities reachable from the gateway's code in that toolchain, most of them in
`net/http`, `crypto/tls` and `crypto/x509` -- the HTTP server and TLS stack a client
reaches first. The format's cryptography is not among them, and nothing a release
wrote needs rewriting. 1.2.0 is built with current Go, and its release workflow now
checks that toolchain before it builds (see Fixed).

Beyond that, 1.2 adds `blindbucket inspect`, which reports what a file or a stored
segment claims about itself without a key, as a table or as a JSON document, and
provenance attestations on every release artifact. All of it is additive under
[ADR-021](docs/adr/ADR-021-what-1.0-promises.md), and the format is still `1`.

**Upgrading:** nothing to do for the binaries, the image or the Helm chart. Two
behaviours change at the edges, both towards a clearer answer. With `names.encrypt`
off, a listing the provider refuses as malformed now returns the provider's `400`
and its message rather than `502 InternalError`, so a client that retried on 502
now stops at once ([ADR-027](docs/adr/ADR-027-plaintext-listing-provider-errors.md)).
And an empty multipart part is refused when it is uploaded rather than at
completion, which also refuses an upload that sent an empty part and then left it
out of the completion ([ADR-026](docs/adr/ADR-026-empty-parts-refused-on-arrival.md)).
Building from source needs Go 1.25.

### Added

**`blindbucket inspect` reports what a file or a stored segment says it is, without a
key.** `blindbucket inspect big.tar.zst.bb`, or the same bytes piped in, prints the
segment header's fields -- format version, chunk size, whether the segment is one part
of a multipart object and which part, the salt -- plus the key id a `BBF1` file wraps
its data key under, and the plaintext size derived from the length the way `HEAD`
derives it. Nothing is decrypted and no keyring is read, which is what makes it usable
on an object whose provenance is the question being asked.

What it prints is what the headers claim, not what has been verified: a header is
authenticated together with its chunks rather than on its own. The sizes are arithmetic
on the length, and a length is not a checksum -- bytes appended to a ciphertext usually
read as a sound segment of a different plaintext. A segment the header calls a part is
left without a derived size entirely: a multipart object is its parts concatenated, and
the count of them lives in the manifest rather than the body, so reading the input's
length as one segment reports a number that is wrong by a tag per extra part. A length
no encoder could produce is refused, as is every header field
[section 5.2 of docs/FORMAT.md](docs/FORMAT.md) forbids, with the check that failed
named, and a refusal exits non-zero after printing the fields that did arrive unless
`--json` was given. A multipart manifest (`BBM1`, `BBM2`) is named as what it is and
not reported: it records part sizes rather than a segment header.

`--json` prints the same fields as one JSON document, for a script that checks stored
segments: sizes are numbers, the salt is in full, and `kid` and `envelope_bytes` are
`null` for a raw segment. `plaintext_bytes` is `null` for a part, whose size is not
derived, and `0` only for an empty single-part object. A refused input prints nothing
to stdout, so a consumer that reads only stdout cannot mistake a failure for a result.

**The Helm chart is published**, as `oci://ghcr.io/lennardgeissler/charts/blindbucket`,
starting with chart version 0.1.1 (gateway 1.1.0); until now it could only be
installed from a checkout. A chart version is published once, when main first
carries it, and never again with other contents: CI refuses a pull request that
changes the chart without changing its version, and the publishing workflow
fails on a push to main that does. The values file CI renders with is no longer
part of the packaged chart.

**The network benchmark can run on AWS.** [`deploy/aws-bench/`](deploy/aws-bench/)
is a stack of its own -- an EC2 instance and a bucket in one region, the instance
terminating itself after a set number of hours -- and `bench/aws-run.sh` runs
`bench/warp.sh`'s matrix on it, direct and through a gateway that takes its
upstream credentials from the instance role with `credential_source: imds`.
`bench/warp.sh` gained what a real provider needs: bucket names, TLS, a region,
and credentials refreshed from IMDSv2 before every direct run. Results go to a
bucket of their own: in the one warp runs against, the next run deleted them.
The gateway in the benchmark accepts `UNSIGNED-PAYLOAD`, because warp, built on
minio-go like `mc`, sends it for every multipart upload.

**Releases carry provenance attestations.** Every archive and test vector listed in
`checksums.txt`, and the container image by the digest of its multi-arch index, gets a
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) statement signed with a
certificate Sigstore issues to the release workflow and recorded in its public log.
`gh attestation verify <file> --repo LennardGeissler/blindbucket` checks that a
download was built by that workflow from a tagged commit of this repository, which
`checksums.txt` cannot show on its own: it travels with the files it describes. The
release page says how. Releases up to 1.1.0 have no attestations. What it does not
cover: a compromise of the workflow itself, or of the commit it builds, is attested
like anything else.

### Changed

**Building from source needs Go 1.25.** `golang.org/x/crypto` v0.52.0 requires it, so
the module's floor moves from 1.24 with the update. With Go's default
`GOTOOLCHAIN=auto`, an older `go install` fetches 1.25 by itself; with
`GOTOOLCHAIN=local` it refuses and says which version it needs. Released binaries and
images are not affected: they are built with current Go. The update clears the 13
advisories GitHub lists against `x/crypto` v0.45.0. None of them touched blindbucket --
all are in the SSH packages, and the gateway imports only `argon2` from that module,
where `govulncheck` finds no affected call -- so no earlier release needs replacing
on their account.

### Measured

**The gateway against AWS S3 over a real network (M9).** From a c7g.2xlarge in
eu-central-1 to S3 in the same region, three repetitions per cell: through the
gateway, 1 KiB objects move at 92–99 % of the direct path, about 0.3–0.6 ms
added to a read and 1.2–2.1 ms to a write against S3's own 23.5 ms; 10 MiB and
1 GiB objects at 99–101 % wherever the network is the limit, with the gateway
encrypting some 1.8 GB/s at 64 clients. The tail at saturation is where it
costs: a 10 MiB PUT's p99 at 64 clients goes from 0.56 to 1.26 s. Some upload
cells run faster through the gateway (up to 114 %), and that is the HTTP
client, not the gateway: its upstream client sends `Expect: 100-continue`,
warp's does not, and S3 takes a 10 MiB PUT in 128 ms with the header against
143 ms without. The laptop measurement had put 1 KiB uploads from one client at
70 % of direct; here they are at 92 %. Figures, raw output and method in
[bench/figures/aws/](bench/figures/aws/). This is also the first use of
`credential_source: imds` against real IMDS rather than a stub.

**Litmus tests for S3-compatible stores.** `test/litmus/` measures, with a
fixed request sequence per property and no SDK in between, what a store does
with conditional writes and with two overlapping writes to one key. Against
MinIO, Garage v2.4.1 and SeaweedFS 4.48, five repetitions each: Garage accepts
`If-None-Match` and `If-Match` on `PutObject` and on `CompleteMultipartUpload`
and ignores them, answering success; the other two enforce them. On overlap,
Garage keeps the write that began last and refuses the other; MinIO and
SeaweedFS keep the one that completed last. AWS S3 enforces every condition
and keeps the write that began last, like Garage, but answers the loser `200`.
`test/providers/seaweedfs.sh` starts the third store.

**The laptop figures, again, with their raw output.** Cipher throughput, the
10 GiB heap, the freshness index, the sorted listing and the audit log, six runs
each, and a thousand-object rotation three times, all in
[bench/figures/local/](bench/figures/local/). Most moved by a few per cent; the
README now quotes 7.1 and 6.9 GB/s. The rotation did not: it moves 2598 bytes per
object where it moved about 1500, and running the test either side of ADR-025
puts all of it on the `ListMultipartUploads` a rotation now makes per object so
as to give way to a client's upload.

**OpenBao works as a root-key source, unchanged.** OpenBao, the open-source fork
of Vault, serves the same Transit API, so `provider: vault` pointed at it is all
it takes. Measured with OpenBao 2.7.1: a keyring sealed by it, a gateway started
with no passphrase that round-trips a multipart object and reads it back after a
restart, and a deleted Transit key refusing the next start. CI now runs the
root-key, `keygen` and `reseal` tests against OpenBao as well as Vault on every
commit.

### Fixed

**Every release so far was built with Go 1.24.0.** The release workflow installed Go
from `go.mod`, whose `go 1.24.0` is the oldest Go the module builds with, and read it
as the exact version to use. So every binary and image from 0.1.0 to 1.1.0 carries the
standard library of February 2025, without the fixes Go has shipped since. `govulncheck`
run against the source with Go 1.24.0 finds 43 of those vulnerabilities reachable from
the gateway's own code, most in `net/http`, `crypto/tls` and `crypto/x509`: HTTP/2
memory exhaustion, connection desynchronisation, certificate parsing. The cryptography
of the format is not involved -- AES-GCM, HKDF and the key wrapping are unaffected, and
nothing written by an affected release needs rewriting -- but the HTTP server in front
of it is the part a client reaches first. CI never saw it: its `govulncheck` ran with
current Go, which is not what the release was built with.

Releases are now built with current stable Go, and `govulncheck` runs in the release job
against that same toolchain before anything is built. The module's floor stays 1.24 and
is still tested, before every release as well. `deploy/Dockerfile`, the image built
from source, moves from Go 1.25, which no longer receives fixes, to 1.27. A binary built
with `go install` was never affected: it uses whichever Go installs it.

**Empty multipart parts are refused when they arrive.** `UploadPartCopy` from
an empty object and `UploadPart` with an empty body now return `InvalidRequest`
with the same explanation completion already gave, before storing or replacing
a part. Small nonempty parts still work as the last part; empty objects written
with `PutObject` or copied with `CopyObject` are unaffected. The wire format is
unchanged ([ADR-026](docs/adr/ADR-026-empty-parts-refused-on-arrival.md)).

**`UploadPartCopy` comment still said name encryption refused it.** The gate in
`names.go` already lets `UploadPartCopy` through, integration tests exercise both
copy paths, and COMPATIBILITY.md says the same; the comment above `storedKey` in
`copypart.go` still described a refusal that had been lifted. It now states in the
present tense why the source key goes through `storedKey`. No behaviour change.
Released changelog sections that recorded the old refusal are left as the record
of those releases.

**A provider's refusal of a plaintext listing is reported as client input.**
With name encryption off, a provider 400 reaches the client as 400 with the
provider's code and message, rather than `502 InternalError`. This includes
MinIO's refusal of `prefix=.`. Listings with name encryption on, other operations
and other provider statuses keep their existing error handling
([ADR-027](docs/adr/ADR-027-plaintext-listing-provider-errors.md)).

**Every GitHub release went out without notes.** goreleaser's changelog had been
switched off since 0.1.0, so that a list of commit subjects would not stand in for
this file -- and nothing put this file in its place, so each release said how to
verify a download and nothing about what it contained. The release workflow now
renders the release's section of this file with `build/releasenotes`: paragraphs
joined into single lines, because a release page breaks a line wherever the file
does, and links pinned to the tag, because a release page has no repository root
to resolve them against. A tag this file does not describe stops the release
before anything is published. The footer goreleaser adds is now one line per
paragraph for the same reason. Every existing release has been given its notes,
except v0.3.0, which had hand-written ones; those were only joined into lines.

**Documentation figures that had gone stale, or said more than was measured.**
The README and `spec/tla/README.md` still counted five configurations, or four
that must fail, where `make tla` runs thirteen and eleven must fail; the README
now also gives the size of the check that holds the fixed rules, two uploads in
about 8.7 million states. Goals G1–G7, which the ADRs argue from, were defined
only in the design document removed in 0.1.0; [docs/adr/README.md](docs/adr/README.md)
now lists them, each with its criterion and where it stands, G3 and G7 included
where they are not met as worded. FORMAT.md's last-updated line predated section
10.7's change for ADR-025; the threat model called size padding a deferred M6
option after M6 closed without it; COMPATIBILITY.md said `mc` had not been
re-measured since 0.2.0 above a table dating it 2026-09-28. Two figures in earlier
entries of this file are corrected here rather than rewritten there: the 0.4.0
entry's "about 2.3 seconds to the first page against a same-region provider" is
the gateway's measured CPU time plus an assumed 20 ms round trip, not a network
measurement ([ADR-017](docs/adr/ADR-017-listing-order-under-name-encryption.md));
and the copy Garage refuses, in the 0.5.0 entry, is one from a source stored
inline, under 3072 bytes, not under 5 MiB
([ADR-020](docs/adr/ADR-020-conditional-writes-measured.md)). The 5 MiB bound in
`CopyObject` stays, because it is S3's.

## [1.1.0] — 2026-10-03

Three things 1.0 could not do: move a bucket to encrypted names, move a keyring
to another root-key source, and run on AWS without a long-lived key. All of it is
additive under [ADR-021](docs/adr/ADR-021-what-1.0-promises.md) — new commands,
new configuration keys, one new `--json` field — and the format is still `1`.
Among the fixes, two matter to 1.0 users in particular. Against AWS, two
overlapping uploads of one key could leave an object no read could open, because
AWS does not keep the write the gateway assumed it kept
([ADR-025](docs/adr/ADR-025-writes-rank-by-when-they-began.md)); the AWS workflow
run for this release found it. And the AWS CLI's uploads to a gateway serving
HTTPS were refused.

**Upgrading:** `rotate` and `migrate-names` now list a key's open uploads before
publishing a copy, so the credentials they run with need
`s3:ListBucketMultipartUploads` on the bucket, as `gc`'s already did. Without
it every object is reported as failed and left as it was.

### Added

**The AWS credential chain, without the SDK.** The upstream and KMS sections
take `credential_source` instead of keys: `env`, `profile`, `web_identity`
(IRSA, any OIDC federation), `container` (ECS task roles, EKS Pod Identity),
`imds` (the EC2 instance role) or `chain`. Credentials that expire are refreshed
in their last five minutes, and while a refresh fails the ones still valid keep
being used, so a key service having a bad minute does not fail requests. The
SDK's own resolver would have added twelve modules; this one adds none
([ADR-024](docs/adr/ADR-024-aws-credentials-without-the-sdk.md)).

Where it differs from the SDK it does so on purpose. `chain` decides by what is
configured and never falls through when the source it chose fails -- on EKS that
fall-through is how a pod with a broken IRSA setup ends up with its node's
role. IMDS is asked only with a version 2 session token. A profile may hold
keys, a role with a `source_profile`, or a role with a
`web_identity_token_file`; SSO and `credential_process` are refused with the
reason. Keys and a source together are an error, and so is neither: a
forgotten key does not quietly become whatever the environment offers. `serve`
asks the source once at startup and names it in the log, so a role that cannot
be assumed stops the start rather than the first request.

Web identity is measured against real STS by the manual AWS workflow, with the
job's GitHub OIDC token in IRSA's place; IMDS on EC2 and Pod Identity on EKS are
tested against stubs of their protocols, not measured.

**`blindbucket reseal`** moves a keyring between a passphrase, Vault Transit
and AWS KMS, in any direction, and changes a passphrase. The keys inside are
the same bytes before and after, so no object is touched. Until now there was no
way to do this at all: the documentation suggested creating a new keyring and
rotating objects onto it, which cannot work -- rotation needs the old keys in the
keyring it runs against, and a new keyring would also have brought a new name key
and a new audit key.

Before it replaces the file, reseal opens what it wrote with the new source and
compares it key by key with what it read, so a source that seals and will not
unseal -- a KMS key policy or Vault policy allowing encrypt and not decrypt -- is
caught with nothing written; `--dry-run` asks exactly that and stops. There is no
backup, because a backup is a second way into the same keys, and every old copy
of the file still opens with the old source: against a passphrase or root key
that may have leaked, the remedy is still a new KEK, `rotate` and `keys remove`
([ADR-023](docs/adr/ADR-023-resealing-a-keyring.md)). A new passphrase is never
read from `$BLINDBUCKET_PASSPHRASE`, which holds the current one, and one equal
to the current one is refused. Tested against Vault -- including a token allowed
to encrypt and not to decrypt -- and the KMS emulator; the manual AWS workflow
reseals its KMS keyring to a passphrase and back.

**`blindbucket migrate-names`** moves a bucket written before `names.encrypt`
was switched on to the keys its objects have with it on — the limitation
"there is no migration command" since `v0.4.0`. It is a rename at the provider,
not a re-encryption: each object keeps its data key, its KEK and its ciphertext,
and a megabyte of objects costs about ten kilobytes on the wire. Switch every
gateway instance to `names.encrypt: true` first, then run it; a real run under a
configuration that does not encrypt names is refused, and a `--dry-run` works
either way. An interrupted run is finished by the next one, which reports the
objects it found already copied as `resumed`.

Its limits, stated in [ADR-022](docs/adr/ADR-022-migrating-to-encrypted-names.md)
and each pinned by a test: an object not yet migrated is invisible to clients
until the run reaches it, and a delete of such an object does not reach it — the
migration brings it back. A write through an instance still serving names in
clear during the run is lost. A client writing an object's encrypted key during
the run keeps its write: the copy is published with `If-None-Match`, which the
run measures first and refuses to start without, as rotation does — so on Garage
v2.4.1, which ignores it, a migration needs `--allow-unconditional`. A key too
long to encrypt, or an object at the encrypted key that is not newer than the one
in clear, is reported and left, and makes the command exit 1. On a versioned
bucket the names stay in earlier versions. `--json` prints a document of its own,
under ADR-021's rules for the others.

The design was model-checked before it was written:
[`spec/tla/Migrate.tla`](spec/tla/Migrate.tla) holds over 3.1 million states and
has a counterexample for each alternative it rejects, including the run that dies
between publishing the copy and deleting the key in clear.

**`probe` measures a third condition**, `If-None-Match` on
`CompleteMultipartUpload`: the one guard a name migration relies on, so that a
client writing an object's encrypted key before the migration's copy lands there
keeps its write ([ADR-022](docs/adr/ADR-022-migrating-to-encrypted-names.md)).
`probe --json` gains a `migration` field with its own `checks` and `guarded`;
`checks`, `guarded` and the exit status keep answering for rotation alone, as
ADR-021 holds them. Measured on 2026-10-02: MinIO enforces it, Garage v2.4.1
ignores it. Every probe, and so every rotation, makes three or four more
requests.

**`make help`.** Lists documented Makefile targets by section without changing
what a bare `make` runs.

**Prometheus alerting rules.** `deploy/prometheus/alerts.yaml` alerts on
integrity failures, an unwritable audit log and gaps in it, an unreachable
gateway, a 5xx rate over 5 % and a key-encryption key older than a year.
`make alerts` checks them with promtool and replays series against each, and CI
runs it. A Go test holds every metric the rules name to the metric contract of
ADR-021, which promtool's own tests cannot do.

**Coverage, measured and held.** The MinIO integration job now measures
statement coverage of the production code, with Vault and the KMS emulator up
so that the root-key tests count too, writes the total to the job summary and
fails below 82 %. Measured with Go 1.24, the declared floor: 70.9 % when first
measured, 77.0 % with tests for the audit CLI, `serve` and `keygen`, 80.3 %
once test helpers left the denominator and the root-key tests were counted, and
83.8 % with tests that fail the provider at each step of an operation. What
remains is mostly defensive: a failing random source, a key wrap that cannot
fail with a valid key, the terminal prompt. A
push to `main` publishes it as the README's badge through a `badges` branch that
holds one commit. `make cover` measures the same way.

**A Helm chart.** `deploy/helm/blindbucket` runs the gateway as a shared service
other pods reach over the network. That shape puts plaintext on the wire, so the
chart serves S3 over TLS only and refuses to render without a certificate, and
it creates no Secrets: keys and credentials are referenced by name. Optional
NetworkPolicy, ServiceMonitor and PrometheusRule, the last carrying the rules
from `deploy/prometheus`. The audit log and rollback detection are left out,
since each needs a file per instance that outlives the pod. `make chart` lints,
renders and validates it; `make chart-e2e` installs it in kind and has the AWS
CLI put a multipart object through it over TLS, then checks that MinIO holds
ciphertext. Both run in CI. On EKS it needs no AWS key in a Secret: a ServiceAccount
carries the IRSA role or the Pod Identity association, and `credentialSource`
names where the gateway takes its credentials from (ADR-024).

### Measured

**Against AWS, before the tag.** The manual AWS workflow ran three times for this
release, and the first two failed for reasons worth having found: the fault
tests could not reach a provider addressed by virtual host (#60), a condition
AWS enforced read as refused (#62), and AWS keeps a different write than the
gateway assumed (ADR-025). The third,
[37133982130](https://github.com/LennardGeissler/blindbucket/actions/runs/37133982130),
ran on the code this release ships and passed every step. Those steps were:
the integration suite against S3 in eu-central-1; the KMS root-key tests; boto3
and the AWS CLI through a gateway whose keyring KMS seals, before and after a
restart; a reseal of that keyring from KMS to a passphrase and back, with an
object written before it still read after; and, for the first time, a gateway
that takes its upstream and KMS credentials from web identity. That gateway
exchanged the job's GitHub OIDC token at STS where IRSA's would be, and passed
a 40 MiB AWS CLI round trip.

### Fixed

**Two commands writing one keyring could lose a key.** `keygen --add`,
`keygen --add-*-key` and `keys remove` each read the keyring, change it in
memory and write it back, so two of them run at once each wrote what they had
read, and the second silently dropped what the first added -- a lost KEK is every
object wrapped under it. A keyring is now replaced only if the file still holds
exactly what the command read; otherwise nothing is written and the command
says to run again. The check runs just before the rename, which narrows the
window rather than closing it; a lock file would close it, and a crash would
leave that behind. Writes are also synced, the file and then its directory, so a
power cut can no longer leave a keyring of the right name and no content, and
`keygen` creating a keyring no longer replaces one that appeared after it
checked.

**`rotate --to-kid` accepted a key the keyring does not hold.** Only the id's
syntax was checked, so a typo made a dry run report every object as rotatable
onto a key that does not exist, and a real run fail each object in turn --
nothing was written, but nothing said why until the end. The command now
refuses up front and names the key.

**`rotate` dropped three of an object's headers.** Since 0.1.0 the copy it
writes carried `Content-Type`, `Cache-Control` and the client's metadata, but
not `Content-Disposition`, `Content-Encoding` or `Content-Language`: a rotated
object downloaded under a different file name, or without the encoding a
browser needed to read it. The bytes and their key were never affected. Writing
`migrate-names`, which carries all five, found it
([ADR-022](docs/adr/ADR-022-migrating-to-encrypted-names.md)); rotation now
carries them too, and a test holds it to that on the guarded path and on both
unconditional ones. An object rotated by an earlier build has lost them, and
nothing else records them -- they have to be set again, for instance with a
copy of the object onto itself that replaces its metadata.

**The AWS CLI could not upload over HTTPS.** Over HTTPS the CLI sends
`STREAMING-UNSIGNED-PAYLOAD-TRAILER`: aws-chunked, with its checksum in a
trailer that follows the final `0` chunk directly. The decoder expected a CRLF
after that chunk as if it carried data, and refused every such body with
`IncompleteBody`. Every client measurement so far had been over HTTP, where the
CLI signs the whole body instead, and the tests built their bodies with an
encoder that made the same mistake -- so the two agreed and the defect never
showed. The Helm chart's test found it. A test now holds the decoder to the
literal bytes the CLI sends, captured from 2.37.4.

**The sidecar example could not read its own keyring.**
`deploy/kubernetes-sidecar.yaml` mounted the keyring Secret with mode `0400`,
owned by root, into a container that runs as UID 65532. The pod now sets
`fsGroup: 65532` and the mode is `0440`. The chart's test found this in its own
templates first.

**The first integrity failure was invisible to `increase()`.**
`blindbucket_integrity_failures_total` created a series for a kind only at that
kind's first failure, so the series began at 1 and an alert on its increase
stayed silent until the second. Every kind is now exported at zero from
startup. No metric, type or label changes.

**The README's key-age query took `max` where it meant `min`.** `time() - max(...)`
over the key creation timestamps is the age of the newest key, not the oldest.

**On AWS, two overlapping uploads of one key could leave an object nobody can
read.** AWS keeps whichever write *began* last, and answers a completion it then
discards with a success. Upload B, created after A and completed before it,
stayed visible; A's completion, discarded, deleted B's manifest as the version
it had replaced -- and every read of B failed with `IntegrityCheckFailed`. The
data was intact but unreachable through the gateway. A completion now deletes
the manifest it observed only once a HEAD shows that version replaced, and does
not record a discarded write for rollback detection. Present since 0.1.0, in
every release. Of the providers measured only AWS produces it: MinIO keeps the
write that lands last, and Garage refuses the outranked completion. The AWS workflow
found it on 2026-10-03, the model now reproduces it in twelve states, and
[ADR-025](docs/adr/ADR-025-writes-rank-by-when-they-began.md) records what was
measured on each provider.

**On AWS, `rotate` and `migrate-names` could make a client's upload disappear.**
For the same reason: a client upload created before the command's copy of that
object and completed after it was discarded in the copy's favour, after the
client had been told it succeeded. `If-Match` and `If-None-Match` cannot see an
upload still in flight. Both commands now give way: before publishing a copy
they list the key's open uploads and leave the object if there is one --
`rotate` counts it as conflicted, `migrate-names` as failed with the reason --
and the next run handles it. Both therefore need `s3:ListBucketMultipartUploads`,
as `gc` already did. A PUT is not affected: AWS ranks it when its body has
arrived, so it outranks any copy it outlasts. Two runs of one command over the
same objects at once now take each other's copies for client uploads: where they
meet, both leave the object for the next run instead of one finishing it.

**On AWS, a condition that held could read as a provider failure.**
`CompleteMultipartUpload`, `CopyObject` and `UploadPartCopy` may answer `200 OK`
and put the error in the body, and AWS does so with a failed `If-Match` or
`If-None-Match` once a completion has started streaming. Such an error was given
the status 500, and a `PreconditionFailed` is recognised by its 412 — so `probe`
could report a condition AWS enforces as `refused`, which stopped rotations and
migrations from starting; a guard that fired during `rotate` or `migrate-names`
was counted as a failed object instead of one that changed under it; and a
server-side copy whose source changed while it was copied answered 502 instead
of `PreconditionFailed`. Nothing was written
that should not have been: AWS had refused the write. `PreconditionFailed` and
`ConditionalRequestConflict` inside a 200 now carry 412 and 409. Found by the AWS
workflow on 2026-10-03, where `probe` measured the same condition as enforced in
one run and refused in the next.

**The threat model left three headers off what the provider sees.**
`Content-Disposition`, `Content-Encoding` and `Content-Language` have been
stored in clear, as the client sent them, since 0.1.0;
§4 named only `Content-Type` and `Cache-Control`. It now names all five, and says
what that means under `names.encrypt`: a file name a client puts in
`Content-Disposition`, or a path in user metadata, is not hidden by encrypting
the key. Nothing in the gateway changed.

## [1.0.0] — 2026-09-27

The release that says what it promises. Nothing in the format changes: format
`1` has been written by every release since `v0.1.0`, and what `1.0.0` adds is
that this is now a commitment rather than a habit.

### Changed

**The stability promise of [ADR-021](docs/adr/ADR-021-what-1.0-promises.md)
takes effect.** Three tiers. Data at rest — segments, manifests, upload tokens,
the name mapping, the audit log, the keyring and the freshness index — is read
by every later release, and a 1.x release writes a new format only when the
configuration asks for it, so two 1.x versions in a rolling upgrade read each
other's writes. Configuration keys, CLI commands, flags and exit codes, the
`--json` documents, metric names, types and labels, `/healthz`, `/readyz` and
`/metrics`, and `IntegrityCheckFailed`, `RollbackDetected` and
`ObjectNotEncrypted` change incompatibly only in a major release; a consumer of
`--json` ignores fields it does not know. The Go API, log lines and text output
are not promised. The data at rest, the `--json` field sets and the metrics are
pinned by tests: the upgrade test, the field-set tests, `TestMetricsAreAContract`.

**Format `1` is stable** in [docs/FORMAT.md](docs/FORMAT.md) §16, no longer a
draft.

**Supported versions** in [SECURITY.md](SECURITY.md): the latest 1.x minor.
From 2.0 on, the last minor of the previous major keeps receiving security
fixes for six months.

### Measured

**A KMS-sealed gateway against AWS, end to end.** The manual AWS workflow now
runs boto3 and the AWS CLI through a gateway whose keyring AWS KMS seals and
whose upstream is the real bucket, and restarts it to open the keyring again
([docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)). Passed on 2026-09-27.

### Fixed

**Root-key credentials can be referenced, as the example always showed.**
`keys.vault.token` and `keys.awskms.access_key_id`, `secret_access_key` and
`session_token` now resolve a `${VAR}` reference like the upstream and client
credentials do. Before, only those were resolved: the Vault token and the KMS
credentials had to be written into the file, and the `${VAULT_TOKEN}` that
`blindbucket.example.yaml` shows was sent to Vault as the literal string. The
example's `${VAULT_ADDR}` was never resolved either, and an address is not a
secret, so it is now written out.

## [0.6.0] — 2026-09-27

### Added

**Build information in metrics and the startup log.**
`blindbucket_build_info{version,go_version}` is a gauge fixed at 1, so dashboards
can identify the running gateway and its Go toolchain without parsing logs.
It is present before any traffic; development builds report `version="dev"`,
matching `blindbucket version`. The existing startup log also carries `version`.

**`blindbucket probe`.** Measures what a provider does with the two
conditional writes rotation relies on — the same measurement a rotation makes
before it starts ([ADR-020](docs/adr/ADR-020-conditional-writes-measured.md)),
without the rotation. Prints each as enforced, ignored or refused, or emits
JSON with `--json`, and exits 1 where a guarded rotation would be refused, so a
script can ask the question. Needs the configuration, not the keyring.

**`blindbucket gc --json`.** The collection summary as one JSON document, for
the runs that are on a timer. Every count is always present, zero included, so
a parser never has to tell zero from absent; `dry_run` is a field instead of
the verb changing between "deleted" and "would delete"; the start is RFC 3339
UTC and the duration a number of seconds. A run that could not process every
manifest still prints its document, with the failure in a non-zero exit code
and in `errors`, because the counts are what a monitoring system most needs
when something went wrong.

**`blindbucket rotate --json`.** The rotation summary in the same shape as
`gc --json`, and decided the same way on a partial failure. The target key id
is a field of its own rather than a quote inside the verb line, since it is
what the run was for, and `conflicted` above zero is the answer to "does this
need running again". `unconditional` records whether the run gave up the
guards.

**Every release carries the test vectors.** `segment_v1.json` and
`names_v1.json`, the known-answer vectors of `docs/FORMAT.md` §13 and §15.6,
are attached to each release and listed in `checksums.txt`, for anyone
testing a second implementation against format 1. They are named by the
format version they pin rather than by the release, because they are the same
files in every release that writes that format.

**`--json` help says to ignore fields you do not know**, in all four commands
that have it. Later releases may add fields to a document; they never remove,
rename or retype one (ADR-021).

### Fixed

**`blindbucket help` no longer lists `inspect` as planned for M6.** M6 closed
without it.

## [0.5.0] — 2026-09-25

### Added

**`blindbucket keys list --json`.** The key listing can be emitted as
structured JSON, for scripts and scheduled rotation checks. Timestamps are
UTC RFC 3339 and every entry carries the key's age in seconds and whether it
is active; a key with no recorded creation time has `null` for both rather
than a zero date. Warnings stay on stderr, so stdout is only the document.

**A rotation measures the provider's conditional writes before it starts.**
`blindbucket rotate` guards two windows with a precondition each, and a
provider that ignores one looks exactly like one that allowed the write. Garage
v2.4.1 ignores `If-Match` on `CompleteMultipartUpload`, so until now a rotation
there could replace a client's concurrent write with the pre-rotation version
and report success. A run now checks both preconditions against the provider
with a probe object under `.blindbucket/probe/`, and refuses to start unless
both are enforced, naming the one that is not. `--allow-unconditional` skips the
check along with the guard. A dry run checks too. See
[ADR-020](docs/adr/ADR-020-conditional-writes-measured.md).

### Changed

**`blindbucket rotate` can now refuse to start where it used to run.** On a
provider that ignores or refuses either conditional write — Garage v2.4.1 among
them — a rotation exits with an error naming the missing guard. That run was
never safe; it now says so. Rotating there takes `--allow-unconditional`, with
nothing writing to the prefix meanwhile.

**`docker compose` takes MinIO from `cgr.dev/chainguard/minio`.** MinIO stopped
publishing images, and `quay.io/minio/minio` now answers 401. Chainguard's is
MinIO built from source, and carries `mc` too.

**A small single-part object with nothing to guard is copied with
`CopyObject`.** Under 5 MiB, for a server-side copy and for a rotation under
`--allow-unconditional`, one request replaces a one-part multipart upload.
Garage refuses to copy a source that small into a part, so such copies failed
there. A guarded rotation keeps the multipart path, where its second
precondition lives.

### Fixed

**`GetObjectTagging` against a provider without tagging.** Garage answers
`NotImplemented`, which the gateway passed on as a 502 — and the AWS CLI asks
for an object's tags before every multipart server-side copy, so the copy
failed. A provider that does not implement tags holds none, so the gateway now
answers with the empty set, which is the true answer rather than an invented
one. Found by the first run of the integration suite against Garage.

## [0.4.0] — 2026-09-16

### Added

**Rollback detection: the gateway can now tell that a provider served an older
but genuine version of an object.** That was the one row in the threat model's
risk table that said **No**, deferred to M6 by ADR-002 in M0 and explicitly
declined by ADR-016. It is the last one.

Off by default. Set `freshness.index` to a path and add a key with
`blindbucket keygen --add-freshness-key`. What is recorded per object is a hash
over its segment salts — which `FORMAT.md` §4.1 already requires to be fresh per
write and authenticates as associated data of every chunk, so a provider cannot
forge one and can only serve a whole genuine segment, which is the attack. The
check runs where ADR-014's salt comparison already runs: after the header is
authenticated and before any plaintext is released. A mismatch answers
`RollbackDetected` (502) rather than `IntegrityCheckFailed`, because nothing
failed authentication — the bytes are genuine, they are simply not current. A
suppressed `DeleteObject` is caught the same way, through a tombstone.

**Nothing in the wire format changed.** Objects written by every previous version
are covered the moment an index records them, and objects written with this on
are readable by a gateway without it. `blindbucket rotate` costs the index
nothing either: ADR-009 re-wraps metadata without moving ciphertext, so the salts
and therefore the tags are untouched. That is why the tag covers salts rather
than the wrapped data key, and there are integration tests for both halves of it.

**The limits are part of the feature and are stated everywhere it is documented.**
The first read of any object is unchecked — an index that has just been created,
or lost, trusts what it is shown. A server-side copy leaves its destination
unchecked until it is read once. `HEAD` is never checked, because it reads no
body. And a tag says *which* write, never *which is newer*, so in a deployment
where several instances write the same objects a peer's legitimate write is
indistinguishable from a rollback — which is why this is off by default and why
the store is an interface with room for a shared implementation.

It costs memory proportional to live objects, about 112 MiB per million and
897 MiB for ten, which is a shape of cost nothing else in this gateway has. A
read pays 279 ns against the 0.13 ms a request already costs; a write pays 21 µs,
almost all of it an amortised fsync. Full reasoning, alternatives and the
measurements in [ADR-018](docs/adr/ADR-018-rollback-detection.md).

**Presigned URLs are verified, which closes M6.** A client signs a URL offline
with credentials it already holds; whoever receives it can make that one request
until it expires, with no credential and no SDK. The gateway never issues one —
presigning is a local computation, so there was never anything to build on that
side — and it verifies them on by default, because this removes a refusal of
something every S3 client expects rather than adding a cost.

**Reads only.** `GET` and `HEAD` are served; every other operation a presigned URL
can name is refused with `AccessDenied`. The argument is the accident rather than
the attacker: a URL is where a bearer credential gets copied — browser history,
`Referer` headers, chat previews, CI logs — and a link preview that issues a `GET`
is a `GET`, while one that issues a `DELETE` is data loss with nobody hostile in
the story. Presigned `PUT` is deferred rather than refused permanently; presigned
POST is a different protocol and is not planned.

Expiry is a window and not a clock-skew bound, which is the part that had to be
right: a presigned URL is meant to be used long after it was signed, so the
fifteen-minute rule that governs header-signed requests would have refused every
one of them. `server.presign.max_expiry` caps the window and defaults to S3's own
seven days; most deployments should set something far shorter.

A presigned read is an ordinary read once authenticated, so it inherits rollback
detection, the audit log, fail-closed and name encryption without any of them
being taught about presigning. What it does leak is the object's name: the
plaintext key is in the URL, which `THREAT_MODEL` §4 now says. Full reasoning in
[ADR-019](docs/adr/ADR-019-presigned-urls.md).

### Fixed

- **boto3 presigns with SigV2 by default against a custom endpoint**, and the
  gateway answered `the sub-resource "AWSAccessKeyId" is not implemented` — a
  symptom nobody can act on. It now answers `InvalidRequest` naming
  `Config(signature_version="s3v4")`. Found by pointing real boto3 at it; SigV2
  itself stays unsupported.
- The roadmap in `README.md` still described the audit log as unreleased, eleven
  lines below a status banner announcing it in `v0.3.0`.
- A comment in `internal/proxy/copy.go` still said `CopyObject` was refused while
  object names are encrypted. It has been served since `v0.3.0`.

## [0.3.0] — 2026-09-16

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

### Known limitations

- **Object-name encryption is not a toggle.** An object lives at the encrypted
  form of its key, so turning `names.encrypt` on hides everything written before
  it and turning it off hides everything written since. There is no migration
  command; moving an existing bucket across is a rewrite of every object's key.
- **"Encrypted" names are confirmable by guessing, not unguessable.** The mapping
  is deterministic, because a client naming one object has to reach it in one
  request with no index. Deterministic encryption never hides equality, and
  equality is what confirms a guessed name. `THREAT_MODEL` section 4 states what
  is and is not hidden, and it is the paragraph to read before switching this on.
- **A listing is bounded.** The provider orders by the encrypted key, so a prefix
  is read whole and sorted before any of it is served. Past
  `names.max_listing_keys` (default 100 000) a listing is refused rather than
  answered in an order the client cannot use.
- **Key length under name encryption** depends on a key's shape rather than a
  single multiplier: 624 bytes of plaintext key for one long segment, 128 for a
  path of four-character ones, because the synthetic IV is charged per segment. A
  key past the limit is refused with `KeyTooLongError`.
- **No `blindbucket reseal`.** Moving a keyring from one root-key source to
  another still means creating a new keyring and rotating objects onto it.
- **Presigned URLs** are refused, and **rollback to an older genuine version of an
  object is still not detectable** — the audit log, despite the name, does not
  change that (`THREAT_MODEL` section 5.1).
- **Object tags** are refused rather than stored, because the provider would hold
  them in the clear.
- **The audit log is per instance**, has no cross-instance order, and entries
  after its last checkpoint are chained but unsigned. All three are by design and
  recorded in [ADR-016](docs/adr/ADR-016-audit-log.md).
- **One benchmark cell** — 10 MiB uploads at 64 concurrent clients — runs at 18 %
  of the direct path. The gateway's share is measured at 0.13 ms per request, so
  the time is the provider's; why it behaves that way under this access pattern
  is not established.

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

[Unreleased]: https://github.com/LennardGeissler/blindbucket/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/LennardGeissler/blindbucket/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.6.0...v1.0.0
[0.6.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LennardGeissler/blindbucket/releases/tag/v0.1.0
