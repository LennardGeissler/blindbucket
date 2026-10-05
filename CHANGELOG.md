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

**OpenBao works as a root-key source, unchanged.** OpenBao, the open-source fork
of Vault, serves the same Transit API, so `provider: vault` pointed at it is all
it takes. Measured with OpenBao 2.7.1: a keyring sealed by it, a gateway started
with no passphrase that round-trips a multipart object and reads it back after a
restart, and a deleted Transit key refusing the next start. CI now runs the
root-key, `keygen` and `reseal` tests against OpenBao as well as Vault on every
commit.

### Fixed

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

[Unreleased]: https://github.com/LennardGeissler/blindbucket/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/LennardGeissler/blindbucket/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.6.0...v1.0.0
[0.6.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LennardGeissler/blindbucket/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LennardGeissler/blindbucket/releases/tag/v0.1.0
