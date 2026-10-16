# ADR-031 — `doctor` runs every check, and each finding names its fix

**Status:** Accepted
**Date:** 2026-10-16
**Milestone:** M11
**Implements:** `internal/doctor`, `cmd/blindbucket` (`doctor`), `upstream.DefaultHTTPClient` ([#120](https://github.com/LennardGeissler/blindbucket/issues/120))

## Context

When a deployment does not work, `serve` stops at the first thing wrong, or
starts and fails on the first request, with one error. The operator fixes it,
starts again, and meets the next one. Most of the things that can be wrong are
already checked somewhere: `config.Load` rejects an unknown key and an unset
variable, `serve` refuses a keyring sealed by another source or missing a key a
feature needs, `probe` measures conditional writes. What is missing is one
command that asks all of it at once, before `serve`, and says what to change.

Two of the answers are only in response headers, and arrive with failures as
often as with successes: the provider's clock in `Date`, and where a bucket
lives in `x-amz-bucket-region`. The upstream client turns an error response
into an error and keeps its code and message, not its headers.

## Decision

**`blindbucket doctor` runs a fixed list of checks, all of them on every run,
and reports each as `ok`, `warning`, `failed` or `skipped`, with what was found
and, for a warning or a failure, what to change.**

1. **Nothing stops the run.** A check that depends on one that failed is
   reported as skipped, with why, rather than left out. The list is the same on
   every run, which is what makes `--json` something to look a check up in by
   name: config, listener, tls, keyring, feature_keys, audit_log,
   freshness_index, upstream_credentials, then bucket and conditional_writes
   for each bucket, then clock.

2. **The keyring is opened the way `serve` opens it.** For a passphrase keyring
   that means the passphrase, from `$BLINDBUCKET_PASSPHRASE`, a file, or the
   terminal; for Vault and KMS a real unseal. A look at the file's metadata
   alone would not find a wrong passphrase or a missing grant, and those are the
   failures an operator cannot see from the configuration.

3. **One read per bucket answers most of the provider.** A `ListObjectsV2` with
   `max-keys=1` tells whether the endpoint answers and its certificate
   verifies, whether the credentials and the region are right, whether the
   bucket exists and whether it may be listed. Each S3 error code maps to the
   setting it points at: `InvalidAccessKeyId` to `upstream.access_key_id`,
   `SignatureDoesNotMatch` to the secret, `AuthorizationHeaderMalformed` and
   `PermanentRedirect` to `upstream.region`, with the region the provider names.

4. **The headers are read from the transport.** `doctor` wraps the transport of
   `upstream.DefaultHTTPClient` in a recorder that keeps the last response's
   headers. The upstream client is unchanged; `DefaultHTTPClient` is exported so
   that the wrapping keeps its timeouts rather than replacing them. Requests
   are not retried: a retried timeout would triple how long `doctor` takes to
   say that nothing answers.

5. **`doctor` writes, by default.** The conditional-writes check calls what
   `probe` calls, which writes one small object under `.blindbucket/probe/` and
   removes it. That is the only check that finds a provider ignoring the
   conditions rotation relies on, and it also proves the credentials may write.
   `--no-write` skips it, for credentials that are read-only on purpose.

6. **A provider that ignores conditional writes is a warning, not a failure.**
   The gateway serves; `rotate` and `migrate-names` refuse on that provider and
   say why (ADR-020, ADR-022). A failure would make every Garage deployment
   fail `doctor` while it works.

7. **The clock is a warning from one minute and a failure from fifteen.** SigV4
   allows fifteen minutes either way, and past that the provider refuses every
   request. A host whose clock is kept by NTP is within milliseconds, so a
   minute already means it is not being kept.

8. **The audit log is not verified.** `serve` verifies it on opening, and for a
   large log that takes time. `doctor` checks that its directory exists and can
   be written, by creating and removing a temporary file, and that an existing
   log can be opened for appending.

9. **Exit 0 when nothing failed, warnings included, and 1 when something did.**
   The `--json` document is stable under ADR-021: `config`, `ok`, and `checks`
   with `name`, `bucket` for the per-bucket checks, `outcome`, `detail` and
   `fix`.

## Alternatives considered

- **Stopping at the first failure.** That is what `serve` already does, and
  what this command exists to improve on.
- **A HEAD of the bucket instead of a listing.** A HEAD response has no body, so
  the error code that says which setting is wrong never arrives.
- **Keeping the response headers in `upstream.APIError`.** It would work, and
  would change a type every caller of the upstream client sees, for one
  command's sake. The recorder keeps the change in `doctor`.
- **Not writing, ever.** A `doctor` that cannot see a provider ignoring
  conditions misses the failure that is hardest to see any other way. The
  flag covers read-only credentials.
- **Verifying the audit log.** Doing what `serve` does on opening, a second
  time, at the cost of time proportional to the log's size, for a failure
  `serve` reports clearly anyway.

## Consequences

- An operator can ask whether a deployment will work before starting it, and
  get every problem in one run. `init`'s summary points at `doctor` instead of
  `probe`.
- The CI job "Client compatibility" runs `doctor` on the configuration `init`
  wrote, against the provider its clients use; a failed check fails the job.
- The list of checks is part of the `--json` promise. A new check is a new name
  added to it, which ADR-021 allows; a renamed one is not.
- `doctor` leaves a probe object behind only if it is interrupted between
  writing and removing it, as `probe` can; `gc` does not consider the prefix,
  and the next run reuses none of it.
