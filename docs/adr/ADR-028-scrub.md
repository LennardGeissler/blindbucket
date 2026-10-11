# ADR-028 — Scrub: every stored object verified by the read path's own checks

**Status:** Accepted
**Date:** 2026-10-11
**Milestone:** post-1.0
**Implements:** `internal/verify`, `internal/scrub`, `blindbucket scrub` ([#107](https://github.com/LennardGeissler/blindbucket/issues/107))

## Context

The gateway authenticates an object when it serves one, and at no other time.
Everything the threat model lets an active provider (A2) do to an object at rest
-- alter a chunk, truncate it, drop or reorder a part, substitute another
genuine attempt of a part, lose the manifest, copy an object to a key it was not
written under -- is detected, and detected at the read. That read is the worst
moment to find out: it is the restore that needed the data, months after the
damage, by a client that gets `IntegrityCheckFailed` and has no other copy.

Two operations want the answer earlier. Retiring a key: after `rotate`, the
old KEK should only be removed once every object opens without it, and `keys
remove` cannot see the bucket. And trusting a provider after an incident or a
migration: a statement about the whole bucket, rather than about the objects
someone happened to read since.

The checks a read performs lived in `internal/proxy`, unexported and written
against `*http.Request` and `*s3api.Error`. Anything outside the proxy that
wanted to verify an object could only copy them.

## Decision

**`blindbucket scrub` reads every object under a prefix and verifies it with the
checks a GET performs, discarding the plaintext.** It reports each object that
fails, with what failed, and changes nothing.

1. **One verification.** The read path's checks move to `internal/verify`:
   the data key unwrapped under bucket and identity, the segment header and
   first chunk, the cross-check of the recorded chunk size, the manifest with its
   MAC and size bound, the part geometry against the stored size, each part's
   salt against the manifest, and the segment chain. The proxy and `scrub` both
   call it. The proxy's behaviour, error messages, log lines and metric labels
   do not change; its tests pass unchanged. A failure carries a `Kind` from a
   bounded set -- `metadata`, `unknown_kid`, `dek_unwrap`, `header`, `chunk`,
   `size`, `manifest`, the integrity metric's labels plus the two outcomes that
   are not tampering but still mean the object cannot be read -- and the phrase
   the proxy has always logged. One case is named differently from the metric:
   a part replaced by another genuine attempt is `manifest` here, because that
   is what it is, while the proxy, which finds it opening the part's header,
   counts it under `header`. The verdict is the same.

2. **No finding without a recheck.** An object can change while it is being
   read, and a multipart object can then lose the manifest the read started
   with: an overwrite deletes the manifest it replaces (rule R3, ADR-010). A
   scrub of a healthy bucket under write load would report that as a missing
   manifest. So a failure is reported only after a HEAD shows the object still
   at the version that failed. One replaced meanwhile is verified once more in
   its new version, and a second failure is confirmed the same way; one deleted
   meanwhile is counted as vanished. An object that moved on again, or whose
   HEAD failed, is listed as unreadable rather than judged either way. A body
   that ends before the length the provider announced is a failure to read
   rather than a truncated object: the decoder cannot tell the two apart, the
   byte count can.

3. **Read-only.** Nothing is repaired, rewritten or deleted. There is nothing to
   repair from -- the gateway keeps no redundancy -- and a scrub that deleted
   what failed would turn a provider's damage into data loss on the gateway's
   authority.

4. **No rollback check.** Rollback detection needs `freshness.index`, which
   records an object's tag the first time an instance sees it and is not safe to
   share with a running gateway: it is an append-only file without a lock, per
   instance (ADR-018). A scrub that opened it would write into the gateway's
   index; one that kept its own would trust every object on first sight, which
   is every object. The limit is stated rather than half-closed.

5. **Classified, not merely counted.** An object without `bb-*` metadata, or
   with name encryption on a stored name this keyring does not produce, is
   `foreign` and not a failure: buckets legitimately hold objects written
   around the gateway. A data key wrapped under a KEK the keyring does not hold
   is a finding (`unknown_kid`): not evidence of tampering, but an object this
   keyring cannot read, which is exactly what a scrub before `keys remove` is
   for. An object that could not be read at all is unreadable and makes the
   run incomplete, because nothing is known about it. It is named, not only
   counted, and not to be taken as benign: a provider that announces more than
   it sends turns a damaged object into an unreadable one, so a consumer that
   retried unreadable objects as transient would never learn which object it
   was.

6. **The command shape the other bucket commands have**: `--config`,
   `--concurrency` (4 by default, below rotate's 8, because a scrub moves every
   byte where a rotation moves metadata), `--json` as a stable document under
   ADR-021 with every count always present and `findings` and
   `unreadable_objects` always arrays, exit `1` if any object failed or could
   not be read, and `130` if the run was interrupted, including during the last
   objects after the listing finished.

## Alternatives considered

**Read every object through the gateway, with an S3 client into `/dev/null`.**
It needs no code, and it is what an operator could do today. Rejected because
it answers less and costs more. A failure in a later chunk arrives as a
connection the gateway aborted after `200 OK` (ADR-004), which a client reports
as a network error -- indistinguishable from a real one, and with no kind
attached. Every byte crosses one more hop, as plaintext. It needs client
credentials for every bucket. And a recheck against concurrent writes would
have to be built into a shell loop.

**A scrub with verification code of its own.** The obvious first draft:
`openSegment` and the manifest loader are a few dozen lines. Rejected because
the value of a scrub is that its verdict is the read's verdict. Two copies of
the checks drift -- `objcopy` already carries a second manifest loader -- and
an object a scrub passed and a read refused would make the scrub worse than
none.

**Run the proxy in-process and call its GET handler.** Shared code without a
move. Rejected because the proxy cannot be built without a request verifier
for clients that a scrub does not have, the handler signals a late failure by
panicking with `http.ErrAbortHandler`, and the kind of a failure would have to
be read back out of a metric.

**Trust the provider's checksums.** S3 stores a checksum per object and part.
Rejected as a substitute: it is computed by the party the threat model does
not trust, over ciphertext the provider is able to rewrite together with its
checksum. It detects the provider's own bit rot, not the provider.

**Sampling: verify a random fraction per run.** Cheaper on a provider that
charges for egress. Not rejected so much as deferred: it changes what a clean
run means, from "every object verified" to a probability, and that deserves a
flag and a sentence of its own. The prefix in the target already bounds a run.

## Consequences

- An operator can verify a bucket on a schedule, and before `keys remove`.
  `scrub --json` is the document a cron job or a dashboard reads.
- A scrub reads every byte. On a provider that charges for egress it costs what
  downloading the prefix costs, and on any provider it competes with clients
  for bandwidth; `--concurrency` is the only throttle.
- It sees the version the provider serves now. An older genuine version served
  in place of the latest one passes, as it does for any read without
  `freshness.index`.
- It sees what the listing shows. An object the provider deleted is not a
  finding; availability is a non-goal of the threat model.
- `internal/verify` is the read path's checks, and a change to them is now a
  change to two commands' verdicts at once. That is the point, and it is why
  the move came first and alone: the proxy's tests passed unchanged before
  `scrub` existed.
- `objcopy` keeps its own manifest loader for now. Folding it into
  `internal/verify` is a separate change.
