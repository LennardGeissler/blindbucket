# ADR-034 — Encrypting the objects a bucket held before the gateway, in place

**Status:** Accepted
**Date:** 2026-10-18
**Milestone:** M12
**Implements:** `blindbucket encrypt-existing`, [#151](https://github.com/LennardGeissler/blindbucket/issues/151)
**Builds on:** [ADR-009](ADR-009-rotation-by-copy.md), [ADR-020](ADR-020-conditional-writes-measured.md), [ADR-022](ADR-022-migrating-to-encrypted-names.md), [ADR-025](ADR-025-writes-rank-by-when-they-began.md)
**Checked by:** [`spec/tla/Multipart.tla`](../../spec/tla/Multipart.tla) and [`spec/tla/Migrate.tla`](../../spec/tla/Migrate.tla) — see [The models](#the-models)

## Context

A gateway put in front of a bucket that already holds objects cannot read them. Every
GET answers `ObjectNotEncrypted`, by design: the gateway never serves plaintext it did
not encrypt ([ADR-004](ADR-004-fail-closed.md)). All five applications measured in M12
hit it. Nextcloud answers 503 for such a file, Loki loses the logs stored before, GitLab
and Mastodon lose every attachment, Velero every backup. Each guide says *new buckets
only*, and that is what keeps an existing installation from moving behind the gateway.

What is missing is a way to turn those objects into what the gateway would have written:
read each one, encrypt it, and put it back under the key the application knows.
[ADR-022](ADR-022-migrating-to-encrypted-names.md) solved the closest problem,
`migrate-names`, and #151 asks the same questions of this one. Three things make it
different, and they decide most of what follows:

- **The data moves.** `migrate-names` and `rotate` copy ciphertext inside the provider
  and keep the data key, the segment salts and with them the freshness tag. Here every
  byte goes through the command: read in clear, encrypted under a new data key with new
  salts, written back.
- **There are two cases, and they have the shape of two existing operations.** With
  object names in clear, the encrypted object goes to the key the plaintext sits at.
  That is an overwrite, and it is a rotation's final write ([ADR-009](ADR-009-rotation-by-copy.md)).
  With `names.encrypt`, it goes to the encrypted form of that key, a different stored
  key, and the plaintext is deleted afterwards. That is a migration's copy and delete
  ([ADR-022](ADR-022-migrating-to-encrypted-names.md)).
- **The source has no integrity.** A segment authenticates itself; a plaintext object
  does not. Whatever the provider returns when the command reads it is what gets
  encrypted, and from then on authenticated.

## Decision

### A command, run while the application is stopped

`blindbucket encrypt-existing --config <file> s3://<bucket>[/<prefix>]`, with
`--dry-run`, `--json`, `--concurrency`, `--allow-unconditional` and `-v`, as `rotate` and
`migrate-names` have them.

**The application is stopped, or in maintenance, for the run.** Until the run reaches
an object, the gateway refuses it, so for reads the run is a maintenance window as long
as the run itself. A gateway mode that serves plaintext for objects not yet encrypted is
a non-goal: it is the downgrade the format exists to refuse, and #151 rules it out.

**Writes during the run are safe, and they win.** A client writing through the gateway
during the run is the case the guards below exist for, as in ADR-022. Stopping the
application is about reads, not about correctness.

**With `names.encrypt`, every instance serves with it before the run**, exactly as
ADR-022 requires: from then on clients read and write at the encrypted key, and the key
in clear is reached by nothing but this command. It refuses a real run when its own
configuration does not encrypt names; that is the one instance it can see.

### What it touches

An object is a candidate when it carries none of the gateway's metadata. Everything the
gateway wrote carries it (FORMAT §6.3), so this is the test `rotate` already uses for
`foreign`, turned around. Left alone, each counted under its own name:

- **Objects the gateway wrote** (`skipped`). Under `names.encrypt`, an object the
  gateway wrote with names in clear is `migrate-names`' business, and is reported as
  `needs_name_migration` rather than touched.
- **The reserved prefix** `.blindbucket/`, which no listing through the gateway shows and
  this command does not list.
- **A key whose encrypted form would exceed 1024 bytes** (`too_long`), as in ADR-022.
- **An object whose metadata uses the gateway's own prefix**, `x-amz-meta-bb-*`
  (`conflicted`). Carrying it across would be read as the gateway's own metadata, and
  FORMAT §6.3 has the gateway refuse a client that tries to set it, so such an object
  was written past the gateway.
- **An object the command cannot read as it is**: one encrypted with SSE-C, or under
  Object Lock or a legal hold that forbids the overwrite (`unreadable`, `locked`).
- **An object with tags** (`tagged`). An overwrite would drop the tags, and carrying them
  across would keep plaintext at the provider through a side door, which is why the
  gateway refuses tags at all. The operator decides.

### Per object

Every object is streamed, as `rotate` and `scrub` stream; none is held in memory.

1. **HEAD** the key. Not a candidate: count it and stop.
2. **GET** it with `If-Match` on the ETag from step 1, and encrypt as it arrives: a new
   data key, wrapped under the active key and bound to the key the client names
   (FORMAT §6.1), fresh salts, the configured chunk size. A 412 means the object changed
   since step 1: start over at step 1.
3. **Check what was read**, where the provider says what it stored. For a single-part
   object whose ETag is a plain MD5, the MD5 of the bytes read must match it, and a
   full-object checksum (`x-amz-checksum-*`) is compared where the HEAD carries one. A
   mismatch aborts the object as `failed`. A multipart ETag proves nothing about the
   bytes, and such an object is encrypted as read.
4. **Write it**, in one of two ways:
   - **Names in clear: overwrite in place**, as a rotation does. A multipart upload to
     the same key, the manifest written before the completion (R2), open uploads of the
     key checked after its own exists and given way to (`objcopy.YieldToUploads`,
     ADR-025), and `If-Match` on the completion with the ETag from step 1. A 412, or an
     upload to give way to, means a client wrote meanwhile: its version stands, and the
     object is `conflicted` for this run. It is a gateway object now, and the next run
     skips it.
   - **Names encrypted: write the encrypted key, then delete the plain one**, as a
     migration does. HEAD the encrypted key first; something there makes the plaintext
     obsolete (below). Otherwise a multipart upload to it with `If-None-Match: *` on the
     completion, giving way to open uploads in the same way. A 412 means a client wrote
     the encrypted key meanwhile, which also makes the plaintext obsolete. Then delete
     the key in clear, unconditionally, as ADR-022 measured and decided.
5. **Carry the object across:** `Content-Type`, `Cache-Control`, `Content-Disposition`,
   `Content-Encoding`, `Content-Language` and every user metadata entry, read from the
   HEAD. ADR-022 found that rotation once carried fewer; this command carries all of
   them, and a test holds it to that.

Even a small object is written as a one-part multipart upload, because the condition
lives in the completion. Under `--allow-unconditional` a small object is one
`PutObject`, by ADR-020's rule.

### An object at the encrypted key makes the plaintext obsolete

With `names.encrypt`, ADR-022's rule carries over unchanged, and for the same two
reasons. Something at the encrypted key is either this command's own write from a run
that died before the delete, or a client's write through the switched gateway, which is
newer. Either way the plaintext is obsolete and is deleted (`obsolete`). Leaving it is
`MCMigrateLeaveOnResume`: an aborted run's plaintext would never go.

ADR-022 tells the two apart by comparing data keys, and reports `resumed` or
`superseded`. That comparison is not available here, because the encrypted object never
shared a data key with the plaintext. This command reports both as `obsolete`, which is
what decides the action. ADR-022's two exceptions stay: an object at the encrypted key
the gateway did not write, or one not newer than the plaintext by `Last-Modified`, is
`conflicted`, and the plaintext is left for the operator.

### Which guards, and the probe

| Case | Guard | Measured by |
|---|---|---|
| Names in clear | `If-Match` on `CompleteMultipartUpload` | the probe's rotation check (ADR-020) |
| Names in clear | giving way to open uploads | nothing to measure: `ListMultipartUploads` |
| Names encrypted | `If-None-Match: *` on `CompleteMultipartUpload` | the probe's migration check (ADR-022) |
| Both | `If-Match` on the GET | not a write guard: a provider that ignores it fails step 3 or serves the version the HEAD saw |

The run probes before it starts, as `rotate` and `migrate-names` do, and refuses unless
the guard its case needs is **enforced**. `--allow-unconditional` skips the measurement
with the condition: the operator's statement that nothing writes to the prefix while the
run lasts, the one condition under which the guard has nothing to catch. A dry run probes
too.

`If-Match` on the GET is not measured, because nothing depends on it alone. If the
provider ignores it, the GET returns whatever is current. That is the HEAD's version,
unless a write landed in between, and then the conditional completion refuses the write
in any case.

### Rollback detection

[ADR-018](ADR-018-rollback-detection.md) says anything that re-encrypts an object has to
update the freshness index, and that no such operation may be added without doing so.
This one does not update it, and here is why that meets the rule's purpose rather than
breaking it. The index is local to each gateway instance, and the command is a
different process. More to the point, the keys it writes have no entry. An entry is made
when the gateway writes, deletes or first reads an object, and the gateway has done none
of these to a plaintext object: every read of one was refused before a tag existed. The
first read after the run therefore finds no entry, and records what it reads, which is
the case ADR-018 already covers after an index is lost.

One case breaks that argument. An object the gateway once wrote, then overwritten with
plaintext directly at the provider, then encrypted by this command, has an entry with the
old tag, and its next read is refused as a rollback. That is a write past the gateway,
which the threat model does not cover. The documentation names it, and so does the
output when freshness is configured.

### Versioned buckets keep the plaintext

On a bucket with versioning, an overwrite or a delete keeps the plaintext as a
noncurrent version. **The run then encrypts what clients see, and leaves every
plaintext version at the provider.** That is the opposite of what an operator running this
command wants, and nothing in the output would show it. So the run asks the provider for
the bucket's versioning state, and refuses on a versioned bucket unless
`--keep-versions` is given. That flag is the operator's statement that the old versions
are handled elsewhere: a lifecycle rule for noncurrent versions, or a deletion after the
run.

### The output

`--json` prints, with every count always present:

```json
{"bucket":"nextcloud","prefix":"","dry_run":false,"unconditional":false,
 "names_encrypted":false,"started":"2026-10-18T10:00:00Z","duration_seconds":42.0,
 "scanned":1200,"encrypted":1150,"obsolete":0,"skipped":40,"conflicted":2,
 "needs_name_migration":0,"too_long":0,"tagged":0,"locked":0,"unreadable":0,"failed":0,
 "bytes_encrypted":53687091200}
```

The document joins the Tier 2 interfaces of [ADR-021](ADR-021-what-1.0-promises.md). The
exit code is `1` when anything but `encrypted`, `obsolete` or `skipped` is above zero.
**Exit `0` means no plaintext object is left under the prefix**, or for a dry run that
none would be. A dry run lists every candidate and what it would do with it, and changes
nothing beyond the probe's own object under the reserved prefix.

## The models

The order of the requests is not new, which is why no third model is added. The names-
in-clear write *is* a rotation's final write: HEAD, create the upload, write the
manifest, give way to open uploads, complete with `If-Match`, clean up. The names-
encrypted write *is* a migration's copy and delete. Neither model represents bytes, so
an upload of new ciphertext and a copy of old ciphertext are the same step to them.

What is new is the starting state. `Multipart.tla` begins with a multipart object the
gateway wrote, which has a manifest. Here the object at the key is a single-part object
with no manifest, and it is never a gateway write. The model gains a constant `Initial`,
`"gateway"` or `"plaintext"`, and three configurations:

| Configuration | Expected | Result |
|---|---|---|
| `MCEncrypt` | the rotation write as above, `Initial = "plaintext"`, two client uploads, a PUT, a delete and `gc`, `Ordering = "either"`: no violation of I1 or I2 | no counterexample, 2.7 million distinct states |
| `MCEncryptUnconditional` | `--allow-unconditional`: **I2 violated**, a client write lost | violated, as expected |
| `MCEncryptAws` | `If-Match` without giving way to open uploads, on a provider that ranks by initiation: **I2 violated** | violated, as expected |

The command skips an object the gateway wrote, where the model's rotation process rotates
one. That only adds behaviours, so what holds in the model holds for the command. Every
other configuration of `Multipart.tla` sets `Initial = "gateway"`, and all of them report
what they did before, with the same state counts.

For the names-encrypted case, `Migrate.tla` needs no change. Its plain key is reached by
nothing but the migration whatever it holds, and its configurations already cover this
command's rules: `MCMigrate` must pass, `MCMigrateNoCreateGuard` and
`MCMigrateLeaveOnResume` must fail, and they do.

## Alternatives considered

**A gateway mode that serves plaintext until an object is encrypted.** Rejected by #151 and
by ADR-004: a provider, or anyone who can write to the bucket, could then hand any client
plaintext of their choosing for any key, and the gateway would pass it on as genuine.

**Encrypt through the gateway: read from the provider, PUT through a running instance.**
It would reuse every write path as it is. Rejected because a PUT through the gateway
carries no condition: the gateway offers clients no conditional writes, so nothing would
reach the provider as a guard, and the run would lose a client write that landed between
its read and its PUT.
Built into the command, the write is the rotation's, guards and all.

**Copy to a new bucket instead of in place.** Simple, and the source stays untouched until
the end. But it is not what #151 asks for, and it changes the bucket every application is
configured for. An operator who wants that can already do it with any S3 client through
the gateway.

**Leave versioned buckets to the operator, with a warning.** A warning in the output of a
run that took hours is read after the fact, if at all. Refusing up front costs one flag
for the operator who has thought about it.

**Carry tags across, encrypted in the gateway's metadata.** Tags are what lifecycle rules
and access policies at the provider match on, so encrypting them would break whatever
they were for, and keeping them in clear is what the gateway refuses everywhere else.

## Consequences

**Positive.**

- An existing bucket can move behind the gateway, which closes the last gap in M12. Each
  guide's *new buckets only* becomes a procedure.
- A run is idempotent and resumable. Encrypted objects are skipped, and an aborted
  names-encrypted run is finished by the next one (`obsolete`).
- A client write during the run is never lost, on a provider that enforces the guard.

**Negative.**

- A maintenance window for reads, as long as the run.
- Every byte goes through the command: a run reads and writes the whole bucket, and pays
  the provider's egress and requests for it. The dry run says how many bytes.
- A plaintext object is trusted as the provider serves it at the moment of the read,
  checked only against an MD5 or checksum the provider keeps for it. What the provider
  serves then is what is authenticated from then on.
- Objects come out as one-part multipart objects, with a manifest each, where the
  original was a single PUT. Readable and correct, and one more object per object at the
  provider.
- The storage class is not carried across, as the gateway does not forward it.
- On Garage v2.4.1, as for rotation and migration, a run needs `--allow-unconditional`
  and nothing writing.
