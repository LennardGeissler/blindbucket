# ADR-023 — Resealing a keyring: verified before it replaces, and no second door

**Status:** Accepted
**Date:** 2026-10-02
**Milestone:** post-1.0
**Implements:** `blindbucket reseal`, `cmd/blindbucket` (keyring writes), `internal/crypto/keys` (`Keyring.Equal`)
**Amends:** [ADR-013](ADR-013-root-key-sources.md), whose consequences said there was no `blindbucket reseal`

## Context

[ADR-013](ADR-013-root-key-sources.md) gave a keyring three possible root-key
sources — a passphrase, Vault Transit, AWS KMS — and recorded which one sealed a
given file. It left moving between them unimplemented: "a migration between
sources is a `keygen --add` away from being possible but is *not* implemented".

The documentation since then has offered a way around it — create a new keyring
and rotate objects onto it — and **that way does not exist.** `rotate` runs
against one keyring and needs the old KEKs in it to unwrap the data keys it
re-wraps; a new keyring holds none of them, and nothing imports a KEK. A new
keyring would also carry a new name key, so under `names.encrypt` every object
would become unfindable, and a new audit key, so every log written so far would
stop verifying. A deployment sealed by a passphrase had no way to move to KMS,
and one whose Vault key had to be retired had no way off it.

The mechanics are not the hard part. `keygen --add` already opens a keyring with
its source and seals it again under a fresh root key; a reseal is the same with
one source to open and another to seal. Two things are hard, and both are about
the one file:

- **A source that can seal but not unseal.** A KMS key policy granting
  `kms:Encrypt` without `kms:Decrypt`, a Vault policy on `transit/encrypt` and
  not `transit/decrypt`, a context condition that the encrypt call satisfies and
  a decrypt from another principal would not. Each produces a keyring nobody can
  open. Written over the only copy, that is every object.
- **The old file.** ADR-013 rejected a keyring that opens two ways, because it
  has the security of the weaker door. Any copy of the file from before a reseal
  is exactly that door.

## Decision

`blindbucket reseal --keyring <file> [--config <current>] [--to-config <target>]`
opens the keyring with the source `--config` names, seals the same keys under a
fresh root key from the source `--to-config` names, and replaces the file.
Either config left out means a passphrase, so a passphrase change is
`reseal --keyring <file>`.

**Verified before it replaces.** The sealed bytes are opened again with the
target source — the service is asked to decrypt what it just encrypted, or the
passphrase is stretched again — and the result must be `Keyring.Equal` to what
was read: the same KEKs under the same ids and dates, the same active one, the
same audit, name and freshness keys. Only then is the file replaced. A target
that can seal and not unseal fails here, with nothing written. `--dry-run` stops
after this check, which makes it the way to ask a key service whether a set of
credentials would work, before it matters.

**In place, without a backup.** A backup sealed under the old source is the
second door ADR-013 rejected, kept on purpose beside the new one. The
verification is what makes going without one safe: the file is replaced only by
a keyring that has been shown to open.

**Only as it was read, and durably.** The replace refuses a file that changed
since it was opened — another `keygen` or `keys` run — and syncs the file and
its directory. That is the write path every command that rewrites a keyring now
uses, fixed in the change before this one rather than for reseal alone.

**A new passphrase never comes from `$BLINDBUCKET_PASSPHRASE`.** That variable
holds the current one, and reading it for both would reseal under the
passphrase the keyring already has while the operator believed it had changed.
It comes from `--new-passphrase-file`, the target configuration's
`passphrase_file`, or a prompt asked twice. A new passphrase equal to the
current one is refused for the same reason.

**No `--json`.** A reseal is an interactive, one-off operation; a JSON document
would be a Tier 2 interface under ADR-021 that nothing reads.

### What it does not do

**It changes the lock, not the keys.** The KEKs, and the name, audit and
freshness keys, are byte for byte what they were — that is how no object has to
be touched. It follows that anyone holding the old source *and* a copy of the
old file has every key, before and after. Moving custody to a service, retiring
a Vault key, or changing a passphrase that has not leaked is what reseal is for.
Against a root key or passphrase that may already be out, it is the first step
and not the remedy: the remedy is a new KEK, `rotate` and `keys remove`, as
THREAT_MODEL §5.5 has it.

**It does not reconfigure the gateway.** Every instance's `keys` section has to
name the new source before it restarts. One that does not refuses to start and
says which source the file needs, which is ADR-013's check doing its job: the
failure is loud, at startup, and loses nothing.

## Alternatives considered

**Keep a backup** (`keyring.json.bak`). The comfortable choice, and the one
most tools make. Rejected as the second door: after a move from a passphrase to
KMS, the backup still opens with the passphrase, and it sits next to the file it
was meant to replace. What a backup protects against — a reseal that bricks the
keyring — the verification prevents instead.

**Write to a new file** (`--out`) and let the operator swap it in. It leaves two
files with the same keys and different doors in the same directory, and turns
"no backup" into "the operator deletes the old one", which is the step that gets
forgotten. A deployment that stages keyrings — a Kubernetes Secret — reseals a
copy anyway.

**Let a keyring carry two sources** for the duration of a move. ADR-013 rejected
it for good, and the reasons have not changed.

**Export and import KEKs**, so the documented workaround would work. It would
put raw KEKs in a file for the length of the operation, which is the one thing
the keyring format exists to prevent.

**`keygen --reseal`** instead of a command. `keygen` creates keys; a reseal adds
none, and the flag would share a usage text with operations that do.

**A TLA+ model**, as ADR-022 had. A model is evidence about how many processes
interleave on shared state, and here there is one file and no state at the
services: Encrypt and Decrypt are stateless calls. A crash leaves the old file
or the new one, and two writers are refused at the replace. The evidence that
fits is the hostile tests below.

## Consequences

- A keyring moves between a passphrase, Vault and KMS in any direction without
  touching an object, and the documentation's workaround, which never worked, is
  gone.
- The tests play the target that will not unseal twice: a stub of Vault's API
  that encrypts and answers 403 to decrypt, and a real Vault token whose policy
  grants `transit/encrypt` only. Both leave the file as it was. One keyring
  walked from a passphrase through Vault and KMS to a new passphrase decrypts at
  the end a file encrypted at the start.
- Real KMS is measured only by the manual AWS workflow, which now reseals its
  KMS-sealed keyring to a passphrase and back; until it next runs, KMS is
  covered by the emulator, which knows nothing of key policies.
- Every old copy of a keyring file — backups, a previous Secret version, a
  laptop — remains a door to the same keys. The command says so when it
  finishes, and THREAT_MODEL §5.5 says what to do about it.
