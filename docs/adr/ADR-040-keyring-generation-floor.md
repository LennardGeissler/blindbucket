# ADR-040 — A floor on the keyring's generation, set in the configuration

**Status:** Proposed
**Date:** 2026-11-06
**Milestone:** post-M15
**Implements:** [#223](https://github.com/LennardGeissler/blindbucket/issues/223)
**Builds on:** [ADR-038](ADR-038-tenants-and-crypto-shredding.md)

## Context

ADR-038 put the tenants, their buckets and the tombstones in a directory sealed under
the deployment's root key, so that a file which drops a tenant or a tombstone fails to
open rather than letting those buckets fall back to the default tenant. That holds for
a file that was edited. It does not hold for a file that was **replaced by another
genuine one**, and a review before 1.8.0 found two ways to do that without any root key:

- **A rollback.** Put back an older copy of the keyring, from a backup, a Secret's
  history or an operator's laptop, from before a tenant was created or destroyed. If the
  default tenant's keys are the same, it opens.
- **A version flip.** Change a version 2 file's `"version": 2` to `1` and remove
  `generation`, `directory` and `tenants`. What remains is a genuine version 1 file.
  1.8.0 refuses the flip that leaves the version 2 members in place (FORMAT §18.6), but
  not this one.

Either way the tenants and tombstones are gone. A live tenant's buckets are written
under the default tenant's keys, which survive the tenant's later destruction, and a
destroyed tenant's buckets are served again, under keys nobody means to destroy. A
tenant's own section in an older copy is no help to an attacker: it is sealed under the
tenant's lock, and a destroyed lock leaves it unopened, `503`. The harm is in the
buckets the older file does not assign at all.

Three facts shape the decision:

- **Nothing in the file can tell.** A genuine older file is genuine; every check of
  FORMAT §18.6 passes. Detecting a rollback needs a number that only goes up and that is
  kept somewhere the attacker cannot write.
- **The gateway keeps no state of its own.** Instances are replaceable pods; a new one
  knows nothing about what an old one served. The provider is an adversary that can
  replay what it stores (THREAT_MODEL, adversary A2), so the bucket is no place for
  that number either.
- **The configuration is already a second artifact.** It lives apart from the keyring:
  a ConfigMap, not the Secret, in the Helm chart. Whoever can write one cannot always
  write the other, and the operator already changes it deliberately.

## Decision

### `keys.min_generation`

```yaml
keys:
  keyring: /etc/blindbucket/keyring.json
  min_generation: 12
```

The gateway, and every command that opens the keyring with a configuration, refuses a
keyring whose generation is below `keys.min_generation`, naming both numbers and how to
proceed. A version 1 file has generation 0, so any floor of 1 or more refuses it, and
the version flip with it, without a rule of its own. Absent or 0, the floor is off, and
everything stays as it is.

The check sits where every command already opens the file, before any key is used. It
applies to commands that only read as well. A refusal that depended on the command
would leave a way around it, and an operator who restores a backup on purpose lowers
the floor on purpose, which is the point: a rollback then takes two changes in two
places, not one.

`min_generation` is a setting of the deployment's keyring, not of a tenant. Under
`keys.tenants.<name>`, which shares the type, it is refused.

### When an operator raises it

The floor goes up to N once every instance serves generation N, which
`blindbucket_keyring_generation` shows (ADR-038, rule 1). It may go up in the same
change that rolls out N, when both arrive together, as with a Helm upgrade. A floor
above the file's generation stops every instance from starting, with the reason; that
is fail-closed and visible, not silent.

So that it is not forgotten:

- **Every command that writes the keyring** says, next to the generation it already
  prints, to raise `keys.min_generation` to it after the rollout. `tenants destroy`
  adds it to its steps, since a destruction is the change a rollback most wants to undo.
- **The gateway logs a warning at start** when the keyring's generation is above the
  floor, and `doctor` reports the floor next to the generation, as a warning when it
  lags.
- **`blindbucket_keyring_min_generation`** exports the floor, and an alert fires when
  the generation has been above it for a day on a keyring with tenants. A deployment
  without tenants has a version 1 file at generation 0, nothing to roll back to, and
  sees no alert.

### What it protects against, and what not

It stops whoever can write the keyring's file or Secret, but not the configuration,
from rolling the keyring back below the floor. It does not stop:

- whoever can write both, such as someone who can change the Helm release;
- a rollback to a generation between the floor and the current one, until the floor
  is raised;
- a rollback before the floor was first set.

THREAT_MODEL §5.12 says so, and keeps its advice that the keyring's Secret be writable
only by those who hold the root key.

### Formats

The keyring format does not change. FORMAT §18.6 gains one rule: a reader given a
floor MUST refuse a file whose generation is below it, a version 1 file counting as
generation 0. The configuration refuses keys it does not know, so an older release
refuses a configuration with `min_generation` rather than ignoring the floor: a
downgrade has to drop the setting on purpose.

## Alternatives considered

**Bind the version into the format.** In version 2, wrap the default tenant's secrets
with associated data that names version 2, so that its keys never open as version 1.
That stops the flip and not the rollback, and it needs a new keyring version that
releases before it cannot open. The floor covers both without a format change.

**A counter kept by the key service.** A KMS encryption context or a Vault key version
that carries the generation. The root key is wrapped once and reused; an older file's
wrapped root key is as genuine as the newest one's, so the key service would have to
re-seal on every write and refuse old ciphertexts, which neither KMS nor Vault Transit
offers for a single key. A passphrase has no service at all.

**A marker in the bucket**, sealed under the deployment's key. The provider can replay
an older marker or delete it, and the threat model counts it as one who may (A2).

**State kept by the gateway.** Instances are stateless, and a new pod would trust the
first file it sees.

**Leave it to the deployment**: the keyring's Secret writable only by those who hold the
root key. Worth saying in the guide in any case, and it stays there, but it is nothing
the gateway can check, and Secret history and backups outlive any access rule.

## Consequences

**Positive.**

- A rollback or a version flip of the keyring alone no longer brings back buckets a
  destroyed tenant had, or takes a live tenant's buckets back to the default tenant's
  keys, once the floor is set.
- No format change, no new dependency, one comparison where the file is already opened.
- Restoring a backup on purpose stays possible, by lowering the floor on purpose.

**Negative.**

- **One more number for operators to keep up.** A floor never raised gives what 1.8.0
  gives; the warning, `doctor` and the alert make that visible but cannot do it for them.
- **A floor set too high stops the deployment**, every instance at once, until it is
  lowered.
- **It protects only as far as the configuration is harder to write than the keyring.**
  In a deployment where the same people and the same pipeline write both, it adds
  little.

## Implementation order

No model comes first this time. ADR-038's model is about instances that serve
different generations at once; the floor adds no interleaving to it, only a comparison
when a file is opened, and tests say all there is to say about that.

1. `keys.min_generation` in the configuration, refused under a tenant; the check where
   the keyring is opened, with tests for a rollback, a version flip, a file at and above
   the floor, and the floor off.
2. The messages of the commands that write the keyring, the warning at start, `doctor`,
   and the metric.
3. Docs: FORMAT §18.6, THREAT_MODEL §5.12, the tenants guide, `blindbucket.example.yaml`,
   the CHANGELOG.
4. The Helm chart's `keys.minGeneration` and the alert, held until the release
   (they need a gateway that knows the setting).
