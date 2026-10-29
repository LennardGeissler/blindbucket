# ADR-038 — Tenants: keys per set of buckets, each under its own lock, and a tenant deleted by destroying them

**Status:** Proposed
**Date:** 2026-10-29
**Milestone:** M15
**Implements:** [#133](https://github.com/LennardGeissler/blindbucket/issues/133)
**Builds on:** [ADR-002](ADR-002-key-hierarchy.md), [ADR-009](ADR-009-rotation-by-copy.md), [ADR-013](ADR-013-root-key-sources.md), [ADR-015](ADR-015-object-name-encryption.md), [ADR-022](ADR-022-migrating-to-encrypted-names.md), [ADR-023](ADR-023-resealing-a-keyring.md)

## Context

One gateway serves several clients, each with a bucket allow-list, and wraps every
object under the same keyring. Two groups that share a gateway share keys. Neither
group's data can be made unreadable without the other's, and "delete everything of
customer X" means deleting objects at a provider, which the gateway cannot verify:
versioning, replication and the provider's own backups keep copies nobody asked for.

**Crypto-shredding** is the usual answer: give each group its own keys, and delete
the group by destroying them. The ciphertext stays where it is and becomes noise.
It is only as good as the claim "the keys are gone", and in this design the keys
live in a file that is copied by design. Every instance reads it; operators back it
up; a Kubernetes Secret keeps its earlier versions. Removing a key from the current
file removes it from none of those. [ADR-023](ADR-023-resealing-a-keyring.md) met
the same problem for reseal and answered that every old copy is still a door. For
shredding, that answer would make the promise depend on the backup discipline of
every operator who ever held the file.

Four more things make it more than "a KEK per tenant":

- **The keyring holds more than KEKs.** With `names.encrypt` on, stored names are
  encrypted under one name key (FORMAT §15). Audit entries encrypt names under a key
  from the audit secret (§14.5). A tenant whose KEKs are gone but whose names still
  decrypt under the deployment's keys has not been deleted.
- **Instances load the keyring once, at startup.** A change reaches an instance when
  it restarts, so for the length of a rollout instances disagree about the keyring.
  This already bites today: `keygen --add` activates the new KEK by default, and an
  instance that has not restarted cannot read what a restarted one wrote under it.
  Nothing documents that.
- **Something must decide which tenant a bucket is in**, and every instance and
  every command (`rotate`, `scrub`, `encrypt-existing`, `migrate-names`) has to
  decide the same way. An instance that disagrees wraps a tenant's objects under
  another tenant's keys, and nothing fails until the shredding misses them.
- **Running processes keep keys in memory** for as long as they run (THREAT_MODEL
  §5.5), the gateway and every CLI command that opened the keyring.

IAM-style access rules stay out of scope ([THREAT_MODEL §6](../THREAT_MODEL.md)).
Which client may reach which bucket is configured as today. This ADR is about keys.

## Decision

**A tenant is a named set of buckets with its own KEKs and its own name key, sealed
under its own lock.** Deleting a tenant means destroying that lock at the key
service. That makes every copy of the keyring that ever held the tenant useless for
it, wherever the copy is.

### What a tenant is

```
Deployment lock (root key: passphrase | Vault Transit | AWS KMS, as today)
 ├─ the default tenant: today's KEKs and name key
 ├─ the audit secret, the freshness key        (deployment-wide, as today)
 └─ the directory: tenants, their buckets, their locks, tombstones, the generation

Tenant lock "acme" (its own root key: KMS key, Vault Transit key, or passphrase)
 └─ acme's KEKs and acme's name key
```

- **Buckets** are listed by exact name or by a prefix ending in `*` (`acme-*`).
  Patterns of different tenants must not overlap. A bucket that matches no tenant
  belongs to the **default tenant**, which holds today's keys, so a keyring without
  tenants means exactly what it means now.
- **A bucket joins a tenant and never leaves it.** It joins from the default tenant,
  empty or not, and stays until the tenant is destroyed. Moving data between
  tenants is a copy. This is what makes destruction safe for everyone else: a
  tenant's keys only ever wrap objects in that tenant's buckets. `MCTenantsMoveBucket`
  below is the counterexample if buckets could leave.
- **Key ids are unique across the keyring**, tenants and tombstones included. The
  object format does not change: `bb-kid` names the KEK, and the KEK says which
  tenant it belongs to. A destroyed tenant's ids are never issued again.
- **The default tenant cannot be destroyed.** Deleting it is deleting the
  deployment.

### Where the mapping lives: in the keyring, authenticated

The bucket-to-tenant mapping is part of the keyring, in a **directory** sealed under
the deployment lock: the tenants, their bucket patterns, which source seals each one
and every lock it was ever sealed under, the tombstones, and a **generation** that
increases with every write of the file. Each tenant's own section is sealed under its
lock, with its name in the associated data, so a section cannot be moved to another
name.

The keyring is the one artifact every instance and every command already has to
share ([ADR-002](ADR-002-key-hierarchy.md)), and a sealed directory cannot be edited
without the deployment's root key. A file that drops a tenant, moves a bucket or
removes a tombstone fails to open instead of letting those buckets fall back to the
default tenant.

### Writing and reading

- **Every write wraps under the active KEK of the bucket's tenant**: PutObject,
  multipart uploads and their upload tokens, CopyObject's destination (the data key
  is rewrapped, as for any copy), presigned uploads, `encrypt-existing`, and
  `rotate`.
- **A read unwraps with whichever KEK `bb-kid` names**, as now. This allows a
  bucket's objects to be moved onto its tenant's keys by `rotate` while they are
  still on the default tenant's keys. It cannot be abused: the data key's associated
  data binds bucket and key (FORMAT §6.1), so an object moved to another bucket does
  not open whatever key it names. `scrub` and `rotate --dry-run` report objects that
  are not on their bucket's tenant's keys.
- **Names follow buckets.** With `names.encrypt`, a tenant's buckets map names under
  the tenant's name key. A bucket that joins a tenant with encrypted names in it is
  moved by `migrate-names` from the default name key to the tenant's, under
  ADR-022's rule: every instance switched first, then the migration.
- **Audit entries about a tenant's buckets** encrypt their names under a key derived
  from the tenant's name key, and record the tenant in clear. After destruction
  those names are opaque for good, while the chain and the checkpoints still verify:
  they cover what is stored, not the plaintext. The audit secret stays
  deployment-wide.
- **A destroyed tenant's buckets are refused**, reads and writes, with
  `403 AccessDenied` and a message naming the destruction. They do not fall back to
  the default tenant. Without that, the first write after a destruction would store
  new data in a deleted tenant's bucket under keys nobody intends to destroy.
- **A tenant whose lock cannot be opened at startup** (KMS down, a grant revoked)
  does not stop the instance. Its buckets answer `503 ServiceUnavailable`, the other
  tenants are served, and `blindbucket_tenant_open{tenant}` is 0. One tenant's key
  service must not be every tenant's outage. This stays fail-closed for that tenant,
  since its buckets are known from the directory and get no other keys. It also gives
  operators a way to suspend a tenant: revoke its grant, restart. The deployment lock
  stays as today: if it does not open, the instance does not start.

### Rolling a keyring change out

Instances agree on the keyring only once all of them have restarted onto it. The
directory's generation is exported as `blindbucket_keyring_generation`, so "every
instance serves generation N" is something an operator can check, and the dashboard
shows it. Two rules follow, and they apply to a new KEK today as much as to a tenant:

1. **Add, roll out, then activate.** A new tenant, or a new KEK, enters the keyring
   inactive. Writes keep using the old keys until every instance serves it, and only
   then is it activated, with a second rollout. Otherwise an instance that has not
   restarted cannot read what one that has wrote (`MCTenantsActivateEarly`).
   `keygen --add` keeps activating by default for single-instance deployments, and
   the documentation for several instances says to pass `--activate=false`.
2. **Count only after every instance serves the tenant.** A destruction is preceded
   by a census of the tenant's buckets (below). An instance that still serves a
   keyring without the tenant writes its buckets under the default tenant's keys,
   and if it does so after the census, those objects survive the destruction
   (`MCTenantsStaleInstance`).

### Destroying a tenant

`blindbucket tenants destroy <name>` and what follows it, in this order:

1. **Census.** Every object in the tenant's buckets is HEADed, as `rotate --dry-run`
   does. If any is wrapped under a key that is not the tenant's, the command stops
   and says how many and where: those objects would survive. `--force` proceeds and
   repeats the count in its output. The tenant's buckets are listed in the
   directory, so unlike `keys remove`, this command can see what it is about to
   strand.
2. **Tombstone.** The keyring is rewritten without the tenant's section. The
   directory keeps a tombstone instead: the name, the bucket patterns, the key ids,
   every lock that ever sealed the tenant, and the date. The generation increases.
3. **Rollout.** Every instance restarts onto the new generation and refuses the
   tenant's buckets from then on. Every other process that opened the keyring before
   step 2 (a running `rotate`, `scrub` or `encrypt-existing`) has to end. Until then
   it still holds the keys in memory.
4. **Destroy the locks at their services.** The command prints what to do for each
   lock in the tombstone, for example the KMS key to schedule for deletion. It does
   not do it itself: the gateway's credentials need `Decrypt` on a tenant's key, and
   they should not also need the right to destroy it. The lock is destroyed last,
   after the rollout. Destroyed earlier, it stops every instance that restarts before
   step 2 from opening its keyring (`MCTenantsLockFirst`).

**Every lock the tenant ever had.** `reseal --tenant` moves a tenant to a new lock
as [ADR-023](ADR-023-resealing-a-keyring.md) moves the deployment, and the copies of
the file from before are sealed under the old one. So the directory records the
tenant's lock history, and step 4 names all of it. Destroying only the current lock
leaves every older copy openable (`MCTenantsResealedLock`).

### What destruction promises, and what it does not

**It promises**, once step 4's services have actually deleted the key material and
every process from before step 2 has ended: no copy of the keyring, current or old,
in a backup or a Secret's history, opens the tenant's KEKs or its name key. Every
object the gateway wrote to the tenant's buckets is then unreadable, and so is
everything sealed under those objects' data keys: segments, manifests' MACs and tag
sidecars (ADR-037). That holds for the provider, for the operator, and for whoever
holds the deployment lock. The tenant's encrypted names are unreadable in the bucket
and in the audit log.

**It does not promise:**

- **Anything before the service has deleted the key.** AWS KMS waits 7 to 30 days
  and can be cancelled in that window. Vault deletes a Transit key only if the key
  allows deletion, and a snapshot or storage backup of Vault from before still holds
  it. The promise is as final as the service's own deletion.
- **Anything for a tenant sealed with a passphrase**, beyond everyone forgetting it.
  That cannot be checked, and the command says so.
- **Anything for a tenant left under the deployment lock.** A tenant may be created
  without a lock of its own. It then has its own keys but shares the deployment's
  lock, and any old copy of the file together with the deployment's root key brings
  it back. `tenants create` warns, `doctor` reports it, and `tenants destroy` says
  that destruction then rests on the copies.
- **Anything about what the provider sees in clear** (THREAT_MODEL §4): sizes,
  timestamps, the number of objects, access patterns, `x-amz-meta-*` metadata as
  clients sent it, and, with `names.encrypt` off, the object names. All of that
  stays readable after destruction for as long as the ciphertext is stored.
- **Objects in the tenant's buckets that are not on its keys** when step 1 is
  overridden with `--force`.
- **Copies a client made into another tenant's buckets.** They are the other
  tenant's data, wrapped under its keys, and that is correct.
- **Plaintext that left the gateway**: client copies, caches, and the memory, swap
  and core dumps of processes that held the keys (A5, out of scope).
- **The audit log's clear fields**: client, principal, operation, code, key id,
  tenant and time stay readable. So do the freshness index's entries, which are
  keyed hashes under the deployment's freshness key and say nothing without it.
- **The ciphertext against future cryptanalysis of AES-256-GCM.** The bytes stay at
  the provider until someone deletes them, and destroying the tenant does not delete
  them.

### The model first

`spec/tla/Tenants.tla`, a module of its own as `Migrate.tla` is, checked before any
code. It models two instances that each serve a keyring generation they loaded at
their last restart; client writes and reads through either; `rotate` with its own
snapshot of the keyring; the operator's steps (add, activate, census, tombstone,
lock destruction) in any order the configuration allows; and old copies of the file
for every generation. Buckets: one joining a tenant from the default tenant with
objects in it, one created in the tenant, one staying in the default tenant.

| Invariant | Meaning |
|---|---|
| `Shredded` | After destruction completes, no object in the tenant's buckets is wrapped under a key that any reachable copy of the keyring, or any running process, still opens |
| `NoCollateral` | A destruction never makes an object outside the tenant's buckets unreadable |
| `StartsAfterRestart` | An instance that restarts can always open the keyring it is given |
| `ReadableEverywhere` | An object a live tenant wrote is readable through every running instance |

| Configuration | Expected | What it shows |
|---|---|---|
| `MCTenants` | passes | The order above |
| `MCTenantsNoCensus` | `Shredded` fails | A tombstone without a census strands objects on the default tenant's keys |
| `MCTenantsStaleInstance` | `Shredded` fails | A census before every instance serves the tenant |
| `MCTenantsLockFirst` | `StartsAfterRestart` fails | The lock destroyed before the rollout |
| `MCTenantsActivateEarly` | `ReadableEverywhere` fails | A tenant activated before every instance serves it |
| `MCTenantsMoveBucket` | `NoCollateral` fails | A bucket allowed to leave a tenant |
| `MCTenantsForeignRotate` | `NoCollateral` fails | `rotate --to-kid` accepting a key that is not the bucket's tenant's |
| `MCTenantsResealedLock` | `Shredded` fails | Only the current lock destroyed after a reseal |

### Formats

- **The object format does not change.** Segments, data-key wrapping (§6), manifests,
  upload tokens and tag sidecars stay as they are. Every object written before this
  stays readable under the default tenant, which is today's keyring
  ([ADR-021](ADR-021-what-1.0-promises.md)).
- **FORMAT.md gains §18, the keyring file**, written down normatively for the first
  time, since it now holds sections sealed under different sources. It covers the
  directory, tenant sections, their associated data, and tombstones. §3 gains the
  tenant lock, §15 says which name key maps a bucket, and §14.5 says which key
  encrypts an audit entry's names. Each comes with test vectors and the Python
  reference.
- **A keyring with tenants or tombstones is `version: 2`.** Releases before this
  refuse any version but 1, and they have to refuse this one: a release that ignored
  the tenants would wrap their buckets under the default tenant's keys. A keyring
  without tenants stays version 1, so a deployment that never uses them can still
  downgrade.

### Configuration

The keyring records which source seals each tenant, as it does for the deployment
(ADR-013). The configuration supplies credentials:

```yaml
keys:
  provider: awskms                  # the deployment lock, as today
  awskms: { ... }
  tenants:
    acme:
      provider: awskms
      awskms: { key_id: alias/bb-acme, ... }
    globex:
      provider: vault
      vault: { key_name: bb-globex, ... }
```

A tenant missing here is one whose lock this instance cannot open: its buckets get
`503`. Commands: `blindbucket tenants create | assign | activate | list | destroy`,
`reseal --tenant`, and a tenant column in `keys list`.

## Alternatives considered

**One lock for every tenant**: tenants' KEKs in the keyring under the deployment's
root key, and destruction as removal from the file. Simpler, with no extra
configuration and no service call per tenant at startup. Rejected because the
promise would end at the first old copy of the file. That is ADR-023's second door,
and here it would be opened on purpose. It remains available per tenant, with the
weaker promise stated wherever it applies.

**A keyring file per tenant**, which the gateway loads side by side. Deleting the file
would look like destruction, and the format would not change. But the mapping from
buckets to files would then live in each instance's configuration. A missing file
would put its buckets back on the default tenant without a sound, and no file would
hold a tombstone. Deleting a file is also no more final than removing a section.
The lock is what makes it final.

**The mapping in the configuration**, beside the clients' bucket lists. That is where
operators look for it. Rejected because configuration is per instance and per
command, and one that disagrees with the others wraps a tenant's objects under the
wrong keys without any error, which is the one failure shredding cannot afford. The
keyring is already the shared artifact. The configuration says only how to open
locks.

**The tenant in the key id**, for example `acme.2026-10`, with no keyring change.
`.` is a legal character in ids already in use, so the tenant could not be read off
an id unambiguously, and the mapping would still need a home.

**Buckets that may leave a tenant.** A bucket reassigned to another tenant keeps its
objects on the old tenant's keys until a rotation, and destroying the old tenant in
between destroys the new one's data. A census of every other bucket would catch it,
but at the cost of listing the whole deployment for each destruction. A copy does
the same job and leaves both tenants' keys where they belong.

**Fail at startup when any tenant's lock does not open**, as for the deployment
lock. It would be the simplest fail-closed rule, and it would make each tenant's key
service a dependency of every other tenant. Refusing that tenant's buckets is just
as closed for that tenant.

**Re-reading the keyring while running**, so that a rollout is not a restart. It
would narrow the windows the rollout rules exist for, and it is a change to
ADR-002's load-once model that this ADR does not need. The generation metric makes
restarts checkable, which is the part that was missing. It can follow on its own.

**Deleting the objects instead.** It cannot be verified at a provider with
versioning, replication or backups, and that is the reason to shred. `tenants
destroy` deletes nothing; deleting the ciphertext afterwards is the operator's
choice.

**A key service call per object for tenant buckets**, so destruction at the service
would take effect immediately everywhere. Rejected by ADR-002 and ADR-013 for
latency and for putting the key service on the data path, and the reasons have not
changed.

## Consequences

**Positive.**

- Groups sharing a gateway no longer share keys. Destroying one group's keys leaves
  the others' objects untouched, and the model checks that.
- With its own lock, a tenant's deletion survives every old copy of the keyring:
  backups, Secret history, laptops.
- Names and audit entries are shredded with the data, not left behind by it.
- One tenant's key service outage, or a revoked grant, affects only that tenant.
- The rollout rules, and the generation that makes them checkable, also close the
  undocumented gap of `keygen --add` with several instances.
- Deployments without tenants see nothing new, and their keyring stays version 1.

**Negative.**

- **Destruction is as final as the key service's deletion**, which waits up to 30
  days on KMS, and is undone by a Vault backup.
- **Every tenant with its own lock costs one key service call per instance start**,
  and one more set of credentials in the configuration.
- **A destruction takes a census of every object in the tenant's buckets**, one HEAD
  each, and two rollouts: one before the census, one after the tombstone.
- **What the provider sees in clear outlives the tenant**: sizes, timestamps, user
  metadata, and names when `names.encrypt` is off.
- **A tenant created without its own lock gets a weaker promise.** The commands
  state it, but the choice stays with the operator.
- **A keyring with tenants cannot be opened by an older release**, so a deployment
  that adopts tenants cannot downgrade below the release that introduced them.
- `rotate`, `scrub`, `migrate-names`, `encrypt-existing`, the audit log, the
  dashboard and the Helm chart each learn about tenants.

## Implementation order

1. The model, `spec/tla/Tenants.tla`, with the configurations above.
2. FORMAT.md §18 and the amendments to §3, §14.5 and §15, with vectors and the
   Python reference.
3. The keyring: directory, tenant sections and locks, generation, tombstones;
   `tenants create | assign | activate | list`, `reseal --tenant`, `keys list`.
4. The write path: the bucket's tenant chooses the KEK and the name key; destroyed
   and unopened tenants are refused; the generation and tenant metrics.
5. `rotate`, `scrub`, `encrypt-existing` and `migrate-names` per tenant, and the
   census.
6. `tenants destroy`.
7. Audit names per tenant.
8. Docs: THREAT_MODEL (a §5 section for tenants, §6), the README, an operations
   guide for rollouts and destruction, the dashboard, and the Helm chart.
