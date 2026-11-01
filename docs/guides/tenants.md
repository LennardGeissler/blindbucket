# Tenants: running them, and destroying one

A tenant is a set of buckets with keys of its own, sealed under a lock of its own: a
KMS key, a Vault Transit key, or a passphrase. Destroying that lock is what deletes the
tenant, wherever its ciphertext and the copies of the keyring are. Every bucket no
tenant claims belongs to the default tenant, which holds the keyring's other keys.

This guide is the order of operations. Why it is that order, and what destruction
promises, are in [ADR-038](../adr/ADR-038-tenants-and-crypto-shredding.md) and
[THREAT_MODEL §5.12](../THREAT_MODEL.md#512-tenants-and-their-destruction).

## The one rule: roll out before the next step

Every tenant command writes the keyring as its next **generation**. An instance reads
the keyring when it starts, so a change reaches it when it restarts. Until every
instance runs the new generation, some still act on the old one. Two steps depend on
that, and both are irreversible if taken too early:

1. **Activate a tenant only after every instance serves the keyring that added it.**
   One that does not know the tenant cannot read what the others write under its keys.
2. **Take a census, or destroy anything, only after every instance serves the tenant
   active**, and every `rotate` or `encrypt-existing` started on an earlier keyring has
   ended. Until then something can still write the tenant's buckets under the default
   tenant's keys, and that would survive the destruction.

`blindbucket_keyring_generation` is the generation each instance serves. A rollout is
done when it is the same on all of them. `blindbucket doctor` and the status page show
it too.

## Creating a tenant

Give the gateway the tenant's lock, under `keys.tenants` and by the tenant's name, as
`keys` names the deployment's:

```yaml
keys:
  provider: vault
  keyring: /etc/blindbucket/keyring.json
  vault: { address: https://vault:8200, key_name: blindbucket, token: ${VAULT_TOKEN} }
  tenants:
    acme:
      provider: awskms
      awskms: { region: eu-central-1, key_id: alias/bb-acme }
```

Use a key for this tenant alone. A key that also seals the deployment or another tenant
cannot be destroyed without destroying them, and `tenants destroy` will say so rather
than tell you to delete it.

Then add the tenant with its buckets, names or prefixes ending in `*`:

```sh
blindbucket tenants create --keyring keyring.json --config blindbucket.yaml acme 'acme-*'
```

It starts **inactive**: its buckets are still written under the default tenant's keys.
Roll the keyring out, then activate it and roll that out too:

```sh
blindbucket tenants activate --keyring keyring.json --config blindbucket.yaml acme
```

From then on, new writes to its buckets use its key, and with `names.encrypt` its name
key. A bucket joins a tenant and never leaves it: `tenants assign` adds more, and moving
data between tenants is a copy.

`--deployment-lock` creates a tenant without a lock of its own. It has its own keys, but
every copy of the keyring opens them with the deployment's root key, so destroying it
rests on every such copy being deleted. `blindbucket reseal --tenant` gives it a lock
later, and moves a tenant from one lock to another. The old lock stays in the tenant's
history, because the copies of the keyring from before still open with it.

## Moving existing objects onto the tenant's keys

Objects already in the buckets stay under the keys they were written with. Once the
tenant is active everywhere, rotate each bucket onto it:

```sh
blindbucket rotate --config blindbucket.yaml s3://acme-photos
```

With `names.encrypt`, `blindbucket migrate-names` moves the bucket's names from the
default name key to the tenant's.

## Watching

- `blindbucket doctor` opens every tenant the configuration can. Its `tenants` check
  fails for a tenant that does not open: the gateway would answer `503` for its buckets.
  It warns about a tenant under the deployment's lock, and about an entry in
  `keys.tenants` the keyring does not have.
- `blindbucket_tenant_open{tenant}` is 0 for a tenant whose keys did not open on an
  instance. The instance's log says why.
- The status page lists the tenants, the key their writes use, their lock, and whether
  each opened.
- `blindbucket tenants list` and `blindbucket keys list` show the keyring itself.

## Destroying a tenant

Nothing here can be undone once the last lock is gone. Read the whole section first.

**1. Make the census come out clean.** With the tenant active on every instance:

```sh
blindbucket tenants census --config blindbucket.yaml acme
```

It reads every object's metadata in the tenant's buckets and counts those not under the
tenant's keys. Each of those would stay readable after the destruction. Rotate them, or
delete them, until it reports none. It needs no key and decrypts nothing.

In a **versioned bucket**, the census counts every version. A version written under the
default tenant's keys before the tenant was active survives its object being replaced,
and `rotate` cannot move a version that is not current: delete such versions, or expire
noncurrent versions with a lifecycle rule, until the census reports none.

**2. Destroy the tenant in the keyring.** Try it with `--dry-run`, which takes the same
census and writes nothing:

```sh
blindbucket tenants destroy --config blindbucket.yaml --dry-run acme
blindbucket tenants destroy --config blindbucket.yaml acme
```

It takes the census again and stops if anything is off the tenant's keys or could not be
read. `--force` destroys it all the same and says how much is left readable. The keyring
is then written with a **tombstone** in the tenant's place. Its buckets stay its own and
are refused with `403`, and its name and key ids are never issued again. The tenant's
lock is not needed for this, so a tenant whose key service is already gone can still be
destroyed.

**3. Roll it out.** Wait until `blindbucket_keyring_generation` is the new generation on
every instance, and every command started on an earlier keyring has ended. Until then
they hold the tenant's keys in memory.

**4. Destroy every lock the tenant ever had.** The command lists them, and what to do
for each. It does not do it itself, so that the gateway's credentials need no right to
delete keys.
- **AWS KMS:** schedule the key's deletion. That takes a key id, so resolve an alias
  first, to the key it pointed to when the tenant was sealed under it. Until the waiting
  period of 7 to 30 days ends, the deletion can be cancelled, and the tenant comes back
  with the key.
- **Vault Transit:** allow the key's deletion and delete it. Vault snapshots and storage
  backups from before still hold it until they are gone.
- **A passphrase:** forget it, every copy of it. Nothing can check that.
- **The deployment's lock:** delete every copy of the keyring from while the tenant was
  under it: backups, Secrets, old releases of the file.

Then remove `keys.tenants.acme` from every instance's configuration.

Destroying a tenant deletes no ciphertext: it stays at the provider as noise, and
deleting it is your choice. The tenant's names in the audit log are unreadable from now
on, while the log still verifies.

**A mistaken `create`.** A tenant whose buckets hold nothing has a clean census even
when it was never activated. It is destroyed without `--force`, with the same steps.
