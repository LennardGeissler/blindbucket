# Grafana Loki through blindbucket

Loki keeps the logs it receives in an object store: chunks of log lines, a
TSDB index, and its compactor's state. Logs carry whatever the applications
wrote into them -- addresses, tokens, user ids -- and with S3 as the store the
provider holds all of it. With blindbucket between the two, the provider
holds ciphertext.

**Measured:** Loki 3.7.8 in single-binary mode against MinIO, with the gateway
built from `main`, by [test/apps/loki/](../../test/apps/loki/). CI runs it on
every change to the gateway and once a week. The row in
[COMPATIBILITY.md](../COMPATIBILITY.md#applications) says what is current.

## What works

Run with object names in clear and with `names.encrypt`:

| Step | What it shows |
|---|---|
| Push 600 lines in three streams, flush, restart Loki without a WAL | chunks and the index are written through the gateway |
| Query every line after the restart, compare with what was pushed | they are read back through the gateway, identical |
| A deletion request for one stream, carried out by the compactor | the compactor lists, rewrites the index, and deletes the stream's chunk through the gateway; afterwards exactly the other two streams' 400 lines remain |

The compactor also merges a day's index files into one, as it did in the runs
inspected. At the provider every object is ciphertext.

## Setting it up

The gateway, with one client for Loki allowed its bucket and nothing else
(`blindbucket init` writes such a configuration). Then Loki's storage points
at the gateway instead of the provider:

```yaml
common:
  storage:
    s3:
      endpoint: blindbucket.internal:9000   # the gateway
      bucketnames: loki
      region: eu-central-1
      access_key_id: the client access key id
      secret_access_key: the client secret
      s3forcepathstyle: true
      insecure: false                       # see "Between Loki and the gateway"
```

With `-config.expand-env=true`, the credentials can come from the
environment, as in the scenario's [loki.yaml](../../test/apps/loki/loki.yaml).
Every other part of Loki's configuration is unchanged: schema, index and
compactor all go through `common.storage`. For an existing Loki, see
[below](#an-existing-loki).

## Choices

**Object-name encryption hides who and when, and works.** Loki's keys say
more than Nextcloud's: the tenant (`fake` without authentication, otherwise its
id), a fingerprint per stream, and the day of every index table. Where tenants
are named after customers, `names.encrypt` keeps those names from the provider.
The compactor's listings and deletes were measured with it on. What remains
visible either way is the number of objects, their sizes and their timing.

## Between Loki and the gateway

The gateway receives plaintext, so the hop from Loki to it has to be trusted or
encrypted: run the gateway beside Loki on loopback or an internal network, or
give it a certificate (`server.tls`) and set `insecure: false`.

## An existing Loki

A gateway put in front of a bucket that already holds Loki's data cannot read
it: each object answers `ObjectNotEncrypted`, so older logs disappear from
queries. `blindbucket encrypt-existing` encrypts the objects in place
([ADR-034](../adr/ADR-034-encrypting-existing-objects.md)): stop Loki -- a clean
stop flushes what it holds in memory --, run it with the configuration the
gateway will serve with, first with `--dry-run`, then point Loki at the gateway
and start it again.

This was measured with Nextcloud ([its
guide](nextcloud.md#an-existing-nextcloud)), not with Loki; the command does not
depend on the application that wrote the objects.

## What you will see

- **`WARN request failed … NoSuchKey`** for `index/delete_requests/delete_requests.gz`
  and `loki_cluster_seed.json`, while Loki starts: it looks for files it has
  not written yet. The gateway logs every 404 it relays at WARN.
- **A deleted stream still answers queries until Loki restarts**, after its
  compactor has removed it from storage. Loki answers from its caches. This is
  the same without the gateway: the scenario measured it against MinIO
  directly, too.
