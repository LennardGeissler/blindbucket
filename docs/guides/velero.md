# Velero through blindbucket

Velero backs up a Kubernetes cluster's resources to an object store:
Deployments, ConfigMaps, and Secrets, with their values, as a tarball per backup,
next to logs and lists of what it holds. A backup of a namespace is a copy of
its Secrets, and with S3 as the store the provider holds them. With
blindbucket between the two, the provider holds ciphertext.

**Measured:** Velero 1.18.4 with velero-plugin-for-aws 1.14.4, in a kind
cluster against MinIO, with the gateway built from `main`, by
[test/apps/velero/](../../test/apps/velero/). CI runs it on every change to the
gateway and once a week. The row in
[COMPATIBILITY.md](../COMPATIBILITY.md#applications) says what is current.

## What works

Run with object names in clear and with `names.encrypt`, one backup storage
location each:

| Step | What it shows |
|---|---|
| The location becomes `Available` | Velero lists the bucket through the gateway |
| Back up a namespace with a ConfigMap, a Secret, a ServiceAccount and a Deployment | the tarball, its logs and its lists are written through the gateway |
| Restore it into another namespace, compare with the original | they are read back through the gateway, identical |
| Delete Velero's record of the backup; the backup sync recreates it | the sync finds the backup by listing `backups/` and reading its metadata |
| `velero backup delete` | Velero deletes the backup's objects and its restore's, through the gateway; afterwards the bucket is empty at the provider |

Velero's file-system backup and its data mover, which copy volume contents
through Kopia into the same bucket, were not measured.

## Setting it up

The gateway, with one client for Velero allowed its bucket and nothing else
(`blindbucket init` writes such a configuration). Velero's AWS plugin takes it
as an S3-compatible store:

```sh
velero install --plugins velero/velero-plugin-for-aws:v1.14.4 \
  --provider aws --bucket velero \
  --secret-file ./credentials-velero \
  --backup-location-config region=eu-central-1,s3ForcePathStyle=true,s3Url=https://blindbucket.internal:9000 \
  --cacert ./gateway-ca.pem \
  --use-volume-snapshots=false
```

`credentials-velero` holds the gateway's client credentials, not the
provider's:

```ini
[default]
aws_access_key_id=the client access key id
aws_secret_access_key=the client secret
```

For a location added to a running Velero, the same goes into
`velero backup-location create`, as in the scenario's
[run.sh](../../test/apps/velero/run.sh). `s3ForcePathStyle=true` keeps the
bucket in the path; without it, the gateway needs `server.base_domain` and a
DNS name per bucket. For an existing location, see
[below](#an-existing-velero).

## Choices

**Object-name encryption hides what was backed up and when.** Velero's keys
carry each backup's name, and names usually say which namespace or schedule
they come from, such as `backups/payments-daily-20261017030000/`. With
`names.encrypt`, the provider sees neither. Listings, the backup sync and
deletes were measured with it on. What remains visible either way is the
number of objects, their sizes and their timing.

## Between Velero and the gateway

The gateway receives plaintext, so the hop from Velero to it has to be trusted
or encrypted. In a cluster, a Service in front of the gateway and a network
policy that only lets Velero reach it, or a certificate (`server.tls`) whose
CA is given to Velero with `--cacert`, as above.

## An existing Velero

A gateway put in front of a bucket that already holds Velero's backups cannot
read them: each object answers `ObjectNotEncrypted`, so the backup sync cannot
read their metadata and they cannot be restored through it. `blindbucket
encrypt-existing` encrypts the objects in place
([ADR-034](../adr/ADR-034-encrypting-existing-objects.md)): stop Velero, by
scaling its deployment to zero, so that no backup, restore or sync runs
meanwhile,, run it with the configuration the gateway will serve with, first
with `--dry-run`, then point Velero at the gateway and start it again.

This was measured with Nextcloud ([its
guide](nextcloud.md#an-existing-nextcloud)), not with Velero; the command does
not depend on the application that wrote the objects.

## What you will see

- **`WARN request failed … NoSuchKey`** for `backups/<name>/velero-backup.json`
  when a backup starts, and for `backups/<name>/<name>-csi-volumesnapshots.json.gz`
  when it is restored: Velero checks that the backup does not exist yet, and
  looks for CSI snapshots a backup without volumes does not have. The gateway
  logs every 404 it relays at WARN.
