# Nextcloud through blindbucket

Nextcloud can keep every file in an S3 bucket ("S3 as primary storage"). The
provider then holds all of it in plaintext: Nextcloud's own encryption module
is off by default and keeps its keys on the same server. With blindbucket
between the two, the provider holds ciphertext, and the keys stay with the
gateway.

**Measured:** Nextcloud 35.0.2 against MinIO, with the gateway built from
`main`, by [test/apps/nextcloud/](../../test/apps/nextcloud/). CI runs it on
every change to the gateway and once a week. The row in
[COMPATIBILITY.md](../COMPATIBILITY.md#applications) says what is current.

## What works

Every operation below was run through Nextcloud's own interfaces (WebDAV and
the sharing API) with object names in clear and with `names.encrypt`. Each file
was read back with an identical SHA-256, and every object at the provider is
ciphertext.

| Operation | What Nextcloud does at S3 |
|---|---|
| Installation | about sixty objects: app data, previews, avatars |
| Upload and download, small and 25 MB | `PutObject`, `GetObject` |
| Reading part of a file | ranged `GetObject` |
| Rename and move | nothing: the name lives in Nextcloud's database |
| Copy | `CopyObject`, which moves no data through the gateway |
| Overwrite, and reading the old version | `CopyObject` for the version, then `PutObject` |
| Chunked upload, as the desktop and mobile apps send large files | each chunk as an object, then one `PutObject` of the whole |
| Uploads above Nextcloud's multipart threshold | `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload` |
| Public link share, downloaded without an account | `GetObject` |
| Delete, and emptying the trash | `DeleteObject` |

## Setting it up

This is for a **new** Nextcloud, or one whose bucket is empty. For an existing
one, see [below](#an-existing-nextcloud).

**1. The gateway.** One client for Nextcloud, allowed its bucket and nothing
else. `blindbucket init`, asked for Nextcloud's bucket, writes a configuration
with exactly one such client; the part that matters:

```yaml
upstream:
  endpoint: https://s3.eu-central-1.amazonaws.com   # your provider
  region: eu-central-1
  access_key_id: ${UPSTREAM_ACCESS_KEY_ID}
  secret_access_key: ${UPSTREAM_SECRET_ACCESS_KEY}

clients:
  - name: nextcloud
    access_key_id: ${NEXTCLOUD_ACCESS_KEY_ID}
    secret_access_key: ${NEXTCLOUD_SECRET_ACCESS_KEY}
    buckets: ["nextcloud"]
```

Run `blindbucket doctor` before Nextcloud is pointed at it.

**2. Nextcloud.** The object store in `config/config.php` points at the gateway
rather than at the provider, with the client credentials from step 1, and
addresses the bucket in the path:

```php
'objectstore' => [
  'class' => '\\OC\\Files\\ObjectStore\\S3',
  'arguments' => [
    'bucket' => 'nextcloud',
    'hostname' => 'blindbucket.internal',   // the gateway
    'port' => 9000,
    'use_ssl' => true,                      // see "Between Nextcloud and the gateway"
    'use_path_style' => true,
    'region' => 'eu-central-1',
    'key' => 'the client access key id',
    'secret' => 'the client secret',
    'autocreate' => false,
  ],
],
```

With the official Docker image, the same settings are the `OBJECTSTORE_S3_*`
variables: `HOST`, `PORT`, `BUCKET`, `KEY`, `SECRET`, `SSL`,
`USEPATH_STYLE=true`, `REGION`. The scenario's
[compose.yaml](../../test/apps/nextcloud/compose.yaml) is a working example.

The object store has to be configured **before Nextcloud is installed**.
Nextcloud does not move files between storages when this setting changes.

## Choices

**Object-name encryption is not needed.** In primary-storage mode Nextcloud
stores every file as `urn:oid:<number>`; names, folders and owners are in its
database, not in the bucket. The provider learns nothing from the keys, so
`names.encrypt` adds nothing here, and it brings the listing bound of
[ADR-017](../adr/ADR-017-listing-order-under-name-encryption.md) with it.
Nextcloud works either way: both were measured. What the provider does see is
the number of objects, their sizes and when they change.

**Nextcloud's encryption module can stay off.** With the gateway, the provider
already holds only ciphertext. The module would encrypt a second time, with
keys on the Nextcloud server.

**Multipart part size.** Nextcloud uploads files above `putSizeLimit` (default
100 MiB) in parts of `uploadPartSize` (default 500 MiB). Every part but the last
has to be a multiple of the gateway's chunk size, 64 KiB
([FORMAT §7.3](../FORMAT.md)). Nextcloud's default is, so nothing needs to be
done. A part size changed to something like 6,000,000 bytes makes every large
upload fail: the gateway refuses the completion with a message that names the
fix, but Nextcloud shows only

```
Error while copying file to target location (copied: -1 bytes, expected filesize: …)
```

and the reason is in the gateway's log: `part sizes break the multipart rules
… configure a part size that is a multiple of 65536`.

## Between Nextcloud and the gateway

The gateway receives plaintext, so the hop from Nextcloud to it has to be
trusted or encrypted. Either run the gateway beside Nextcloud on loopback or
an internal network ([the sidecar shape](../../deploy/kubernetes-sidecar.yaml)),
or give it a certificate (`server.tls`, as the
[Helm chart](../../deploy/helm/blindbucket/) does) and set `use_ssl` in
Nextcloud.

## An existing Nextcloud

Not yet. A gateway in front of a bucket that already holds objects cannot read
them: each one answers `ObjectNotEncrypted`, and Nextcloud shows a 503 for that
file. The gateway never serves plaintext it did not encrypt, so this is not a
setting. Encrypting the objects in place is
[#151](https://github.com/LennardGeissler/blindbucket/issues/151).

Until then, the way across is a new Nextcloud behind the gateway, and the
files moved into it through Nextcloud, for instance with the desktop client.

## What you will see in the gateway's log

- **`INFO … client closed the connection before the response was complete`**:
  Nextcloud reads the start of a file and closes the connection, often.
  Nothing is wrong. Releases up to and including 1.4 logged these at ERROR as
  integrity failures, and audited them with `IntegrityCheckFailed`
  ([#150](https://github.com/LennardGeissler/blindbucket/issues/150)).
- **`ObjectNotEncrypted`** for a file stored before the gateway: see
  [An existing Nextcloud](#an-existing-nextcloud).
- **`InvalidRequest` on `CompleteMultipartUpload`**: the part size, see
  [Choices](#choices).
