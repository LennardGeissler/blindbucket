# Mastodon through blindbucket

Mastodon stores the media its users upload in an object store: images, video,
audio, avatars and headers, each in its original and a preview. That includes
the images attached to direct messages. With S3 as the store, the provider
holds all of it; with blindbucket between the two, the provider holds
ciphertext.

**Measured:** Mastodon 4.7.3 against MinIO, with the gateway built from `main`
and [nginx-s3-gateway](https://github.com/nginx/nginx-s3-gateway) as the media
proxy, by [test/apps/mastodon/](../../test/apps/mastodon/). CI runs it on every
change to the gateway and once a week. The row in
[COMPATIBILITY.md](../COMPATIBILITY.md#applications) says what is current.

## What works

Run with object names in clear and with `names.encrypt`:

| Step | What it shows |
|---|---|
| Upload an image, post it in a direct message | Mastodon stores the original and a preview through the gateway |
| Fetch both from the URLs Mastodon hands out | they are served through the media proxy; the original's pixels are the uploaded image's |
| A 5.6 MB image, with `S3_MULTIPART_THRESHOLD` at 5 MB | stored as a multipart upload, its pixels identical |
| Set the account's avatar | stored and served |
| `tootctl media remove-orphans` after a record is deleted | it lists the bucket through the gateway and deletes exactly the two objects that belong to no record |

At the provider every object is ciphertext.

Video, audio and GIFs were not measured. Mastodon converts them in Sidekiq
with ffmpeg, and the scenario runs no Sidekiq. Remote media that Mastodon
caches from other servers was not measured either.

## How Mastodon serves media, and what to put in front

Mastodon hands browsers a plain URL for each file, such as
`https://files.example.com/media_attachments/files/…/original/….png`. The URL is
unsigned, and anyone with it can fetch the file. Mastodon writes every object
with the `public-read` ACL and relies on the bucket, or a CDN in front of it,
to serve such URLs to anybody.

**The gateway serves no anonymous request.** Pointed at the gateway directly,
every media URL answers `403 AccessDenied`, "the request is not signed". The
scenario checks this for each image it uploads. The gateway does verify
presigned URLs ([ADR-019](../adr/ADR-019-presigned-urls.md)), but Mastodon
issues none.

What goes in between is a **media proxy that signs**: it receives the
browser's anonymous `GET`, signs it with a credential of its own, and fetches
from the gateway. `S3_ALIAS_HOST` points Mastodon's URLs at it. The scenario
uses nginx-s3-gateway, which is nginx with SigV4 signing:

```sh
# The media proxy, reachable by browsers as files.example.com
S3_SERVER=blindbucket.internal
S3_SERVER_PORT=9000
S3_SERVER_PROTO=https
S3_BUCKET_NAME=mastodon
S3_REGION=eu-central-1
S3_STYLE=path
S3_SERVICE=s3
AWS_SIGS_VERSION=4
AWS_ACCESS_KEY_ID=the media proxy's client access key id
AWS_SECRET_ACCESS_KEY=the media proxy's client secret
ALLOW_DIRECTORY_LIST=false
```

A plain `proxy_pass` to the bucket, as Mastodon's own documentation suggests
for caching, does not work in front of the gateway: it forwards the request
unsigned.

What this means:

- **Media stays as public as it is in any Mastodon.** Whoever has a URL gets
  the file, from the proxy. What changes is the provider: it holds
  ciphertext, and only the gateway can read it.
- **The proxy needs a client of its own.** Give it a separate access key, so
  that it can be revoked without touching Mastodon's. The gateway cannot limit
  a client to reads: it allows a client its buckets, not operations on them.
  The proxy's key can therefore write and delete too, and belongs only where
  nginx runs.
- **The proxy caches.** nginx-s3-gateway keeps a 200 for an hour by default
  (`PROXY_CACHE_VALID_OK`), so a deleted file stays visible there for up to
  that long. The scenario checks deletions at the gateway for this reason.

## Setting it up

The gateway, with two clients allowed Mastodon's bucket and nothing else: one
for Mastodon, one for the media proxy. `blindbucket init` writes the first,
and the second is a copy with its own keys. Then Mastodon's storage points at
the gateway, and its media URLs at the proxy:

```sh
S3_ENABLED=true
S3_ENDPOINT=https://blindbucket.internal:9000   # the gateway
S3_REGION=eu-central-1
S3_BUCKET=mastodon
AWS_ACCESS_KEY_ID=Mastodon's client access key id
AWS_SECRET_ACCESS_KEY=Mastodon's client secret
S3_ALIAS_HOST=files.example.com                 # the media proxy
```

With `S3_ENDPOINT` set, Mastodon addresses the bucket path-style. The
`public-read` ACL it sends is accepted and not passed on: the gateway forwards
no ACL to the provider, and the bucket there stays private, which it should.
Neither does it forward a storage class, so `S3_STORAGE_CLASS` has no effect.

`S3_MULTIPART_THRESHOLD` (default 15 MB) can stay as it is. Above it, the AWS
SDK uploads parts of 5 MiB, a multiple of the gateway's 64 KiB chunk, which
the gateway accepts.

## Choices

**Object-name encryption hides which record a file belongs to.** Mastodon's
keys name the kind of media, `media_attachments/files/` or
`accounts/avatars/`, and the record's id. A Mastodon id carries the time it
was created. With `names.encrypt` the provider sees neither, and
`remove-orphans`, which finds its work by listing those prefixes, was measured
with it on. What remains visible either way is the number of objects, their
sizes and their timing.

## Between Mastodon and the gateway

The gateway receives plaintext from two clients, Mastodon and the media proxy,
so both hops have to be trusted or encrypted. Run the gateway on an internal
network next to both, or give it a certificate (`server.tls`) and use `https`
in `S3_ENDPOINT` and `S3_SERVER_PROTO`.

## An existing Mastodon

A gateway in front of a bucket that already holds Mastodon's media cannot read
it: each object answers `ObjectNotEncrypted`, and every file uploaded before
disappears from the instance. Encrypting the objects in place is
[#151](https://github.com/LennardGeissler/blindbucket/issues/151). Until then,
the gateway can only be put in front of a new bucket.

## What you will see

- **`WARN rejecting a request that failed verification`, then `AccessDenied`**
  for a `GetObject`: something asked the gateway for a media URL without
  signing it. Usually that means `S3_ALIAS_HOST` is not set, or points at the
  gateway instead of the media proxy.

In the measured operations, Mastodon itself caused no WARN.
