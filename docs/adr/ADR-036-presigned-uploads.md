# ADR-036 — Presigned uploads: served when the operator sets a size limit, with CORS for the browser

**Status:** Proposed
**Date:** 2026-10-19
**Milestone:** M14
**Implements:** [#131](https://github.com/LennardGeissler/blindbucket/issues/131)
**Builds on:** [ADR-005](ADR-005-checksums.md), [ADR-006](ADR-006-upload-token.md), [ADR-014](ADR-014-part-salts-in-the-manifest.md), [ADR-019](ADR-019-presigned-urls.md)

## Context

A presigned URL through the gateway can only read. [ADR-019](ADR-019-presigned-urls.md)
deferred `PUT` rather than refusing it for good: it is the one other real use, the
browser upload, where a backend that holds a credential hands a browser a URL to
upload one file to. #131 asks whether that can be served safely, and what it would take.

### What the measured applications need

None of the five applications measured in M12 needs it. Nextcloud, Loki and Velero
upload with their own credentials. GitLab's Workhorse uploads with its own S3 client
([gitlab.md](../guides/gitlab.md)), and Mastodon's uploads go through Rails. The case
is real, but no application this project tests needs it. It is the generic web
backend, often with Uppy in the browser, which uploads anything over 100 MiB as a
multipart upload with a presigned URL per part.

### What a signature binds, measured

Presigning is local, so what a URL binds can be read off the URL. Both SDKs
measured on 2026-10-19, boto3 1.43.114 and the AWS SDK for JavaScript v3.1152.0,
presign `PutObject` and `UploadPart`:

| The backend sets | boto3 | JavaScript v3 |
|---|---|---|
| nothing | `host` signed | `host` signed, and `x-amz-checksum-crc32=AAAAAA==` and `x-amz-sdk-checksum-algorithm` in the query |
| `ContentLength` | `content-length` signed | `content-length` signed |
| `ChecksumSHA256` | `x-amz-checksum-sha256` signed, as a header | `x-amz-checksum-sha256` in the query |
| `ContentMD5` | `content-md5` signed | `content-md5` signed |
| `IfNoneMatch: "*"` | `if-none-match` signed | `if-none-match` signed |
| `Metadata` | `x-amz-meta-*` signed, as headers | `x-amz-meta-*` in the query |
| `ContentType` | `content-type` signed | not signed |

Three things follow from it:

- **The method, the key and the window are always bound.** The method is the first
  line of the canonical request, so a `PUT` URL cannot be used for anything else.
- **Size, content and one-time use are bound only if the backend asks.** The body is
  `UNSIGNED-PAYLOAD`. What limits it is a signed `Content-Length`, a signed checksum
  or a signed `If-None-Match`, and each is the backend's choice.
- **JavaScript v3 moves `x-amz-*` values into the query.** S3 reads them there as
  the headers they stand for. The gateway's router refuses every query parameter it
  does not know, so today it refuses every such URL. By default the SDK also binds
  the CRC32 of an *empty* body, `AAAAAA==`, so a URL made with its defaults accepts
  only an empty upload once that checksum is honoured.

### What the gateway does not do today

- **CORS.** A browser sends a `PUT` to another origin only after an `OPTIONS`
  preflight, and the gateway answers no preflight. Serving presigned `PUT` alone
  would leave the browser case as broken as it is now.
- **Conditional writes from a client.** `putObject` never reads `If-None-Match` or
  `If-Match`, and the upstream request has no field for them. A client that asks for
  a conditional write gets an unconditional one, silently. This is a defect on its
  own, apart from presigning ([#168](https://github.com/LennardGeissler/blindbucket/issues/168)), and has to be fixed first: a signed `If-None-Match: *`
  is the only way a backend can make an upload URL single-use.

## Decision

**Yes.** Presigned `PutObject` and `UploadPart` are served, under four conditions.

### 1. Only with a size limit the operator sets

```yaml
server:
  presign:
    uploads:
      max_size: 100MiB      # unset: presigned uploads are refused, as today
      max_expiry: 1h        # the default
```

Presigned uploads are refused unless `presign.uploads.max_size` is set. That setting
switches them on, so there is no configuration in which a URL handed to a browser
can upload without a bound.

The limit holds before the first byte is read. A presigned upload must carry a
`Content-Length`, which every browser sends for a file, and one over the limit is
answered `400 EntityTooLarge` without reading the body. A presigned body may not be
`aws-chunked`, because there is no signature to chain its chunks to. It holds per
request: for a multipart upload, each part is bounded. The total stays the backend's
to bound, since the backend creates the upload, decides how many parts to sign and
completes it with its own credential.

A signed `Content-Length` binds the size exactly, and the canonical request already
checks it. The operator's limit is what holds when the backend binds nothing.

`presign.uploads.max_expiry` caps an upload URL's window separately from
`presign.max_expiry`, which GitLab needs at four hours or more for downloads. An
upload URL is a write, and can be used again until it expires. One hour covers
boto3's default of 3600 seconds and JavaScript v3's 900.

### 2. What the backend binds, the gateway honours

- **A checksum** (`Content-MD5`, `x-amz-checksum-*`), signed as a header or
  carried in the query, is verified as [ADR-005](ADR-005-checksums.md) verifies
  every checksum: over the plaintext, settled before the encrypter's last chunk, so
  a body that does not match is never stored. With a checksum bound, the URL accepts
  that one content and nothing else.
- **`If-None-Match: *`** makes the URL single-use, once the defect above is fixed: a
  second upload to the same key is answered `412`. The gateway keeps no record of
  which URLs have been used, for the same reason it keeps no upload state
  ([ADR-006](ADR-006-upload-token.md)).
- **`x-amz-*` values in the query** are read as the headers they stand for, on a
  presigned upload only, and only these: `x-amz-checksum-{crc32,crc32c,crc64nvme,sha1,sha256}`,
  `x-amz-sdk-checksum-algorithm` and `x-amz-meta-*`. `x-amz-tagging` is refused as
  the header is ([ADR-012](ADR-012-copy-semantics.md), #132). A value given both as
  a header and in the query is refused, not merged. Every other query parameter is
  refused, as now. Like the six signing parameters, none of them is forwarded to the
  provider.
- **An `x-amz-*` header the URL did not sign** is refused, as S3 refuses it. The
  holder of the URL is not its signer, and an unsigned `x-amz-meta-*` would let them
  store metadata the backend never agreed to. Headers outside `x-amz-*`, such as
  `Content-Type`, may be sent unsigned, as on S3: JavaScript v3 does not sign
  `Content-Type`.

### 3. CORS, from the gateway's own configuration

```yaml
server:
  cors:
    allowed_origins: ["https://app.example"]
```

With `allowed_origins` set, the gateway answers a preflight itself, and only for an
origin on the list. It never forwards a preflight to the provider:

- `OPTIONS` is answered without authentication. A preflight carries none, by the
  browser's design. The answer names the methods `GET`, `HEAD` and `PUT`, the
  request headers an upload may sign, and a `Max-Age`, and nothing about the bucket
  or the object.
- The responses to allowed origins carry `Access-Control-Allow-Origin` with that
  origin, never `*`, plus `Vary: Origin` and `Access-Control-Expose-Headers: ETag`
  and the checksum headers. A multipart upload in the browser needs the `ETag`,
  because the part's salt travels in it to the completion
  ([ADR-014](ADR-014-part-salts-in-the-manifest.md)).
- No `Access-Control-Allow-Credentials`. A presigned URL carries its own
  authority, and a browser's cookies mean nothing to the gateway.
- The S3 bucket-CORS sub-resource (`?cors`) stays refused. The provider would store
  that configuration, and it governs the provider's endpoint, which a browser never
  reaches.

Unset, the gateway answers no preflight, as now. A backend that uploads on the
server side needs none of this.

### 4. Not on the operations a backend does itself

`CreateMultipartUpload`, `CompleteMultipartUpload`, `AbortMultipartUpload`,
`DeleteObject`, copies and every bucket operation stay refused by URL. In the browser
pattern, the backend does them with its own credential. A presigned `UploadPart`
carries the sealed upload token in its query. That reveals nothing, because the token
is sealed and bound to the bucket and key. It is still worth saying, because the
token now reaches a URL.

**Presigned POST**, the form-and-policy mechanism, stays out of scope, for ADR-019's
reason: it is a different protocol.

### What it inherits, and what it does not

A presigned upload is an ordinary `PutObject` or `UploadPart` once it is
authenticated. It is encrypted, its name is encrypted if names are, the rollback
index records it, and the audit log records it under the credential that signed the
URL. The audit entry does not say that the write came by URL. That would add a field
to the audit format ([ADR-016](ADR-016-audit-log.md)), and it is left until someone
needs to tell the two apart.

## Alternatives considered

**Keep refusing.** Honest, and costs nothing. Rejected because the reason ADR-019 gave
for reads does not carry over: a link preview issues a `GET`, and a `PUT` URL does not
verify as a `GET`. What a `PUT` URL risks is its holder, who is by design untrusted.
That is what the size limit, the separate expiry and the bindings answer.

**Serve `PutObject` only, not `UploadPart`.** One operation fewer to check. Rejected
because the browser library most backends use uploads anything over 100 MiB in parts.
Serving one without the other would break the feature at a size nobody chose.
`UploadPart` already goes through the same body path, and the upload token is bound
to its key.

**A size limit with a default, on by default.** Same decision with one setting fewer.
Rejected because any default is wrong for someone, and a URL handed to an untrusted
browser should not be able to upload until an operator has said how much.

**A record of used URLs, to make every URL single-use.** Rejected: it is state shared
between instances, which [ADR-006](ADR-006-upload-token.md) declined for uploads. A
backend that wants one use signs `If-None-Match: *`.

**Require a signed checksum.** It would bind every upload to one content. Rejected
because a browser cannot cheaply hash a large file before uploading, so most
backends cannot know the checksum when they sign. Where a backend can, it binds one,
and the gateway honours it.

**CORS from the bucket's `?cors` configuration.** It would let a client manage CORS
with the S3 API. Rejected because the provider stores that configuration, and it
describes a provider endpoint the browser never talks to. Translating it would mean
reading it from the provider on every preflight.

**`Access-Control-Allow-Origin: *`.** It would need no list. Rejected because naming
the origin costs one line of configuration, and a wildcard lets any page read every
response its visitors' browsers can fetch.

## Consequences

**Positive.**

- The browser-upload pattern works, single files and multipart, in the same form as
  against S3.
- No presigned upload is ever unbounded. The operator's limit holds before the first
  byte, and a backend can bind more: the exact size, the content and a single use.
- The conditional-write defect gets fixed, which matters to every client that sends
  `If-None-Match`, not only to presigned ones.
- No new cryptography and no format change.

**Negative.**

- **An upload URL can overwrite its key until it expires**, as many times as it is
  used, unless the backend signs `If-None-Match: *`. In a versioned bucket every use
  leaves a version.
- **The gateway must be reachable from the browser**, as for presigned reads.
- **The body is covered by TLS, not by a signature**, unless a checksum is bound.
- **JavaScript v3 with its defaults binds an empty body's CRC32**, so its URLs fail
  with `BadDigest` for every real file. The fix is on the backend: set
  `requestChecksumCalculation: "WHEN_REQUIRED"`, or bind the real checksum. The guide
  has to say so, prominently.
- An unauthenticated `OPTIONS` path, answered from configuration alone.
- Three settings more, and an upload path whose bound is per request, not per upload.

## Implementation order

1. Conditional writes from clients: `If-None-Match` and `If-Match` on `PutObject`
   and `CompleteMultipartUpload`, forwarded to the provider, with
   `COMPATIBILITY.md` naming the providers that ignore them (Garage does, for the
   completion). This is [#168](https://github.com/LennardGeissler/blindbucket/issues/168) and its own PR, because
   it is a defect today.
2. Presigned `PutObject` and `UploadPart`, with the two settings, the query values
   read as headers, and attack tests: an expired URL, an altered key, method, size,
   checksum or `max_size`, a URL used twice with and without `If-None-Match`, a body
   over the limit, `aws-chunked` by URL, a value both in the header and in the query.
3. CORS, with tests for a preflight from a listed origin, an unlisted one and none,
   and an end-to-end browser upload in a headless browser.
4. A guide, "Browser uploads", with the backend's side for boto3 and JavaScript v3.
