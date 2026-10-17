# GitLab through blindbucket

GitLab keeps much of what its users produce in object storage: attachments on
issues and merge requests, CI job artifacts, Git LFS objects, packages. A
self-hosted GitLab on a public cloud bucket hands the provider all of it in
plaintext, and the names alone say a lot: which project, which pipeline, and,
for LFS, the SHA-256 of every file. With blindbucket between the two, the
provider holds ciphertext.

**Measured:** GitLab CE 19.5.0 (Linux package, in Docker) against MinIO, with
the gateway built from `main`, by
[test/apps/gitlab/](../../test/apps/gitlab/). CI runs it on every change to the
gateway and once a week. The row in
[COMPATIBILITY.md](../COMPATIBILITY.md#applications) says what is current.

**Needs a gateway with [ADR-032](../adr/ADR-032-response-header-overrides.md)**,
the first release after 1.4.0. GitLab puts `response-content-disposition` on
every download, which earlier releases refuse, so no file stored through them
can be downloaded again.

## What works

Run with object names in clear and with `names.encrypt`:

| Step | What it shows |
|---|---|
| An attachment uploaded to a project and downloaded | GitLab redirects to a presigned URL at the gateway; the file comes back identical, under its own name |
| A generic package, downloaded by redirect and proxied through GitLab | both identical |
| A 12 MB LFS object, through the batch API git-lfs uses | uploaded, and read back by the presigned URL the batch answer hands out, its SHA-256 the oid |
| A CI job's artifact archive, uploaded by the runner protocol | the archive by redirect and one file out of it by Workhorse, both identical; the artifact browser lists the file |
| An attachment deleted | gone from the bucket, the other attachment kept |

At the provider every object is ciphertext.

**Uploads need no presigned URLs.** In the consolidated form of the
configuration, Workhorse uploads with its own S3 client and the connection's
credentials, then Rails moves the object from `tmp/uploads/` to its place. The
gateway serves both, and nothing GitLab does needs presigned uploads
([#131](https://github.com/LennardGeissler/blindbucket/issues/131)).

Not measured: the container registry, Pages, Terraform state, the dependency
proxy, external diffs, secure files and backups; a real runner and a real
git-lfs client, rather than their protocols spoken with curl; files over 5 GB;
and the deletion of artifacts, LFS objects and packages, which GitLab does
later, in background jobs.

## Setting it up

The gateway, with one client for GitLab allowed its buckets and nothing else
(`blindbucket init` writes such a configuration), and two changes to it:

```yaml
server:
  presign:
    max_expiry: 5h   # at least 4h15m, see below
```

Then GitLab's object storage, in the consolidated form, points at the gateway:

```ruby
gitlab_rails['object_store']['enabled'] = true
gitlab_rails['object_store']['connection'] = {
  'provider' => 'AWS',
  'region' => 'eu-central-1',
  'endpoint' => 'https://blindbucket.internal:9000',   # the gateway
  'path_style' => true,
  'aws_access_key_id' => "the client access key id",
  'aws_secret_access_key' => "the client secret",
}
gitlab_rails['object_store']['objects']['artifacts']['bucket'] = 'gitlab-artifacts'
gitlab_rails['object_store']['objects']['lfs']['bucket'] = 'gitlab-lfs'
gitlab_rails['object_store']['objects']['uploads']['bucket'] = 'gitlab-uploads'
gitlab_rails['object_store']['objects']['packages']['bucket'] = 'gitlab-packages'
```

And one feature flag off, as an administrator:

```sh
curl -X POST -H "PRIVATE-TOKEN: <admin token>" \
  https://gitlab.example.com/api/v4/features/s3_multithreaded_uploads -d value=false
```

### Why the feature flag

With `s3_multithreaded_uploads` on, GitLab moves a file over 10 MB from
`tmp/uploads/` with fog-aws's multipart copy. fog-aws computes each part's
range one byte too long, so every part is 10 MiB and one byte. S3 accepts
that. The gateway does not: a multipart object's parts must be multiples of its
64 KiB chunk ([FORMAT §7.3](../FORMAT.md)), and the completion is refused with
`InvalidRequest`, "part sizes break the multipart rules". The LFS upload, the
artifact upload or the attachment then fails with a 500.

With the flag off, GitLab moves the file with a single `CopyObject`. The
gateway copies that at the provider, part by part, without the data passing
through it.

### Why `max_expiry` of at least 4h15m

When a job's artifact archive arrives, Workhorse reads it back to index its
files, through a presigned URL GitLab signs for four hours and fifteen
minutes. With `blindbucket init`'s default of `1h` the gateway refuses that
URL, Workhorse indexes nothing, and the artifact browser shows an empty
archive. The archive itself is stored and downloads correctly. The gateway's
own default, without `init`, is S3's seven days.

## Downloads, and who has to reach the gateway

By default (`proxy_download: false`), GitLab answers a download with a redirect
to a presigned URL, and the URL names the `endpoint` of the connection above.
So whatever downloads, has to reach the gateway under that name: browsers,
git-lfs, and runners fetching artifacts from earlier jobs. Give it a name and a
certificate they can use. The URL carries the object's key in clear, which
[ADR-019](../adr/ADR-019-presigned-urls.md) and the
[threat model](../THREAT_MODEL.md) discuss.

Where the gateway should stay internal, `proxy_download: true` makes GitLab
fetch the file itself and pass it on. The scenario measured that with a
package downloaded with `download_mode=proxy`; `proxy_download: true` for every
kind of object was not measured.

## Choices

**Object-name encryption hides more here than for most applications.**
GitLab's keys carry the SHA-256 of the project's id (`6b/86/6b86b273…` is
project 1, and ids are small, so anyone can compute them); the date and id of
every CI job; each attachment's file name; and for LFS, the SHA-256 of the
file's content. Whoever holds a copy of a file can check whether the bucket
holds it too. With `names.encrypt` the provider sees none of this, and every
step above was measured with it on. What remains visible either way is the
number of objects, their sizes and their timing.

## Between GitLab and the gateway

The gateway receives plaintext from GitLab's Rails and Workhorse, and, with
`proxy_download: false`, from everyone who downloads. Every one of those hops
has to be trusted or encrypted: give the gateway a certificate (`server.tls`)
and an `https` endpoint.

## An existing GitLab

A gateway in front of buckets that already hold GitLab's objects cannot read
them: each object answers `ObjectNotEncrypted`, so every file stored before
fails to download. Encrypting the objects in place is
[#151](https://github.com/LennardGeissler/blindbucket/issues/151). Until then,
the gateway can only be put in front of new buckets.

## What you will see

- **`INFO … client closed the connection before the response was complete`**
  for artifact archives: Workhorse reads the part of an archive it needs, to
  serve one file out of it or to index it, and closes the connection. Nothing
  is wrong.
- **`WARN … InvalidRequest` on `CompleteMultipartUpload`, "part sizes break
  the multipart rules"**: `s3_multithreaded_uploads` is on, see
  [Why the feature flag](#why-the-feature-flag).
- **`WARN rejecting a request that failed verification`, "X-Amz-Expires is
  4h15m0s, and this gateway accepts at most …"**: `presign.max_expiry` is too
  short, see [Why `max_expiry`](#why-max_expiry-of-at-least-4h15m).

In the measured operations, with both settings as above, GitLab itself caused
no WARN.
