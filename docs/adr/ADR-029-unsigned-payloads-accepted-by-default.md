# ADR-029 — Unsigned payloads are accepted by default, and signed ones can be required

**Status:** Accepted
**Date:** 2026-10-14
**Milestone:** post-1.0
**Implements:** `internal/auth` (`Verifier.payloadMode`), `internal/config` (`server.allow_unsigned_payload`, `server.require_signed_payload`), the Helm chart's `server.requireSignedPayload` ([#114](https://github.com/LennardGeissler/blindbucket/issues/114))

## Context

A SigV4 request says in `x-amz-content-sha256` how its body is protected. Three
modes put the body under the signature: the SHA-256 of the whole body, and
aws-chunked with a signature per chunk, with or without a trailer. Two do not:
`UNSIGNED-PAYLOAD`, and `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, aws-chunked with a
checksum in a trailer that no key goes into.

Since 0.1 the gateway refused `UNSIGNED-PAYLOAD` unless
`server.allow_unsigned_payload` was set. The comment on the setting said why:
without it the body between client and proxy is covered by the signature. That
was not true. `STREAMING-UNSIGNED-PAYLOAD-TRAILER` was accepted on every listener
regardless of the setting, and it is what current AWS SDKs send for object data
over HTTPS. The AWS CLI's uploads to a TLS listener had always arrived that way,
unsigned. The setting refused one of the two unsigned modes and left the other
open, and the documentation described the protection as complete.

AWS CLI 2.38.0, released 2026-10-13, made the difference visible. It makes the
CRT transfer client the default on every host, and that client sends
`UNSIGNED-PAYLOAD` on every `GetObject`, `HeadObject` and
`CreateMultipartUpload` (none of which has a body) and on
`CompleteMultipartUpload` (whose body is the part list). Against a gateway with
the default configuration, every download and every multipart upload failed,
over HTTPS and HTTP alike. Measured on 2026-10-14
([#114](https://github.com/LennardGeissler/blindbucket/issues/114),
[COMPATIBILITY.md](../COMPATIBILITY.md#aws-cli-238-and-the-crt-transfer-client)).
`rclone` and `mc` had needed the setting for the same reason since they were
first measured.

What the setting actually decided, then: whether a client that sends
`UNSIGNED-PAYLOAD` works. It did not decide whether an attacker on the hop
between client and gateway could alter an upload. With the trailer mode
accepted, they always could, unless TLS stopped them. Threat model A6 says as
much: the client hop is protected "only insofar as TLS or sidecar deployment
covers it".

## Decision

**`UNSIGNED-PAYLOAD` is accepted by default. A new setting,
`server.require_signed_payload`, refuses both unsigned modes for deployments that
need the body under the signature.**

1. `server.allow_unsigned_payload` defaults to `true`. An explicit `false` keeps
   its meaning: it refuses `UNSIGNED-PAYLOAD` and nothing else. Configurations
   written before this change behave as they did, which ADR-021 asks of a minor
   release. Only configurations that never mentioned the key change, and they
   change from refusing a request to serving it.
2. `server.require_signed_payload: true` refuses `UNSIGNED-PAYLOAD` and
   `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, whatever `allow_unsigned_payload` says.
   Under it, a body the gateway accepts is covered by the client's signature,
   which is the protection the old comment claimed. It is the setting for a
   listener whose hop is plaintext and untrusted, such as TLS ending at a load
   balancer in front of the gateway with a network between them that the
   operator does not control.
3. The gateway warns at startup when the listener carries plaintext beyond
   loopback without TLS and signed payloads are not required. The warning about
   `allow_unsigned_payload` itself is gone: it would now fire on every start, and
   the setting is not where the risk sits.
4. Presigned URLs are unaffected. They reach only `GET` and `HEAD` (ADR-019),
   which carry no body.

## Alternatives considered

**Keep the default and document the CLI's workaround**
(`preferred_transfer_client = classic`). Rejected. A current AWS CLI against a
default gateway would fail on its first download, and the refusal buys nothing:
the data the CLI uploads over HTTPS is unsigned in either case.

**Accept `UNSIGNED-PAYLOAD` only on requests without a body.** That covers
`GetObject`, `HeadObject` and `CreateMultipartUpload`, which are most of what CRT
sends that way, and leaves no body to protect. Rejected because it does not
cover `CompleteMultipartUpload`, so every multipart upload of the CLI would
still fail, and because it adds a third rule to explain without making any body
safer.

**Accept unsigned payloads only on a TLS listener.** It looks like the honest
rule, but the gateway cannot see the hop that matters. Behind an ingress that
ends TLS, the listener is plain HTTP while the client spoke HTTPS and sends
unsigned bodies, so this rule would break the common Kubernetes deployment. A
TLS listener with an untrusted proxy in front of it would pass unnoticed. Only
the operator knows whether the hop is trusted, so it is a setting rather than
an inference.

**Make `allow_unsigned_payload: false` refuse both modes.** That would have
given the old key the meaning its comment claimed. Rejected: an existing
configuration with an explicit `false`, running the AWS CLI over HTTPS (whose
uploads are trailer-mode), would stop working on upgrade. ADR-021 rules that
out for a minor release, and a new key leaves the old one meaning what it meant.

## Consequences

**Positive.**

- AWS CLI 2.38 and later, `rclone` and `mc` work against a default gateway, with
  nothing to configure on either side.
- The documented protection now exists. `require_signed_payload` guarantees
  what the old default only appeared to.
- The settings say what they do. The comments on both keys, `verify.go` and
  COMPATIBILITY.md no longer claim a body is signed when it is not.

**Negative.**

- A client that sends `UNSIGNED-PAYLOAD` over plain HTTP is now served where it
  was refused, `rclone` and `mc` among them. On an untrusted plaintext hop, an
  attacker can alter its uploads. That was already true of every
  trailer-mode client, and against the AWS CLI the new acceptance adds only the
  part list of a multipart completion. It is still a refusal the default no
  longer makes, which is what the startup warning and `require_signed_payload`
  are for.
- `require_signed_payload` is demanding. The AWS CLI meets it only over HTTP and
  with `preferred_transfer_client = classic`. Over HTTPS both of its transfer
  clients send object data unsigned. A deployment that needs it has to choose
  its clients for it.
- Refused payload modes still answer `501 NotImplemented`, as before. For a
  mode the listener refuses by policy, `AccessDenied` would describe it better,
  but changing an error code a client already sees is left for its own change.
