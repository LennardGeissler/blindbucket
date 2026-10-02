# ADR-024 — AWS credentials without the SDK: a resolver of our own, chosen explicitly

**Status:** Accepted
**Date:** 2026-10-02
**Milestone:** post-1.0
**Implements:** `internal/awscreds`; then `internal/upstream`, `internal/rootkey` (KMS), `internal/config`, the Helm chart
**Amends:** [ADR-013](ADR-013-root-key-sources.md), whose credential handling took explicit keys only

## Context

The gateway talks to AWS in two places: the upstream S3 provider on every
request, and KMS once at startup to unseal the keyring. Both take credentials
in exactly one form — an access key id and a secret, optionally a session
token, written into the configuration or referenced from the environment with
`${VAR}`. [ADR-013](ADR-013-root-key-sources.md) recorded the cost of that when
it chose a hand-written KMS client: "credential sources the SDK supports —
instance roles, web identity, SSO — are not available".

That limit was tolerable while the gateway ran as a sidecar next to a process
that already had keys. It is not tolerable for the Helm chart on EKS. A pod on
EKS gets its credentials from IRSA (a projected service-account token exchanged
at STS) or from EKS Pod Identity (a credentials endpoint on a link-local
address); on EC2, from the instance role through IMDS. Each is the platform's
answer to "do not put long-lived keys in a Secret", and the chart could use
none of them. Worse, temporary credentials were never refreshed: a session
token passed in by hand expires, and the gateway with it.

The SDK solves all of this in `github.com/aws/aws-sdk-go-v2/config`. Measured on
2026-10-02, adding it to this module adds **twelve modules** — `credentials`,
`feature/ec2/imds`, `service/sts`, `service/sso`, `service/ssooidc`,
`service/signin`, `internal/configsources`, `internal/endpoints/v2`,
`internal/v4a`, two `service/internal` helpers and `config` itself — to a build
whose AWS dependencies today are two: the core module, for the SigV4 signer and
the credential types, and `smithy-go` under it. The module's direct dependency
list is six entries long, and each was a decision (CONTRIBUTING).

## Decision

### A resolver of our own, on the SDK's own interface

`internal/awscreds` implements the sources a machine runs under and hands back an
`aws.CredentialsProvider` — the interface the core module already defines and
the signer already consumes. Nothing new is imported. It speaks four protocols,
each a few hundred lines with its tests:

| Source | What it is | Protocol |
|---|---|---|
| `static` | keys in the configuration, as today | — |
| `env` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | — |
| `profile` | `~/.aws/credentials` and `~/.aws/config`, under `AWS_PROFILE` | INI; STS `AssumeRole`, signed |
| `web_identity` | IRSA, GitHub's OIDC token, any OIDC federation | STS `AssumeRoleWithWebIdentity`, unsigned |
| `container` | ECS task roles, EKS Pod Identity | a JSON endpoint on a link-local address |
| `imds` | the EC2 instance role | IMDSv2 |
| `chain` | the first of the above whose configuration is present | — |

### Chosen explicitly, per section

The configuration names a source: `upstream.credential_source` and
`keys.awskms.credential_source`. Keys in the configuration are `static`, as
before, and remain the default; keys **and** another source are an error,
because they are two answers to one question. **Neither keys nor a source is
still a startup error**, as it is today — the SDK's behaviour, falling back to
whatever the environment offers, would let a forgotten key quietly pick up an
instance role with more rights than the gateway should have.

### The chain selects by configuration, and does not fall through

`chain` follows the SDKs' order — `AWS_PROFILE`, keys in the environment,
`AWS_WEB_IDENTITY_TOKEN_FILE`, a default profile that says something about
credentials, a container endpoint, and IMDS last — but it decides on
configuration alone, before any request, and the source it picks is the
source. If that source then fails, that is the error. It does not try the next
one.

The case this is for is the one EKS is known for: a pod whose IRSA setup is
broken — the token file not mounted, the role's trust policy wrong — falling
through to IMDS and running with the **node's** role. That is a privilege the
pod was never meant to have, granted silently by a misconfiguration. Here it is
a startup error naming the web identity that failed. Deployments that know their
platform should name the source outright, and the chart does.

### What `profile` covers, and what it refuses

Static keys, a role assumed with a `source_profile`'s credentials (signed
`AssumeRole`, with `external_id` and `duration_seconds`), and a role assumed with
a `web_identity_token_file`. A profile may name itself as its source, meaning
its own keys; chains of source profiles end after four, and a cycle is an error.

Refused, each with the reason in the error:

- **SSO** (`sso_session`, `sso_start_url`). It is a person logging in through a
  browser, and its token cache is written by the AWS CLI. A gateway cannot log
  in; a person running `rotate` on a laptop can turn a session into keys with
  `aws configure export-credentials --format env` and use the `env` source.
- **`credential_process`.** It runs a command named in a configuration file. A
  gateway that executes whatever its home directory's AWS config names has
  handed that file its process.
- **`mfa_serial`**, which needs a code typed by a person, and
  **`credential_source` inside a profile**, which the gateway's own
  `credential_source` expresses directly.

### IMDSv2, and no fallback to version 1

IMDSv2 requires a session token obtained with a `PUT` before it answers
anything. That is what stops a server-side request forgery, or a container one
network hop too far away, from reading the role's credentials with a plain
`GET`. Falling back to version 1 when the `PUT` fails would throw exactly that
away, so a refused or unreachable `PUT` is an error — one that says the common
reason: in a container on EC2, the instance's PUT response hop limit must be at
least 2. `AWS_EC2_METADATA_DISABLED` is honoured.

### The container endpoint, restricted as the SDKs restrict it

`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` resolves against ECS's address.
`AWS_CONTAINER_CREDENTIALS_FULL_URI` over plain HTTP is accepted only for
loopback, `169.254.170.2`, `169.254.170.23` and `fd00:ec2::23`; over HTTPS for
any host. Anything else would be the environment directing the gateway to send
its authorization token, and fetch its credentials, in clear across a network.
The authorization token file — Pod Identity's — is read on every fetch, because
the kubelet rotates it; so is a web identity token file.

### STS through its query API

`AssumeRoleWithWebIdentity` is an unsigned form POST — the token is the
credential — and `AssumeRole` is signed with the existing SigV4 signer.
`AWS_ENDPOINT_URL_STS` overrides the endpoint, which is how the tests reach a
stub; `AWS_ENDPOINT_URL`, the override for every service at once, is
deliberately **not** read. A shell that points the AWS CLI at this gateway with
it — as the CI's client steps do — would otherwise point the gateway's own STS
calls at itself.

### A cache of our own

`aws.CredentialsCache` would refresh, and on a failed refresh it returns the
error as soon as the refresh window opens, while the credentials it holds are
still valid for minutes. For a gateway that is a request failure caused by a key
service having a bad minute. So `awscreds.Credentials`:

- refreshes in the last five minutes of a lifetime (halfway through one shorter
  than ten), earlier by a random part of a minute so instances started together
  do not ask together;
- lets one refresh run at a time, and serves still-valid credentials to the
  callers that arrive meanwhile;
- on a failed refresh keeps serving the credentials it holds while they are
  valid, retries after thirty seconds — never later than their expiry — and
  becomes an error only when they have expired.

## Alternatives considered

**The SDK's `config` module.** Every source, maintained by AWS, and the obvious
choice for a service with no stance on dependencies. Rejected on the measurement:
twelve modules, three of them for SSO, which a gateway has no use for, in a
module whose dependency list is a deliberate six entries.

**The SDK's providers piecemeal** — `credentials/stscreds`,
`credentials/ec2rolecreds`, `credentials/endpointcreds`. Smaller, and still
`service/sts` with its generated client and `feature/ec2/imds` with its own,
for two HTTP calls each. The same argument ADR-013 made for KMS and ADR-003 for
S3.

**Fall back to the chain when no keys are configured**, as the SDK does. One
setting fewer. Rejected above: a forgotten key would be silently answered by
whatever the environment holds.

**A chain that falls through on failure**, as the SDK's does for some
sources. Rejected above: it is how a pod ends up with its node's role.

**IMDSv1 as a fallback.** Rejected above.

**`aws.CredentialsCache`.** Rejected for its behaviour on a failed refresh,
described above; it would have been the one piece taken from the SDK as is.

## Consequences

- The gateway runs on EKS with IRSA or Pod Identity, on ECS with a task role and
  on EC2 with an instance role, without a key in a Secret, and temporary
  credentials of every kind are refreshed. The AWS dependencies stay at two.
- About 900 lines of protocol code, 1,200 with their comments, and 730 lines of
  tests are this project's to maintain instead of AWS's — more than the 600 to
  800 estimated before writing them. Most of it is parsing: STS's XML, two JSON
  shapes and the INI dialect of the shared files.
- Each protocol is tested against a stub that holds it to what AWS documents and
  to what the code must never do: ask IMDS without a session token, sign the
  anonymous STS call, send a container token in clear to a remote host. Web
  identity is also measured against real STS by the manual AWS workflow, with
  GitHub's OIDC token standing in for IRSA's. IMDS on EC2 and Pod Identity on EKS
  are not measured, and the documentation says so, as it does for the KMS
  emulator.
- The behaviour differs from the SDK's in the two decisions above and in what
  `profile` refuses. An operator who expects the SDK's chain finds an error
  where the SDK would have found credentials, and the error says why.

## What building it found

- **The Helm chart keeps the API token unmounted.** IRSA and Pod Identity are
  both injected by `aws/amazon-eks-pod-identity-webhook`, as a projected volume
  of their own; its handler has no check on `automountServiceAccountToken`, so
  `false` — which the chart sets, since the gateway never calls the Kubernetes
  API — does not stand in the way. Read from the webhook's source, not measured
  on EKS.
- **The estimate was low.** 600 to 800 lines were planned; the resolver is
  about 900 without its comments. The difference is the profile files, whose INI
  dialect has nested sections and two section-naming conventions.
- **A test can take the whole web identity path without AWS.** A stub of STS that
  answers with the test provider's own keys lets a probe run through the token
  file, the STS exchange, the cache and the signer against real MinIO and Garage
  — the path the AWS workflow then takes against real STS.
