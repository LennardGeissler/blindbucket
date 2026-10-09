# ADR-027 — Attribute provider errors in the plaintext listing handler

**Status:** Accepted
**Date:** 2026-10-07
**Milestone:** post-1.0
**Implements:** `internal/proxy` (`listObjects`)

## Context

[Issue 44](https://github.com/LennardGeissler/blindbucket/issues/44) reports
provider refusals of client input arriving as `502 InternalError`. MinIO, for
example, refuses `prefix=.` with `400 XMinioInvalidResourceName`. But a provider
400 can also describe an invalid request the gateway constructed. Its status or
code alone cannot establish who supplied the rejected input.

The plaintext listing handler forwards the client's listing query, removing
only the client's presigning parameters because the gateway signs its own
request ([ADR-019](ADR-019-presigned-urls.md)). With name encryption on, the
gateway instead constructs the provider query to read and sort encrypted keys
([ADR-017](ADR-017-listing-order-under-name-encryption.md)).

## Decision

Attribute the refusal in the handler that knows which kind of request was sent.
On the plaintext listing path, return a provider 400 as 400 with its code and
message, regardless of the prefix or provider-specific code. Keep the gateway's
own error envelope: provider resource names and request ids are not forwarded.
Do not reject a prefix before the provider answers; a provider that accepts
`prefix=.` still supplies a successful listing.

Leave `translateUpstream` unchanged, including its default `502 InternalError`.
Encrypted listings use that translation because the rejected query was built
by the gateway. Other handlers can establish attribution in separate changes.

## Alternatives considered

**Pass every provider 4xx through.** Rejected: this would blame the caller for
errors in a request the gateway built and change unrelated operations.

**Allowlist provider codes in `translateUpstream`.** Rejected: the same code can
describe client input on one path and gateway-generated input on another. It
would also need to track every provider's vocabulary.

**Keep every otherwise-unmapped refusal at 502.** Rejected for plaintext
listings: a client cannot distinguish a rejected argument from a gateway fault.
It remains the safe default where attribution has not been established.

## Consequences

Clients see the provider's explanation of a rejected plaintext listing instead
of a retryable gateway error. Provider codes and messages are observable on
this path; their vocabulary is not restricted to the gateway's own S3 errors.
The provider's resource and request id fields remain outside the client response.

This also passes through a 400 caused by the gateway's signing or configuration,
such as AWS's `AuthorizationHeaderMalformed` for a wrong region and
`ExpiredToken`/`InvalidToken` for temporary credentials, so the client can receive
a 400 for a gateway fault. [ADR-024](ADR-024-aws-credentials-without-the-sdk.md)
refreshes temporary credentials before expiry and never signs with expired
credentials; a wrong region breaks every request, but the provider's message is
more useful than a generic 502. Excluding these codes would reintroduce the
allowlist rejected above.

No retry policy changes: the upstream client already does not retry 400.
Encrypted listing errors, all other operations and other statuses keep their
existing behavior. Ciphertext, manifests and their versions do not change.
