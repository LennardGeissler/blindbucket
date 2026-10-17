# ADR-032 — A read may set its own response headers

**Status:** Accepted
**Date:** 2026-10-17
**Milestone:** M12
**Implements:** `internal/s3api` (routing), `internal/proxy` (object reads)
**Amends:** [ADR-019](ADR-019-presigned-urls.md), the consequence that refused `response-content-disposition`

## Context

S3's GetObject takes six query parameters that set a header of the response
instead of selecting anything: `response-content-type`,
`response-content-disposition`, `response-content-language`,
`response-content-encoding`, `response-cache-control` and `response-expires`.
They exist for links. Whoever signs a download link can say which file name a
browser should save it under, or which type to show it as, without changing
the object.

This gateway has refused them as unimplemented sub-resources. ADR-019 named
that as a consequence: "a real gap for download links that want to set a
filename". The M12 measurement of GitLab ([#127](https://github.com/LennardGeissler/blindbucket/issues/127))
showed how real it is. GitLab 19.5 puts `response-content-disposition` and
`response-content-type` on every object download:

- by default, in the presigned URL it redirects the browser to, which the
  gateway answered with `501 NotImplemented`;
- with `proxy_download`, in the URL Workhorse fetches on the browser's behalf,
  which failed the same way and turned into GitLab's own 501.

So no attachment, artifact or LFS object uploaded to a GitLab behind the
gateway could be downloaded again, whichever way GitLab was set up. Rails'
ActiveStorage signs the same parameters into every download URL it makes.

## Decision

**GetObject and HeadObject apply the six parameters to the gateway's own
response. Nothing about them reaches the provider.**

1. **Only the six, and only on object reads.** The router accepts them on a
   `GET` or `HEAD` of an object, and nowhere else: on a `PUT`, a multipart
   request or `?tagging` they are still `501 NotImplemented`, and a parameter
   that only looks like one, `response-foo`, is still an unimplemented
   sub-resource.
2. **Applied last, on success only.** The gateway copies the provider's headers
   for the object and then sets each override over them, just before the status
   line of a `200` or `206`. An error response carries none of them.
3. **Never forwarded.** The gateway builds its request to the provider itself,
   with no query string from the client. The provider never sees the parameters,
   so a provider that does not implement them makes no difference.
4. **A value is a header value.** One that holds a control character, a
   carriage return or a line feed among them, is refused with
   `400 InvalidArgument` rather than cleaned, and so is a parameter given
   twice. Otherwise the value is passed on as given, as S3 does: the gateway
   does not parse a `Content-Disposition` or a date.

## Why this is safe

The parameters change what a response says about an object, never which object
it is or who may read it.

- **Signed, always.** The gateway serves no anonymous request, which is the one
  case S3 itself refuses overrides for. On a header-signed request the caller
  holds a credential for the bucket. On a presigned URL the parameters are part
  of the canonical query string, so the signer chose them and the holder cannot
  change or add any without invalidating the signature. ADR-019's tests for a
  lengthened or repointed URL cover adding a parameter as well.
- **No authority a credential lacked.** Whoever can sign a read with
  `response-content-type: text/html` can already store an object with that
  type. What a browser does with it is the same question either way, and the
  answer is the one for every object the gateway serves to a browser: the
  gateway is not a web origin to put anything else on.
- **No header injection.** Point 4: a value cannot end a header and start
  another.

## Consequences

**Positive.**

- GitLab's downloads work in both of its modes, and so does any
  application that signs download links with a file name.
- ADR-019's remaining read-side gap is closed. The browser-upload gap, presigned
  `PUT`, is unaffected and stays [#131](https://github.com/LennardGeissler/blindbucket/issues/131).

**Negative.**

- Six more parameters the router knows. `TestRouteResponseOverrides` keeps the
  set and the operations it applies to from growing by accident.
- A response may carry a type or a disposition the object was not stored with.
  That is the feature, and S3's behaviour.

## Rejected alternatives

- **Keep refusing.** GitLab would be unusable behind the gateway, and the guide
  would have nothing to tell an operator except not to.
- **Forward them to the provider.** It would answer with headers describing
  the ciphertext request it was sent, which the gateway strips anyway. It would
  also make the behaviour depend on the provider, for no gain.
- **Accept them and ignore them.** Every GitLab download would succeed under
  the name `download`, which is worse than an error that says why.
