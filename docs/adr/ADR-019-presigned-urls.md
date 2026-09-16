# ADR-019 — Presigned URLs: verified, never issued, and only for reads

**Status:** Accepted
**Date:** 2026-09-16
**Milestone:** M6
**Implements:** `internal/auth`, `internal/s3api`, `internal/proxy`, `internal/config`

## Context

A presigned URL is an S3 URL carrying its own SigV4 signature in the query string
instead of a header. Whoever holds the URL can perform that one request, on that
one object, until it expires — without holding any credential. It is the standard
way to hand a third party temporary access to an object: a download link in an
email, an upload target for a browser.

This build refuses them. [`internal/auth/verify.go`](../../internal/auth/verify.go)
answers `presigned URLs are not implemented in this build`, and
[`docs/COMPATIBILITY.md`](../COMPATIBILITY.md) has carried the row since M3. It is
the last open item in M6.

Two facts shape the whole decision, and both are easy to get backwards.

## There is nothing to issue

**Presigning is a local computation.** `aws s3 presign` makes no network call, and
neither does any SDK's equivalent: the client already holds the secret access key,
so it derives the signing key and writes the URL itself. S3 is never told that a
presigned URL exists, and learns of one only when somebody uses it.

So "support presigned URLs" does not mean building an endpoint that mints them. It
means **verifying a request whose signature arrived in the query string**. That is
the entire feature, and it is smaller than it sounds — the signing key derivation,
the canonical request and the constant-time comparison are already in
`internal/auth` and are exactly the same. What differs is where the six parameters
come from, what the payload hash is, and how expiry is judged.

An endpoint that issued presigned URLs would be a non-S3 API doing something the
client can already do offline, and it would put the gateway in the business of
minting authority rather than checking it. Not built, and not because it is hard.

## The URL must point at the gateway

The other obvious shape — the gateway hands out a presigned URL to the *provider*,
so the download does not pass through it — cannot work here and is worth saying
out loud, because it is how a plain S3 proxy would save itself the bandwidth.

What sits at the provider is ciphertext, under a name the recipient cannot read
once [ADR-015](ADR-015-object-name-encryption.md) is on, and there is no key. A
recipient following such a URL would download an encrypted blob. The gateway is
not an optional hop for a read; it is the only thing that can perform one.

Two consequences follow. The gateway must be reachable by whoever is given the
URL, which is a deployment fact rather than a detail — a sidecar bound to
localhost cannot serve presigned URLs to anyone. And because `host` is covered by
the signature, a URL signed for the gateway's endpoint does not verify at the
provider and the reverse, so the two cannot be confused.

## Decision

### Verify query-signed requests; issue none

A request with `X-Amz-Signature` in its query is authenticated from the query
rather than the `Authorization` header. The canonical request is built the same
way with three differences, all of them from the SigV4 specification:

- the canonical query string covers every parameter **except** `X-Amz-Signature`;
- the signed headers are whatever `X-Amz-SignedHeaders` names, which must include
  `host`, as for header authentication;
- the payload hash is the literal `UNSIGNED-PAYLOAD`, because at signing time the
  body does not exist.

Everything after that — the credential scope, the signing key, the string to sign,
the constant-time comparison, the bucket authorisation that deliberately follows
authentication — is the existing path unchanged.

### Only object reads: `GET` and `HEAD`

S3 lets a client presign any operation. This gateway will serve two, and refuse
the rest with a message saying so.

The reason is what a presigned URL *is*: a **bearer credential inside a URL**.
URLs are the least confidential thing in a system. They land in browser history,
`Referer` headers, proxy and CDN logs, chat clients that fetch a preview, CI
output, screenshots. S3 accepts that trade across its whole API; this gateway
does not have to, and the cost of narrowing is close to nothing because a download
link is what essentially every presigned URL is.

The asymmetry is the argument. A chat client that previews a pasted link issues a
`GET`, and a `GET` that happens twice is a `GET`. A `DELETE` that happens because
somebody pasted a link into a channel is data loss with no attacker in the story
at all. Refusing is not a security boundary against a determined holder of the
URL — they have the credential's authority for that one request either way — it
is a refusal to make the destructive operations reachable by accident.

There is also a containment argument, and it is concrete rather than theoretical.
A listing forwards its query parameters to the provider verbatim
(`internal/upstream/bucket.go`: `u.RawQuery = query.Encode()`), so a presigned
listing would send the *client's* signature parameters upstream to a request the
gateway signs itself. Every operation reachable by a presigned URL is a path that
has to be audited for that class of mistake. Two read paths is a set that can be
checked; the whole API is not.

`PUT` is deferred rather than refused permanently, and the distinction is in
`COMPATIBILITY.md`. It is the one other real use — the browser upload — but it is
its own decision: a presigned body is by construction `UNSIGNED-PAYLOAD`, which
this gateway gates behind `server.allow_unsigned_payload` for
[ADR-005](ADR-005-checksums.md)'s reasons, and a presigned upload deserves to be
decided against those reasons rather than inheriting a switch that was set for a
different question. **Presigned POST**, the form-and-policy mechanism browsers use
for uploads, is a different protocol from query-string SigV4 and is not in scope
at all.

### Expiry is a window, not a clock-skew bound

Header-authenticated requests are valid within `MaxClockSkew` of their timestamp —
fifteen minutes either way — and that rule is what stops a captured signature being
replayed forever. **It must not be applied here.** A presigned URL is *designed* to
be used long after it was signed, up to seven days, and a gateway that reused the
skew check would refuse every one of them after fifteen minutes.

The rule instead:

```
signedAt - MaxClockSkew  ≤  now  ≤  signedAt + X-Amz-Expires
```

The lower bound is the signer's clock running fast; the upper is the window the
signer chose. `X-Amz-Expires` is covered by the signature, so it cannot be
lengthened by the holder — but it can be chosen generously by the signer, which is
what `presign.max_expiry` is for. It defaults to S3's own maximum of seven days:
being stricter than S3 by default would break working clients for a reason nobody
chose, while an operator who wants an hour can say so.

Getting this wrong in either direction is the failure most worth a test. Too
strict and the feature does not work; too loose and a URL signed a year ago is
still good.

### The six `X-Amz-*` parameters are authentication, not sub-resources

The router refuses any query parameter it does not know, and that is deliberate:
`?acl` answered as a `PUT` would send plaintext to the provider. So
`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
`X-Amz-SignedHeaders` and `X-Amz-Signature` have to be named as parameters that
select no sub-resource.

Naming them weakens nothing. They stay covered by the signature, because the
canonical query string is built from the request as it arrived — the same
reasoning the `?x-id` exception already records, and the same reasoning says the
gateway must strip them before forwarding anything to the provider.

### On by default, and what that changes

Unlike name encryption, the audit log and the rollback index, this is not off by
default. Those three change what the gateway stores or what it costs; this one
removes a refusal of something every S3 client expects to work.

What it does change is worth stating rather than glossing: **a credential holder
can now delegate.** Before this, handing someone access meant handing over the
secret access key. Now it can be handed over for one object, one operation and a
bounded time. That is strictly less dangerous than the alternative people
actually use — but it is new, it is a property of the deployment rather than of
any one request, and an operator who does not want it sets `presign.enabled:
false`. The authority itself is not new: a presigned URL can do nothing the
credential that signed it could not already do.

### What it inherits for free

A presigned `GET` is an ordinary `GET` once it is authenticated, which means it
goes through everything else unchanged. The audit log records it against the
credential that signed it, so a presigned download is attributable to whoever
issued the link rather than anonymous. The rollback check of
[ADR-018](ADR-018-rollback-detection.md) runs on it. Fail-closed
([ADR-004](ADR-004-fail-closed.md)) applies. Name encryption maps the key. None
of that is extra work, and all of it would have been extra work in a design that
answered presigned URLs on a separate path.

## Alternatives considered

**Presign to the provider and redirect.** The gateway verifies the URL, then
answers `307` with a presigned URL to the provider, and the bytes never touch it.
This is what a caching or throttling proxy would do, and it is how the bandwidth
cost disappears. Impossible here, and not marginally: the provider holds
ciphertext under an encrypted name, so the recipient would download a blob they
cannot decrypt, with a key that never leaves the trust boundary. Recording it
because it is the first idea anyone has.

**Serve every operation S3 allows.** Strictly more compatible, and one fewer row
in `COMPATIBILITY.md`. Rejected on the accident case rather than the attacker
case: a URL that deletes an object when a link preview fetches it is a failure
mode with no adversary in it, and this project's habit is to refuse rather than to
serve something surprising. It also multiplies the paths that have to be checked
for parameter leakage upstream, which is a real defect class here and not a
hypothetical one.

**Refuse presigned URLs permanently**, as `ListMultipartUploads` is refused. That
refusal is honest because the gateway's upload ids are sealed tokens that no
client could use; there is no such argument here. Presigned URLs work fine, cost
little, and are the single most-requested S3 feature to be missing from a gateway.
Refusing would be a gap, not a decision.

**Accept the fifteen-minute skew bound and document a fifteen-minute maximum.**
Would need no new expiry logic at all. Rejected as a feature that looks like the
real one and is not: every tutorial, SDK default and operator expectation is
hours to days, and a link that expires while the recipient reads the email is
worse than no link.

**A `presign.max_expiry` default shorter than S3's seven days** — an hour, say.
Tempting, and it is the setting most deployments should use. Rejected as a
default because it would break URLs that clients legitimately produce, for a
reason the operator did not choose, and the failure would appear as an
intermittent `403` on old links rather than as a configuration error. The knob is
there and the documentation recommends lowering it.

## Consequences

**Positive.**

- The last row in `COMPATIBILITY.md` that says a standard S3 feature is refused
  with a milestone against it becomes a row that says what is served.
- No new cryptography and no new format. The signing key derivation, canonical
  request, string to sign and comparison are the existing ones; only the source
  of the parameters and the expiry rule differ.
- Presigned reads inherit rollback detection, the audit log, fail-closed and name
  encryption without any of them being taught about presigning.
- A presigned URL is attributable: it names the credential that signed it, so the
  audit log records who handed the link out.

**Negative.**

- **A bearer credential in a URL is a bearer credential in a URL.** Anyone holding
  it can read that object until it expires, and nothing here changes that. It is
  the feature.
- **Credential holders can delegate**, which is new for a deployment even though
  the authority is not new.
- **The gateway must be publicly reachable** for a presigned URL to be usable by
  anyone outside, which some deployments deliberately are not.
- **The plaintext object key is in the URL.** With name encryption on, whoever
  receives the link learns the object's name — the thing ADR-015 hides from the
  provider. A different adversary, and still a leak, so `THREAT_MODEL` §4 says it.
- Writes stay refused, so the browser-upload case is not served, and
  `response-content-disposition` and its siblings are refused with it — which is
  a real gap for download links that want to set a filename, named here rather
  than discovered.
- One more configuration block, and one more thing an operator has to decide the
  expiry policy for.
