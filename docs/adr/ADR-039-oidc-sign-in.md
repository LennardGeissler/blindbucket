# ADR-039 — OIDC sign-in for the dashboard, so that it can leave loopback

**Status:** Accepted
**Date:** 2026-11-02
**Milestone:** M15
**Implements:** [#134](https://github.com/LennardGeissler/blindbucket/issues/134)
**Builds on:** [ADR-035](ADR-035-dashboard.md), [ADR-038](ADR-038-tenants-and-crypto-shredding.md)

## Context

[ADR-035](ADR-035-dashboard.md) put the status page on a listener of its own and
allowed only loopback, so that `kubectl port-forward` or an SSH tunnel stands in front
of it. It declined to invent an authentication of its own: a bearer token needs a
client that sends a header, HTTP Basic sends a password in clear without TLS, and
client certificates are hard to set up in a browser. Its last sentence was that OIDC
is what lets the dashboard leave loopback.

That is now worth doing. A deployment with several tenants (ADR-038) has several people
who look at the gateway, and an organisation of that size already has an identity
provider. A tunnel per person and per pod is friction, and a separate password for the
gateway would be one more secret to manage. #134 asks for sign-in with the
authorization code flow and PKCE, access decided by a claim, verified tokens, and
read-only access that stays read-only.

Three facts shape the decision:

- **The page is reconnaissance, not a secret.** It shows key IDs, what seals the
  keyring and where, the tenants and their locks, and whether the audit log verifies
  (ADR-035). It shows no key material and no credential. Sign-in guards something worth
  guarding, but a stolen session reads a page; it cannot change anything.
- **The identity provider must not become part of the data path.** A gateway whose
  identity provider is down still serves S3. Only the page may depend on it.
- **Token verification is the place where a small mistake is a bypass.** Issuer,
  audience, expiry, nonce, the signature algorithm, and the keys the issuer publishes
  and rotates: each is a check that fails open when it is missing.

## Decision

### Sign-in is for the dashboard listener only, and needs TLS

`admin.dashboard.oidc` configures sign-in. With it, and only with it, the dashboard
listener may bind an address that is not loopback, and it **must** serve TLS
(`admin.dashboard.tls.cert_file` and `key_file`). The configuration refuses OIDC
without TLS, and a non-loopback address without OIDC, each with the reason. Without
`oidc`, everything stays as ADR-035 has it.

The admin listener (`/healthz`, `/readyz`, `/metrics`, `/debug/pprof/`) is not touched.
The kubelet and Prometheus cannot sign in, and what they read is narrower than the page.

### The flow: authorization code with PKCE, state and nonce

An unauthenticated `GET /` redirects to the issuer's authorization endpoint with a
fresh `state`, a fresh `nonce` and a PKCE challenge (`S256`). The three values are
kept in a short-lived cookie of their own, sealed (below), valid for ten minutes. The
issuer sends the browser back to `/callback`, where the gateway checks `state`, redeems
the code with the PKCE verifier, and verifies the ID token. It then sets its own session
cookie and redirects to `/`. `POST /logout` clears it.

The client may be confidential, with `client_secret` from the environment as every
other secret in the configuration, or public, with PKCE alone. Only the ID token is
used. The access token and any refresh token are discarded, because the gateway calls
no API on the person's behalf.

### Verification: go-oidc, with what it checks pinned by tests

The ID token is verified with `github.com/coreos/go-oidc/v3`, and the flow uses
`golang.org/x/oauth2`. Together with `go-jose`, which go-oidc uses to verify
signatures, that adds three modules to a go.mod that had six direct dependencies.
[ADR-024](ADR-024-aws-credentials-without-the-sdk.md) rejected the AWS SDK's `config`
module because it was large for what it gave; here, what the libraries do is the part
that must not be written by hand. They are widely used, and small.

What is checked, each with a test that requires a refusal:

- the **issuer** is the configured one, and the discovery document is fetched from it;
- the **audience** contains the client ID, and the **expiry** has not passed;
- the **nonce** is the one this browser's sign-in started with;
- the **signature** is one of RS256 or ES256, under a key from the issuer's published
  key set. go-oidc fetches that set again when a token names a key it does not have,
  which is how the issuer's key rotation is followed.

Discovery happens on the first sign-in, not at startup, and is retried on the next one
after a failure. A gateway starts, and serves S3, whatever the identity provider is
doing. The page answers `503` with a short reason while the issuer cannot be reached.

### Who may read it: one claim, and a list of values

`admin.dashboard.oidc.claim` names a claim, `groups` for instance, and `allowed` the
values of it that may read the page. A claim that is a string or a list of strings is
compared value by value. A token without the claim, or without an allowed value, gets
`403` and nothing else. The configuration refuses `oidc` without `allowed`: every
person the identity provider knows is not a sensible default for a page about keys.

*Amended while writing the code:* `admin.dashboard.oidc.scopes` names scopes to ask for
besides `openid`, `profile` and `email`. Dex and Okta put a `groups` claim into the ID
token only when the `groups` scope is asked for, so with `claim: groups` and no scope
nobody would ever be let in. Keycloak, among others, can refuse a scope it does not know,
so none is added by default.

**The page is all or nothing.** A claim does not choose which tenants a person sees.
The page holds no tenant's secrets, the dashboard is an operator's tool, and a view
split by tenant would also have to decide what of the rest — the default tenant's
keys, the audit log — each person sees. That can come later, if someone needs it.

### The session: a cookie sealed under a key that lives in the process

After a verified sign-in, the gateway sets a session cookie holding the subject, the
issuer, and when the session ends. It is sealed with AES-256-GCM under a key the process
generates at start and keeps in memory only. It ends at the ID token's expiry or after
`admin.dashboard.oidc.session` (eight hours by default), whichever comes first. There is
no refresh: when it ends, the person signs in again, which with a session at the
identity provider is one redirect.

The cookie is `__Host-` prefixed, `Secure`, `HttpOnly`, `Path=/`, and `SameSite=Lax`.
`Lax` rather than `Strict`, because the session has to be set while returning from the
identity provider, a navigation that began on another site. A cross-site `POST` does
not carry a `Lax` cookie, so `POST /logout` cannot be forged. Nothing else on the
listener accepts anything but `GET` and `HEAD`.

A restart ends every session, and each instance has its own key. Since each instance
has its own page (ADR-035), a person signs in once per pod they look at. Behind a load
balancer, the dashboard needs sticky routing or a hostname per pod.

### The Host header names the configured address

ADR-035 accepted only loopback names in `Host`, which turns away a DNS-rebinding page.
With sign-in, the listener accepts the host of the configured `redirect_url`, and
loopback names as before. A rebinding page still arrives with its own name and gets
`421`. The redirect URL is also what the identity provider sends the browser back to,
so it has to be the address people use.

### Read-only stays read-only

`/callback` and `/logout` change one thing, the person's session. Every other path is
as ADR-035 has it. The content security policy keeps `form-action 'none'` everywhere
but the page's own logout form, which may post to `'self'`. A sign-in, a refusal by the
claim and a sign-out are logged with the subject and the issuer. The audit log stays a
record of S3 requests.

### Configuration

```yaml
admin:
  dashboard:
    listen: "0.0.0.0:9101"
    tls: { cert_file: /etc/blindbucket/tls/dashboard.crt, key_file: /etc/blindbucket/tls/dashboard.key }
    oidc:
      issuer: https://idp.example.com/realms/ops
      client_id: blindbucket-dashboard
      client_secret: ${DASHBOARD_OIDC_SECRET}   # optional: a public client uses PKCE alone
      redirect_url: https://blindbucket-1.example.com:9101/callback
      claim: groups
      allowed: [blindbucket-operators]
      session: 8h
```

Under [ADR-021](ADR-021-what-1.0-promises.md), the new keys are configuration, and
`/callback` and `/logout` join the dashboard's paths. The page's content stays outside
the promise, as before.

### Tested against an identity provider, and against one that misbehaves

The refusals #134 lists come from a provider written for the tests. It serves a
discovery document and a key set, and mints tokens that are expired, for another
audience, without the claim, with another nonce, under an unknown key, or signed with
`none` or HS256. Each must be refused. A CI job runs the whole flow against
[Dex](https://dexidp.io/) in a container, with a browser-like client that follows the
redirects.

No TLA+ model: the flow has no concurrent state of the gateway's own to get wrong. The
interleavings that matter, the browser's and the identity provider's, are what the
standard and the library already handle.

## Alternatives considered

**Write the verification ourselves**, with the standard library's `crypto/rsa`,
`crypto/ecdsa` and an allowlist of two algorithms, as SigV4 and the AWS credential
resolver were written. It would keep go.mod as it is. Rejected: discovery, key sets,
rotation and the token's claims are a larger surface than SigV4's, and many of the
known JWT vulnerabilities were a check that was missing. The project's own crypto code
earns its place by being needed (the format, the keyring); this would not.

**Take `golang.org/x/oauth2` and verify the token by hand.** One module instead of
three. Rejected for the same reason: the part kept by hand would be the risky one.

**A claim that chooses tenants.** Discussed above, and left out until someone needs it.

**Sessions under a key derived from the keyring**, shared by every instance and kept
across restarts. One sign-in for every pod. Rejected: it would tie a browser session to
the keyring, which nothing else on the dashboard holds, and the page is per instance
anyway.

**A reverse proxy in front of the dashboard** (oauth2-proxy and the like) instead of
sign-in in the gateway. It works today and needs nothing from this project. It is what
an operator can already do, and remains a fine choice. But it puts a second process in
front of every pod, and the dashboard would still need to trust the proxy's headers or
stay on loopback. #134 asks for sign-in in the gateway.

**Refresh tokens**, so a session outlives the ID token. Rejected: a refresh token is a
credential the gateway would have to keep, and one more redirect every few hours costs
nothing for a page people look at now and then.

## Consequences

**Positive.**
- The dashboard can be reached without a tunnel, under the organisation's own sign-in,
  with access decided by a group the organisation already manages.
- The gateway still starts and serves S3 when the identity provider is down.
- What is verified is listed here and pinned by a test that requires each refusal.

**Negative.**
- Three new modules, and with them their updates and advisories to follow.
- A page reachable over the network is a page an attacker can probe. Without a session
  it answers only redirects, `403` and `421`, but it is reachable.
- One sign-in per pod and per restart.
- An identity provider that is compromised, or that puts the wrong people in the
  allowed group, gives read access to the page. THREAT_MODEL §5.9 will say so.

## Implementation order

1. This ADR, and the index.
2. Configuration: `admin.dashboard.tls` and `admin.dashboard.oidc`, and the rules that
   tie a non-loopback address to both.
3. Sign-in: the flow, the sealed cookies, the claim, the Host rule and logout, with the
   misbehaving test provider.
4. A CI job against Dex.
5. Docs: THREAT_MODEL §5.9, the README, the CHANGELOG, and the Helm chart's options,
   which wait for the release that ships the gateway's side.
