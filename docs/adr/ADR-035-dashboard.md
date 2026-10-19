# ADR-035 — A read-only dashboard, on a listener of its own, on loopback

**Status:** Accepted
**Date:** 2026-10-19
**Milestone:** M13
**Implements:** [#130](https://github.com/LennardGeissler/blindbucket/issues/130)

## Context

Everything an operator can learn about a running gateway is in its metrics, its log and
the CLI's output. That is right for automation and hard for a person who wants to know,
at a glance, whether this gateway is healthy, which keys it is using and whether its
audit log still verifies. #130 asks for a page that shows that, read-only.

#130 also asks that the decision start from the threat model, not from the page. Three
facts shape it:

- **The admin listener is not private in practice.** It defaults to `127.0.0.1:9100`,
  but the Helm chart binds it to `0.0.0.0:9100`, because the kubelet's probes and
  Prometheus have to reach `/healthz`, `/readyz` and `/metrics`. Its NetworkPolicy
  leaves that port open inside the cluster. It speaks plain HTTP and has no
  authentication. Anything added to it is reachable by every pod in the cluster.
- **What the dashboard shows is worth having to an attacker.** Key IDs and which is
  active, what seals the keyring and where (a Vault address, a KMS key ARN), whether the
  audit log verifies and when it was last signed. None of it is a secret in the sense of
  key material, but all of it is reconnaissance. A broken audit chain is exactly what
  someone covering tracks wants to know about first.
- **Loopback is not private either, to a browser.** A page served on `127.0.0.1` can be
  read by any website the operator visits, through DNS rebinding: the attacker's name
  resolves to `127.0.0.1` after the page has loaded, and the browser's same-origin rule
  then lets the attacker's script read the response. That applies to `/metrics` today,
  and it would apply to the dashboard.

The threat model does not mention the admin listener at all yet.

## Decision

### Its own listener, loopback only, off by default

The dashboard is served on **a listener of its own**, `admin.dashboard.listen`. It is
off unless set. The configuration refuses an address that is not a loopback address,
with the reason and the way to reach it from elsewhere.

That keeps the dashboard out of reach wherever the admin listener has to be open. In
Kubernetes the gateway listens for the dashboard on the pod's own loopback, and an
operator reaches it with `kubectl port-forward`, which needs cluster credentials and
the RBAC to forward to that pod. On a host, an SSH tunnel does the same. Both put
authentication in front of the page that is already there and already audited, rather
than one this gateway would invent.

**No authentication kind is added in this ADR.** #130 asks the ADR to pick one until
OIDC arrives with #134. The candidates and why none is taken:

- **A bearer token** needs a client that sends a header. A browser does not, without
  JavaScript or an extension.
- **HTTP Basic** is browser-native, but over the admin listener's plain HTTP it sends
  the password in clear on every request. It would need TLS on that listener first,
  and a second credential that lives in the gateway's environment.
- **Client certificates** are the strongest, and the most work for an operator to set
  up in a browser.

None of them is worth carrying until #134 replaces it, when a tunnel already gives
better authentication. When OIDC arrives, it is what lets the dashboard leave loopback.

### Who may read it: the Host header

Every request to the dashboard listener must name it by a loopback host: `localhost`,
`127.0.0.1` or `[::1]`, with or without the port. Anything else is answered `421
Misdirected Request` and nothing more. A DNS-rebinding page arrives with its own name
in `Host`, so it gets nothing. A port-forward or SSH tunnel arrives with `localhost`,
so it gets the page.

The existing admin endpoints do not get this check, because Prometheus and the kubelet
address them by IP from outside the pod. The threat model names what that leaves open.

### What it shows, and what it never shows

One page, for the instance:

- **Health:** whether the gateway is ready -- the same check as `/readyz`, run at most
  once every ten seconds, so that reloading the page does not make the gateway call its
  provider -- the version, the Go version and how long it has been up.
- **The keyring:** each key ID, which one is active and when each was created; and
  what seals the keyring -- a passphrase, Vault or OpenBao Transit with its address and
  key name, or AWS KMS with its key ARN.
- **The audit log**, if one is configured: its path, its chain, whether the writer is
  healthy or has failed, the sequence number and time of its last checkpoint, how many
  entries have been written since, and the result of the last verification (below).

**Never shown**, not even partly: key material, wrapped keys, credentials of any kind,
the passphrase or anything derived from it, client secrets, and object names. The page
takes what it shows from interfaces that carry nothing else, so a later field cannot
leak by accident: the key IDs from `obs.KeyringInfo`, the audit state from a status type
of its own, never the keyring or the configuration as a whole.

### Verifying the audit log without turning a page into work

Verifying the log reads every file of the chain. Doing that on every page load would let
anyone who can reach the page make the gateway read its whole log. Instead, the gateway
verifies the chain **at start and then every ten minutes**, in the background, and the
page shows the last result and when it was taken. It uses the same `audit.VerifyChain`
the CLI's `audit verify` runs, with the public key from the keyring.

### No JavaScript, no external assets, a strict policy

The page is HTML rendered on the server with `html/template`, and a stylesheet the
binary embeds, served from the same listener. It refreshes itself with
`<meta http-equiv="refresh">`, which needs no script. Every response carries:

- `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self';
  base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`.

Only `GET` and `HEAD` are served; every other method is `405`. Nothing on the page
submits anything.

### Under ADR-021

The new paths are `/` (the page) and `/style.css`, on the dashboard listener only. Like
`blindbucket`'s other human-readable output, the page's content and layout are not part
of the stability promise. The setting `admin.dashboard.listen` is, as configuration is.

## Alternatives considered

**Serve it on the admin listener.** One listener fewer to configure. Rejected because the
admin listener is open wherever the chart deploys the gateway, so the dashboard would be
too, or would need the authentication this ADR declines to invent. Keeping them apart
also keeps the admin listener what Prometheus and the kubelet expect.

**Allow a non-loopback dashboard with a warning.** Rejected for the same reason the
issue asks for a refusal: a warning in a startup log is read after the page has been
reachable for a while.

**A JSON endpoint and a page that renders it with JavaScript.** It would let the page
update without reloading. Rejected because the strict policy and the absence of script
are worth more than live updates on a page someone glances at, and a JSON document would
become one more interface under ADR-021.

**Verify the audit log on every load.** Always current, and an amplifier, as above.

**Show more** -- clients, buckets, upstream endpoint, configuration. Each is one more
thing reconnaissance learns, for a page whose job is health. Left out until someone asks
for one with a reason.

## Consequences

**Positive.**

- An operator sees health, keys and the audit log's state on one page, without a
  metrics stack.
- Nothing changes about the admin listener or what the chart exposes.
- The threat model gains the admin listener, which it was missing, and states DNS
  rebinding for both listeners.

**Negative.**

- Reaching the dashboard from anywhere but the host takes a tunnel, until #134.
- One more listener, and in Kubernetes one more port that is only ever reached through
  `port-forward`.
- The audit verification reads the whole chain every ten minutes, which costs I/O in
  proportion to the log.
- The page is a snapshot that refreshes, not a live view.
