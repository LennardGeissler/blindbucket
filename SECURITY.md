# Security Policy

blindbucket is an encryption gateway. A flaw in it does not merely break a
feature — it can expose the plaintext the whole project exists to protect. This
document says how to report one, what counts as one, and what this project has
already written down as a known limit rather than a bug.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected
vulnerability.**

Report it through GitHub's private vulnerability reporting:

**<https://github.com/LennardGeissler/blindbucket/security/advisories/new>**

That opens a draft advisory visible only to you and the maintainer. It stays
private until a fix is published, and a CVE can be requested through it when the
finding warrants one.

If GitHub is not available to you, open a public issue containing **no technical
detail** — a single line asking for a private channel is enough — and a contact
route will be arranged from there.

### What to include

The more of this a report carries, the faster it can be confirmed:

- The affected version or commit, and whether it reproduces on `main`.
- The actor from [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §2 you are
  assuming — a passive provider (A1), an active one (A2), an unauthorised
  client (A4), and so on. This is the single most useful line in a report,
  because it decides immediately whether the finding is in scope.
- What the gateway does, and what it should have done instead.
- A reproduction: a script, a request, a crafted object, or a failing test. The
  compose file brings up a local MinIO in one command (see
  [CONTRIBUTING.md](CONTRIBUTING.md)), and a reproduction against it is worth
  more than a description of one.
- Your assessment of the impact, if you have one. A disagreement about severity
  is easier to resolve than a missing description of the effect.

### What to expect

This project is maintained by one person, so these are commitments about
attention rather than about engineering capacity:

| Stage | Target |
|---|---|
| Acknowledgement that the report arrived | 3 working days |
| Initial assessment — in scope, and a first severity judgement | 7 days |
| Fix, or a written plan with a date | 30 days for high severity |
| Public disclosure | coordinated with you, 90 days by default |

If a report is out of scope you will be told why, with a pointer to the section
of the threat model that covers it, rather than left without an answer.

Reporters are credited in [`CHANGELOG.md`](CHANGELOG.md) and in the advisory
unless you ask otherwise.

## Supported versions

The wire format is the thing held stable before `1.0.0`; the Go API is not.
Security fixes land on `main` and in a new patch release of the most recent
minor version. Older minors are not backported — with two releases so far, a
backport policy would be ceremony rather than a service.

| Version | Supported |
|---|---|
| `main` | yes |
| 0.2.x | yes |
| 0.1.x | no — upgrade to 0.2.x |

Objects written by any released version stay readable: a change to the segment
format would be a change to its version number, announced in the changelog.

## Scope

### In scope

Anything that breaks a guarantee stated in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §3, against the actors §2 admits:

- **Plaintext or key material reaching the provider.** Any path by which A1–A3
  learn object content, a DEK, a KEK or the root key.
- **Forged data accepted as genuine.** A modified, truncated, reordered,
  duplicated or substituted object, part or manifest that a client receives as
  valid plaintext instead of an error.
- **Cryptographic flaws in the format.** Nonce or salt reuse, a subkey
  derivation that collides, associated data that fails to bind what
  [`docs/FORMAT.md`](docs/FORMAT.md) says it binds, an encoding ambiguity that
  lets two plaintexts share a ciphertext.
- **Authentication and authorisation bypass.** A SigV4 verification weakness, a
  signature that validates over a body that was not signed, or a credential
  reaching a bucket outside the `buckets` list configured for it (A4).
- **Upload token or manifest forgery.** A token a client can mint, alter or
  replay across objects; a manifest a provider can substitute
  ([ADR-006](docs/adr/ADR-006-upload-token.md),
  [ADR-014](docs/adr/ADR-014-part-salts-in-the-manifest.md)).
- **Concurrency flaws in the manifest lifecycle** that leave an object
  unreadable or a manifest deletable while its object is live — including a
  case the TLA+ model in [`spec/tla/`](spec/tla/) fails to cover.
- **Audit log forgery** beyond the truncation window §5.8 documents: an edited,
  reordered, spliced or re-signed chain that still verifies.
- **Remote crashes and resource exhaustion** reachable by an authenticated
  client or a hostile provider response — a panic in a parser, unbounded
  allocation from an attacker-controlled length field.
- **A weakness in the reasoning** of `FORMAT.md` or `THREAT_MODEL.md`, even with
  no code to exploit it. The format was specified before it was implemented so
  that it could be argued with.

An attack the existing tests miss is a valid report on its own. §7 of the threat
model lists what is currently simulated; the interesting report is the one
outside that list.

### Not in scope

These are decisions and documented limits, not undiscovered bugs. A report about
one of them will be answered with a pointer rather than a fix — but if you think
the *reasoning* behind one is wrong, say so, and that is in scope as above.

- **Anything requiring control of the proxy host, the KEK or the root key**
  (actor A5). The proxy holds keys and sees plaintext by design; it must run in
  the same trust domain as its clients. This is the fundamental boundary of the
  design, stated in §2 and in the README.
- **Plaintext between client and proxy** (A6), except where TLS or a sidecar
  deployment is documented as covering it.
- **Metadata visible to the provider** — object names, exact sizes, timestamps,
  access patterns. Not hidden, by design (§4, §6).
- **Rollback to an older genuine version of an object** (§5.1). Not currently
  detectable, stated in the README and the threat model, and not changed by the
  audit log.
- **Truncation of audit entries written after the last checkpoint** (§5.8). The
  gap is deliberate, `audit verify --expect` closes it, and a test asserts the
  undetectability so the limit cannot be lost silently.
- **Key material remaining in process memory** (§5.5). Go's garbage collector
  moves and copies; the mitigations are operational and listed there.
- **Partially delivered plaintext on a mid-stream integrity failure** (§5.3),
  and **unauthenticated sizes in a listing** (§5.4).
- **Availability**, including denial of service that needs no credentials beyond
  what a legitimate client has (§6).
- **Missing S3 features** — IAM, bucket policies, object lock, lifecycle,
  versioned reads, object tags, `ListMultipartUploads`. Refused deliberately and
  explained in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).
- **Findings from a scanner with no demonstrated impact on this codebase**, and
  vulnerabilities in dependencies that `govulncheck` already reports as not
  reachable from this module.

## Testing safely

Test against your own infrastructure only. `docker compose up -d` brings up a
local MinIO for exactly this purpose, and the compose file's `keys` profile adds
a Vault and a KMS emulator. Do not test against anyone else's deployment of
blindbucket, and do not test against a hosted S3 provider in a way that violates
that provider's terms.

Research conducted within this scope, reported privately, and given reasonable
time to be fixed will not be met with a legal complaint from this project.

## One thing worth stating plainly

**This code has not had a third-party security audit.** It has extensive
adversarial tests, a formally checked coordination model, known-answer vectors,
differential fuzzing against an independently written decoder, and a threat model
that documents its own residual risks — and none of that is an audit. Weigh it
accordingly before putting data you cannot afford to lose behind it.

That is also the invitation. A finding against this project is welcome, and
saying so in a file is cheaper than meaning it; the residual-risk section of the
threat model is the evidence that unflattering facts about this design get
written down rather than filed away.
