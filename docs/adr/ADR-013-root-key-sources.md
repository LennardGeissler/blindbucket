# ADR-013 — Root-key sources: Vault Transit and AWS KMS, unsealing at startup

**Status:** Accepted
**Date:** 2026-09-12
**Milestone:** M5 (the last of it)
**Implements:** `internal/rootkey`, `internal/crypto/keys` (root-key reference), `cmd/blindbucket`
**Amended by:** [ADR-023](ADR-023-resealing-a-keyring.md) — `blindbucket reseal` moves a keyring between sources, which the consequences below say does not exist; [ADR-024](ADR-024-aws-credentials-without-the-sdk.md) — the KMS credentials, like the upstream's, may come from the credential chain, which the alternatives below say is unavailable

## Context

[ADR-002](ADR-002-key-hierarchy.md) put the root key outside the process, and
`FORMAT.md` §3 has named its three sources from the start: "AWS KMS | Vault
Transit | Argon2id(passphrase)". Only the third existed. The other two were the
last deferred item still outstanding, and the `KeyProvider`
interface had exactly one implementation — which is how an abstraction ends up
being decoration rather than a seam.

The question is not whether to add them. It is *where in the hierarchy* they
attach, and that decision has a large effect on everything else.

## Decision

### The services supply the root key, once, at startup

A key service decrypts the root key when the process opens its keyring. From
then on every KEK is in memory and the service is not consulted again. No
request pays a round trip.

The alternative — a KEK that lives in KMS, with every object's data key wrapped
and unwrapped by a service call — is the shape people usually reach for, and it
is wrong here. This gateway wraps a data key on every PUT and unwraps one on
every GET. At KMS's per-request latency that is tens of milliseconds added to an
operation whose measured overhead is currently 0.5 ms, and a throughput ceiling
set by a KMS rate limit rather than by the network. Worse, it makes the key
service a hard dependency of the *data path*: KMS having a bad minute would stop
reads of objects whose bytes are sitting right there.

Unsealing at startup gives up something real in exchange, and it should be said
plainly: **the root key is in the gateway's memory afterwards**, exactly as the
passphrase-derived one is (THREAT_MODEL §5.5). Somebody who can read the
process's memory gets it either way. What the services buy is not secrecy at
runtime, it is *custody*: the secret is not a passphrase sitting on an
operator's machine or in a CI variable, access to it is logged by somebody else,
and it can be revoked. Revocation was verified rather than assumed — deleting
the Transit key stops the next start with `encryption key not found`, and every
instance is locked out as it restarts.

### The keyring file records which source sealed it

A keyring says, in a `root_key` object, what has to be asked to open it: the
source, the encrypted root key in the service's own envelope, and the name of
the key that sealed it. A passphrase keyring keeps its `kdf` block and writes no
`root_key`; a service-sealed one writes `root_key` and no `kdf`.

This is what stops the failure mode the seam would otherwise have. Without it,
a gateway configured for Vault and handed a passphrase keyring would ask Vault
to decrypt something that is not Vault ciphertext, and a gateway configured for
a passphrase and handed a Vault keyring would prompt an operator for a
passphrase that cannot work. Both now say what is wrong, and the recorded key
name turns "decryption failed" into "this keyring was sealed under transit key
`prod`, but `staging` is configured" — which is the misconfiguration that
actually happens.

### KMS ciphertexts carry an encryption context

A root key sealed by KMS is sealed under an encryption context — AWS's own
associated data, the same idea [ADR-002](ADR-002-key-hierarchy.md) applies to
every wrapped DEK. It always contains `blindbucket=root-key`, and
`keys.awskms.encryption_context` adds whatever identifies the deployment.

It buys two things a key id alone does not. The value appears in CloudTrail, so
a decrypt of *this* key is distinguishable from every other use of the same KMS
key; and a key policy can require it with a `kms:EncryptionContext:blindbucket`
condition, which narrows a grant to this use rather than to the key. The context
is recorded in the keyring file because decrypting requires exactly the context
that encrypted, and a keyring must be openable from the file alone. Recording it
in an untrusted file costs nothing: KMS binds the ciphertext to the context, so
an edited one fails to decrypt rather than opening anything.

Vault Transit gets none, and that is not an oversight. Transit accepts a context
only for keys created with derivation enabled, so sending one would fail against
an ordinary Transit key. The equivalent there is a policy on the key's own mount
path.

### Both clients are hand-written against the HTTP API

Neither source uses its vendor's SDK. [ADR-003](ADR-003-upstream-client.md) took
this position for S3 and the reasoning carries: two endpoints of a documented
JSON API are less code than the dependency that wraps them.

For Vault that means no new dependency at all. For KMS it means reusing the
SigV4 signer already in the module for the S3 side, signing `TrentService.Encrypt`
and `TrentService.Decrypt` over the real payload hash. The AWS SDK's KMS client
would have pulled in the service client, the credential chain and the endpoint
resolver — the largest addition to a module whose entire non-test dependency set
is five direct entries.

## Alternatives considered

**A KEK held in KMS, per-request wrap and unwrap.** The textbook envelope
pattern, and it keeps key material out of the gateway entirely. Rejected on the
numbers above: it moves the key service into the data path, multiplies
per-request latency by an order of magnitude, and makes a key-service outage a
data outage. The hierarchy in ADR-002 exists precisely so that the expensive key
is touched rarely.

**Vault's and AWS's SDKs.** Less code to own, and the vendors' own retry and
credential handling. Rejected for ADR-003's reason, with the added observation
that the Vault SDK would have become the single largest dependency in the module
for two HTTP calls. The cost is that credential sources the SDK supports —
instance roles, web identity, SSO — are not available; configuration takes
explicit credentials. That is a real limitation and it is documented rather than
hidden.

**Deriving the root key from a service-held secret with the existing KDF.** Ask
Vault for a secret, run Argon2id over it, reuse every existing code path.
Rejected because it is the worst of both: the service hands out the secret
itself rather than performing the decryption, so a compromised gateway that ever
saw it keeps the ability to open every keyring sealed under it. Transit and KMS
both decrypt without releasing the key, and that is the property worth having.

**Letting a keyring carry both a passphrase and a service source**, so it can be
opened either way. Convenient for migration. Rejected: a keyring with two doors
has the security of the weaker one, and the weaker one is a passphrase that
somebody chose in order to have a fallback.

## Consequences

- `keys.provider` accepts `file`, `vault` and `awskms`. The last two are
  configured with an address or region, credentials and a key name; a missing
  field is a startup error rather than a failure at the first request.
- `blindbucket keygen --config <file>` seals a new keyring with whatever the
  configuration names. Adding a key to an existing keyring re-seals it under a
  fresh root key.
- A migration between sources is a `keygen --add` away from being possible but
  is *not* implemented: there is no `blindbucket reseal`. Changing a keyring's
  source today means creating a new keyring and rotating objects onto it.
- Vault is tested against a real Vault in dev mode. KMS is tested against an
  emulator of the KMS protocol, not against AWS — the protocol is exercised for
  real, the service is not AWS, and `docs/COMPATIBILITY.md` says exactly that.
  An untested-against-AWS claim would be worse than a scoped one.
- `internal/rootkey` lives outside `internal/crypto` because it speaks HTTP, and
  the crypto packages have no dependency on HTTP or on any service.
- The keyring file gained an optional `root_key` object. Files written before it
  are passphrase keyrings and still load; the format version did not change,
  because the field is additive and its absence already means something.
- `root_key` later gained an optional `context`, for the KMS encryption context.
  Older keyrings carry none and are decrypted with none, as they were encrypted.
  This is the one direction that is not compatible: a keyring sealed *with* a
  context cannot be opened by a build that predates the field, because that
  build would ask KMS to decrypt without it.
- A `Source` returns the whole `RootKeyRef` from `Encrypt` rather than a bare
  ciphertext string. What has to be recorded to reopen a keyring is the
  service's business, not the CLI's; the encryption context is the field that
  made the difference matter.
