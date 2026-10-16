# ADR-030 — `init` writes what a gateway needs to start, and nothing that opens the keyring

**Status:** Accepted
**Date:** 2026-10-16
**Milestone:** M11
**Implements:** `cmd/blindbucket` (`init`), the CI job "Client compatibility" ([#119](https://github.com/LennardGeissler/blindbucket/issues/119))

## Context

Until 1.3, a first run took seven steps: start a provider, build, export a
passphrase, run `keygen`, copy the 200-line `blindbucket.example.yaml`, edit it,
and export the provider's credentials before `serve`. Three of those steps are
decisions a new user has no basis for yet: which settings matter, what to call
the client's credentials, and where the secrets go. M11 asks for a first
encrypted upload within ten minutes from the README alone, measured by watching
people do it ([#124](https://github.com/LennardGeissler/blindbucket/issues/124)).

Most of the answers are already fixed elsewhere. `keygen` creates a keyring and
never overwrites one. The configuration takes secrets only as `${VAR}`
references, and a missing variable is a startup error. The client's secret
cannot only be shown once: the gateway verifies SigV4 signatures with it, so it
has to be somewhere `serve` reads. And ADR-013 and ADR-023 keep a second way
into the keyring closed: a passphrase next to the keyring would be one.

## Decision

**`blindbucket init` writes three files into one directory: `blindbucket.yaml`,
`keyring.json` and `blindbucket.env`.** After it, a gateway starts with
`set -a; . ./blindbucket.env; set +a` and `blindbucket serve`.

1. **No file is overwritten, and the check comes first.** If any of the three
   exists, nothing is written. All three are created with mode `0600`; the
   keyring through the same `createKeyring` as `keygen`.

2. **Secrets go into the environment file, never into the configuration.** The
   configuration references them as `${VAR}`, as the example does. The file
   holds `NAME='value'` lines, the one form a shell, Docker Compose's `env_file`
   and systemd's `EnvironmentFile` all read the same way; a value with a quote
   or a line break is refused rather than escaped in a way one of them reads
   differently.

3. **Nothing that opens the keyring is stored beside it.** Not the passphrase,
   not the Vault token, not KMS keys. Any of them next to `keyring.json` opens
   it for whoever can read the directory. A Vault token would at least stay
   revocable and its use logged, but one rule without exceptions is easier to
   state and to check. The summary names what `serve` still needs from the
   environment. What the file does hold, the provider's and the client's
   credentials, gives access to ciphertext and to the gateway respectively, and
   neither unwraps a key.

4. **The keyring is written last.** Sealing is where `init` fails for reasons
   outside it: a passphrase repeated wrongly, a Vault that does not answer. When
   it does, the two files already written are removed; they can be written
   again. A keyring is never removed, not even one `init` just created, by the
   rule `keygen` follows.

5. **`init` does not contact the provider.** Only sealing uses the network, and
   only for Vault and KMS. Whether the endpoint answers, the credentials work
   and conditional writes hold is what `doctor` checks
   ([#120](https://github.com/LennardGeissler/blindbucket/issues/120)); until it
   exists, the summary points at `probe`.

6. **It asks only what cannot be defaulted**: the provider, the bucket, the
   provider's credentials, the root-key source, and whether names are
   encrypted. Name encryption defaults to off, as in the configuration, and the
   question says why choosing it later costs a migration (ADR-015). TLS, the
   audit log and rollback detection are left as the configuration's defaults and
   pointed to.

7. **Provider presets exist only in the interactive form.** MinIO, AWS S3,
   Cloudflare R2, Backblaze B2, Garage and "other" fill in endpoint, region and
   addressing. As flags they would be one more thing ADR-021 keeps stable, for
   nothing `--endpoint`, `--region` and `--path-style` cannot already say. For
   R2 and B2, which have not been measured against the gateway, the summary
   says so.

8. **`--non-interactive` never asks.** A missing answer is an error that names
   the flag or the variable supplying it. Secrets are never flags, so they do not
   end up in shell history: they come from the variables the configuration
   references.

9. **The client's credentials are generated**: an access key ID of `BB` and 18
   base32 characters, and a 40-character secret of 200 bits, both from
   `crypto/rand`. They are printed once, as an `export` line for the AWS CLI,
   and stored in the environment file.

10. **The keyring path in the configuration is absolute.** `serve` resolves
    `keys.keyring` against its working directory, not against the
    configuration, so a relative path breaks the first time the gateway starts
    from somewhere else.

11. **KMS's keys are `KMS_ACCESS_KEY_ID` and `KMS_SECRET_ACCESS_KEY`**, not the
    `AWS_*` names the example uses. The summary exports the client's
    credentials as `AWS_ACCESS_KEY_ID` for the AWS CLI, and a gateway started in
    that shell would otherwise hand the client's key to KMS.

## Alternatives considered

- **No environment file, only `export` lines in the summary.** The first `serve`
  then fails on a missing variable unless the user copies every line into the
  right shell, which is the step `init` exists to remove. Rejected.
- **Secrets in the configuration.** Configuration files get copied, mounted into
  containers, pasted into issues and committed. The example has always said they
  are referenced, never written, and `init` should not be the first thing to
  break that.
- **The Vault token in the environment file.** It is revocable, which a
  passphrase is not, and that was the argument for it. Against it: a stolen
  directory plus network access to Vault is the keyring, and an exception to
  point 3 is something every reader has to re-derive. Rejected.
- **A provider check at the end of `init`.** It would duplicate `doctor`, make
  `init` depend on the network, and turn a correct set of files into a failed
  run when the provider is down. Rejected.
- **Resolving `keys.keyring` relative to the configuration.** Arguably the
  better rule, but a change to how existing configurations are read, which
  ADR-021 allows only in a major release. An absolute path gets the same result
  for the files `init` writes.
- **Deleting the keyring when a later step fails.** Ordering the writes so that
  nothing can fail after the keyring exists makes that question disappear.
- **A prompt library.** The standard library and `golang.org/x/term`, already a
  dependency, are enough for numbered choices, yes/no and hidden input
  (ADR-011's preference).

## Consequences

- A first run is `init`, loading the environment file, and `serve`. The
  README's "Try it today" starts there.
- The CI job "Client compatibility" runs every client, multipart and the second
  instance against the configuration `init --non-interactive` writes, not one
  written for CI. A change to `init` that breaks a client fails there.
- The flags and exit codes of `init` fall under ADR-021 from the release that
  ships it. The questions, the summary and the comments in the written files are
  human-readable output and do not.
- `blindbucket.env` is a new file with secrets in it. Its client secret lets
  whoever reads it use the gateway, as the client could. `serve` cannot warn
  about its mode the way it warns about the keyring's, because the shell reads
  it, not the gateway.
- Answers typed ahead of a hidden prompt can be lost when the terminal switches
  echo off. A person answering each question as it comes does not meet this; a
  script should use `--non-interactive`.
