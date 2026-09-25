# Contributing to blindbucket

Thank you for looking. This document covers how to set the project up, what CI
will check, and the two conventions that are less obvious from reading the code:
how commits are written, and when a change needs an ADR.

**Found a security flaw? Do not open an issue or a pull request.**
[`SECURITY.md`](SECURITY.md) has the private reporting route.

By contributing you agree that your work is licensed under the
[Apache License 2.0](LICENSE), like the rest of the project. There is no CLA.

## What is most useful

In rough order of value to this project:

1. **An attack the tests miss.** A way to get plaintext, forged data accepted as
   genuine, or a guarantee in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §3
   broken. Report it privately first — see above.
2. **A weakness in the reasoning** of [`docs/FORMAT.md`](docs/FORMAT.md) or the
   threat model, with no code needed. The format was specified before it was
   implemented so that it could be argued with, and an ambiguity found by
   reading is worth as much as a bug found by running.
3. **A client measured rather than assumed.** Point another S3 client at the
   gateway, run it, and record what happened in
   [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Three of the four clients
   documented there each found a real bug that no unit test would have.
4. **Tests for code that only integration tests reach.** Several packages are
   covered only by tests that skip without a running MinIO, which means a plain
   `go test ./...` does not exercise them.
5. **Features and fixes**, ideally from an issue that already exists.

Issues labelled [`good first issue`](https://github.com/LennardGeissler/blindbucket/labels/good%20first%20issue)
are scoped so that they can be finished without reading the whole codebase.

## Before you start

- **For anything beyond a typo or an obvious fix, open an issue first.** A
  design that is discussed before it is written saves you from a rewrite, and
  parts of this codebase carry constraints that are not visible locally — the
  manifest lifecycle rules in [ADR-010](docs/adr/ADR-010-manifest-lifecycle-under-concurrency.md)
  are the clearest example.
- **Say in the issue that you are working on it**, so two people do not do the
  same work.
- **One logical change per pull request.** A fix and a refactor in one diff take
  longer to review than the two apart.

## Setting up

Requires **Go 1.24 or newer** — [`crypto/hkdf`](https://pkg.go.dev/crypto/hkdf)
arrived there, and 1.24 is the declared floor CI builds against — and **Docker**
for the integration tests.

```sh
git clone https://github.com/LennardGeissler/blindbucket
cd blindbucket
make build                 # ./bin/blindbucket
make test                  # go test -race
```

`golangci-lint` is needed for `make lint`; everything else the Makefile needs it
fetches itself.

To run the gateway locally against a stand-in provider:

```sh
docker compose up -d                          # MinIO on :9002, console on :9091
export BLINDBUCKET_PASSPHRASE='dev-passphrase-not-a-secret'
./bin/blindbucket keygen --out keyring.json --kid dev
cp blindbucket.example.yaml blindbucket.yaml
export UPSTREAM_ACCESS_KEY_ID=minioadmin UPSTREAM_SECRET_ACCESS_KEY=minioadmin
./bin/blindbucket serve --config blindbucket.yaml
```

`make demo-setup` does all of that plus a payload, if you want the end-to-end
demo rather than a shell.

## Running the tests

The unit tests need nothing. The rest ask for services and **skip silently
without them**, so a green `go test ./...` is not proof that you ran everything:

```sh
make test                  # unit tests, -race

# Against a provider — internal/upstream and internal/proxy:
docker compose up -d
BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 \
  go test ./internal/upstream ./internal/proxy

# Against Vault and a KMS emulator — internal/rootkey:
docker compose --profile keys up -d
BLINDBUCKET_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
BLINDBUCKET_TEST_VAULT_TOKEN=blindbucket-dev-token \
BLINDBUCKET_TEST_KMS_ENDPOINT=http://127.0.0.1:4599 \
  go test ./internal/rootkey

# Against a running gateway, with a real client:
python3 test/integration/clients/boto3/scenarios.py

make fuzz                  # 30s per fuzz target
make tla                   # model-check spec/tla (needs a JRE)
make ref-vectors           # the Python decoder against the known-answer vectors
make ref-diff              # differential test, 100 000 inputs
make bench                 # micro-benchmarks
make vuln                  # govulncheck
```

The provider tests default to the compose file's MinIO, so locally the endpoint
is the only variable they need. Pointed anywhere else, they read the rest from
the environment ([`internal/testprovider`](internal/testprovider/testprovider.go)):

| Variable | Default |
|---|---|
| `BLINDBUCKET_TEST_S3_ENDPOINT` | none — the tests skip without it |
| `BLINDBUCKET_TEST_S3_REGION` | `us-east-1` |
| `BLINDBUCKET_TEST_S3_ACCESS_KEY` / `_SECRET_KEY` | `minioadmin` |
| `BLINDBUCKET_TEST_S3_BUCKET` | `blindbucket-test` — must already exist |
| `BLINDBUCKET_TEST_S3_PATH_STYLE` | `true` |

The tests write to that bucket and overwrite objects behind the gateway's back,
which is the point of them. Give them a bucket of their own.

### What CI will check

Nothing here is a surprise if `make all` passes locally, except the jobs that
need services:

`go vet` and `golangci-lint` · `go mod tidy` leaves no diff · `go test -race` on
both Go 1.24 and current · a 30-second fuzz smoke run · integration tests against
MinIO · Vault and the KMS emulator · the boto3 and AWS CLI client scenarios,
including a multipart upload across **two gateway instances behind a
round-robin balancer** — statelessness is tested, not asserted. Pull requests
additionally get a `benchstat` comparison against the base commit, reported in
the job summary rather than failing the build.

## Code conventions

**Production code is Go, without exception.** Anything else in this repository —
the Python reference decoder, the TLA+ model, the benchmark plotting — has a
written reason in [ADR-011](docs/adr/ADR-011-languages-outside-the-go-core.md).
A contribution that adds a language needs to amend that ADR first.

- Standard library first. Each of the few dependencies was a decision; adding
  one is a discussion, not a `go get`.
- Every package has a `doc.go` — or a package comment — saying what it is for
  and why it exists separately.
- **Comments explain why, not what.** The code says what it does. The comment
  exists for the reader who wants to know what was rejected, what breaks if the
  order changes, or which document the rule comes from. Much of this codebase's
  commentary cites a section of `FORMAT.md` or an ADR; keep that habit.
- Errors wrap with `%w` and are matched with `errors.Is`/`errors.As` — the
  `errorlint` linter enforces it.
- Test names say what must hold, and the hostile tests say what must *fail*.
  When you fix a bug, the test should fail without the fix.

## Commit messages

This matters more here than in most repositories, because the history is used as
documentation. Run `git log` and read a few before writing your first.

**Subject:** [Conventional Commits](https://www.conventionalcommits.org/) —
`type(scope): description`. Types in use: `feat`, `fix`, `docs`, `test`, `ci`,
`build`, `bench`, `ref`, `chore`. The scope is the package or area (`stream`,
`proxy`, `auth`, `keys`, `obs`, `cli`, `adr-015`) and is optional for changes
that span several. Keep the description lower-case, under about 72 characters,
and phrase it as what the change *does for someone*, not which functions moved:

```
fix(keygen): ask for the passphrase once, not twice
feat(obs): key age as a metric, not as a thing to remember
fix: three compatibility bugs only real clients could find
```

**Body:** this is the part that differs from most projects. For anything larger
than a typo, the body explains **why** — the problem as it showed up, the
alternatives that were rejected and what was wrong with them, the consequences,
and what the new tests assert. Bodies of thirty to fifty lines are normal here
for a feature. A reviewer should be able to reconstruct the decision from the
commit alone, years later, without the pull request thread.

If a change touches something a document already reasons about, name the
document and the section. If it deliberately does *not* fix something nearby,
say so and why — the unfixed thing is what a future reader will wonder about.

## Pull requests

A pull request is ready when:

- [ ] `make all` passes (`fmt`, `lint`, `test`), and the integration tests
      relevant to your change were run with their services up.
- [ ] New behaviour has tests. Security-relevant behaviour has a test that plays
      the hostile party and requires an error rather than plaintext.
- [ ] [`CHANGELOG.md`](CHANGELOG.md) has an entry under `## [Unreleased]`, in
      the Keep a Changelog sections. Write it for a user of the gateway, and
      state the limits of what you added — that is the house style, and the
      existing entries show it.
- [ ] **Every document the change affects is updated**, not only the ones you
      touched. This repository states its own status in a lot of places:
      `README.md` (status block, roadmap table, "what is still missing"),
      `docs/COMPATIBILITY.md`, `docs/THREAT_MODEL.md`, `docs/FORMAT.md`, the ADR
      index, `blindbucket.example.yaml`, and the CLI's own `usage()`. Grep for
      the claim you just made obsolete.
- [ ] Design decisions are recorded in an ADR (below).

The review will ask why before it asks whether. Expect questions about
alternatives you rejected; they are not an objection, they are the same question
the ADRs exist to answer.

## When a change needs an ADR

Add one to [`docs/adr/`](docs/adr/) when the change makes a decision that later
code will have to live with: a format or protocol choice, a trade-off between
security and compatibility, a dependency, a new language or tool, a change to
how failure is handled.

Every ADR has the same four sections — **context**, **decision**, **alternatives
considered**, **consequences**. The alternatives section is the point: *a
decision without rejected options is not a decision, it is a default.* Number it
after the highest existing one, and add it to the table in
[`docs/adr/README.md`](docs/adr/README.md).

## Changing the wire format

[`docs/FORMAT.md`](docs/FORMAT.md) is normative, not descriptive. An independent
implementation should be able to interoperate from that document alone — one
already does. So a change to the format is not a change to the Go code that
happens to have a document alongside it:

1. Change `docs/FORMAT.md` first, and make sure the new rule is stated
   unambiguously for both a streaming and a buffered decoder. The one ambiguity
   found so far was exactly that distinction, and it broke every object whose
   size was an exact multiple of the chunk size.
2. Add or update known-answer vectors in [`testdata/vectors/`](testdata/vectors/).
   §13 makes the segment vectors a normative part of the specification and §15.6
   does the same for the object name mapping; both regenerate with
   `go test ./internal/crypto/<pkg> -update`.
3. Update the second implementation in [`ref/python/`](ref/python/), and run
   `make ref-vectors` and `make ref-diff`. Two implementations disagreeing is the
   signal this setup exists to produce.
4. Decide whether the format version number changes, and say so in the changelog.
   Objects written under version 1 must keep being readable.

Changes to the manifest lifecycle have a parallel obligation: the rules are
modelled in [`spec/tla/Multipart.tla`](spec/tla/Multipart.tla) and checked with
TLC, four of the five configurations are *required* to produce a counterexample,
and each counterexample is also an integration test. `make tla` must still pass.

## How we behave here

Argue with the design as hard as you like, and not with the person. Assume the
other side has a reason you have not heard yet, and ask for it.

Reviews here are direct. A pull request gets asked *why* before it gets asked
*whether*, and a design will be pushed on — that is the same standard the ADRs
hold this project's own decisions to, and it is about the work rather than about
you. If a comment ever reads otherwise, say so; it was not meant that way, and
it is worth fixing.

Not welcome, and removed when it appears: harassment, personal attacks,
demeaning or discriminatory comments, and publishing anyone's private
information. Repeated after a warning, it ends participation here.

Anything that also breaks [GitHub's own rules](https://docs.github.com/site-policy/acceptable-use-policies/github-acceptable-use-policies)
can be reported to GitHub directly at
<https://github.com/contact/report-abuse>, which reaches someone other than the
maintainer of this repository.
