# ADR-021 — What 1.0 promises, and what it does not

**Status:** Proposed — becomes Accepted with the `v1.0.0` release, which is when it takes effect
**Date:** 2026-09-26
**Milestone:** M10
**Implements:** nothing yet; it constrains every release from `v1.0.0` on

## Context

Before 1.0 the project promises one thing, in `CHANGELOG.md` and `SECURITY.md`:
the wire format is held stable and the Go API is not. That was enough while the
only question an operator could ask was "will my objects stay readable". It
still is the most important promise, and since M10 it is checked rather than
stated: CI builds every release from its tag, stores objects through it, and
reads them back with the current build (`test/upgrade/upgrade.sh`).

It is not enough for 1.0, because by now operators build on more than the bytes
at rest. A rotation runs from cron and a dashboard parses its `--json`. An
alert fires on `blindbucket_integrity_failures_total`. A client retries on
`IntegrityCheckFailed` and gives up on `RollbackDetected`. A configuration file
outlives the binary it was written for. Each of those breaks silently if it
changes, and "semantic versioning" says nothing useful until it says *which*
of them the version number is about.

One consequence of the design makes the question sharper than for most tools.
The gateway is stateless and runs as several instances behind a balancer
(ADR-006, and the CI job that uploads one multipart object across two
instances). A rolling upgrade therefore runs two versions side by side, and the
**older** one must read what the **newer** one writes — an upload opened on one
instance is completed on another, an object written by the new version is read
by the old. "New releases read old data" is necessary and not sufficient.

An inventory of what exists, taken from the code rather than from memory:

| Surface | Where it is defined | Versioned today |
|---|---|---|
| Segment format, `BBF1` file, `BBM2` manifest, object metadata | `docs/FORMAT.md` §4–10 | format `1`; `bb-v` in metadata |
| Upload token | FORMAT §11 | `0x01` |
| Object name mapping | FORMAT §15 | `names v1`, with the object format |
| Audit log | FORMAT §14 | `v` field, `1`, independent |
| Keyring file | `internal/crypto/keys` | `version: 1` |
| Freshness index | `internal/freshness` | file version `1` |
| Configuration | `blindbucket.example.yaml`, `internal/config` | — |
| CLI: commands, flags, exit codes 0 / 1 / 2 / 130 | `cmd/blindbucket` | — |
| JSON documents: `keys list`, `gc`, `rotate`, `probe` | `cmd/blindbucket` | — |
| Metrics: 12 names | `internal/obs` | — |
| Admin endpoints: `/healthz`, `/readyz`, `/metrics`, `/debug/pprof/` | `internal/obs` | — |
| S3 error codes of its own: `IntegrityCheckFailed`, `RollbackDetected`, `ObjectNotEncrypted` | `internal/s3api`, `internal/proxy` | — |
| Environment: `BLINDBUCKET_PASSPHRASE`, `${VAR}` in configuration | `cmd/blindbucket`, `internal/config` | — |
| Container image tags | `.goreleaser.yaml` | `X.Y.Z`, without the `v` |

## Decision

Three tiers. What is in a tier is the list below, not whatever seems similar to
it; a surface not named here is in the third.

### Tier 1 — data at rest: readable by every later release, forever

Everything in the first six rows of the inventory: segments, the `BBF1` file,
manifests, object metadata, upload tokens, the name mapping, the audit log, the
keyring file and the freshness index.

- **Every release reads everything any earlier release wrote**, from `v0.1.0`
  on, not just from `v1.0.0`. This is what `test/upgrade/upgrade.sh` checks,
  and a release it fails for is not released.
- **A 1.x release writes nothing an earlier 1.x cannot read, unless the
  operator opts in.** A new format version may arrive in a minor release, but
  it is written only when the configuration asks for it, and it becomes the
  default only in 2.0. This is the rolling-upgrade rule from the context: two
  1.x versions running side by side must be able to read each other's writes.
  An upload token is the sharpest case, because it lives for exactly the length
  of an upload and is issued by one instance and redeemed by another.
- **A format version is never reused.** A change to what a version means is a
  new version, announced in FORMAT §16 and the CHANGELOG. A version once
  readable stays readable: 2.0 may stop *writing* format `1`, never *reading*
  it.

Format `1` moves from "draft" to "stable" in FORMAT §16 as part of `v1.0.0`.
It has been written by every release since `v0.1.0`, which made it stable in
fact long before it was in the table.

### Tier 2 — interfaces: breaking one takes a major version

- **Configuration.** A key keeps its name and meaning. New keys may be added
  in a minor release and default to the old behaviour. A key that is to go
  away is first *deprecated*: still accepted, with a warning at startup naming
  its replacement, for at least one minor release, and removed only in the next
  major. An unknown key stays an error, as it is today — a typo that is
  silently ignored is how an operator believes a setting is on when it is not.
- **The CLI.** Command names, flag names and their meanings, and the exit
  codes: `0` success, `1` failure — including a partially failed `gc` or
  `rotate`, and a `probe` that finds a guard missing — `2` usage, `130`
  interrupted. New commands and flags may be added.
- **The JSON documents** of `keys list`, `gc`, `rotate` and `probe`. A field is
  never removed, renamed, or given a different type or meaning. New fields may
  be added in a minor release, so **a consumer must ignore fields it does not
  know** — which each command's help is to say before 1.0, since today none
  does. Times stay RFC 3339 in UTC and
  durations stay seconds.
- **Metrics.** The names, their types, and their label names. New metrics and
  new label *values* may appear; a label name is never added to an existing
  metric, because that changes the series an alert selects.
- **Admin endpoints.** `/healthz`, `/readyz` and `/metrics`: paths, and the
  status codes that say healthy and ready.
- **The S3 surface.** The set of served operations may grow: a refused
  operation may become served in a minor release. A served operation does not
  become refused. The three error codes of the gateway's own keep their names
  and HTTP statuses, because clients branch on them.
- **Environment and packaging.** `BLINDBUCKET_PASSPHRASE`, `${VAR}` expansion
  in the configuration, and image tags of the form `X.Y.Z`.

### Tier 3 — no promise

- **The Go API.** Everything is under `internal/`, which Go already refuses to
  import from outside the module. It is not a library, and 1.0 does not make it
  one.
- **Human-readable output**: the CLI's tables and summaries, log lines and
  their fields, and the text of error *messages*. The code of an error is
  stable; the sentence next to it is written for a person and will improve.
  Anything that must be parsed has `--json`.
- **`/debug/pprof/`**, off by default and for debugging.
- **Performance figures**, the test suite's environment variables, the TLA+
  model's layout and the Python reference decoder's interface.

### The exception: security

A security fix may break a Tier 2 interface in a minor or patch release when no
compatible fix exists — refusing a request that was served, say, because
serving it was the flaw. It is announced in the CHANGELOG and the advisory, with
what to do. Tier 1 has no such exception: data written by a release stays
readable, and a flaw in reading it is fixed without making it unreadable.

### Support

As `SECURITY.md` has it, with one addition from 1.0: the latest minor release
of the current major is supported, and when a new major is released, the last
minor of the previous one keeps receiving security fixes for six months.

## Alternatives considered

**Stay at 0.x.** Semantic versioning allows anything below 1.0, which is the
problem: an operator cannot tell a release that renames a metric from one that
fixes a typo. The project's claims are measured and its format is specified; a
version number that refuses to promise anything undersells both.

**Promise the Go API.** It would make the internals a public interface without
their having been designed as one. Every refactoring ADR-010's model allows
would need a major version, and nobody has asked to import the packages.

**Freeze the text output too.** It is what people read, and freezing it would
stop it getting better for them, for the sake of scripts that have `--json`.

**Read-forward only — new reads old — without the opt-in rule for writes.**
Simpler to state, and wrong for this design: a stateless gateway is upgraded
while it serves, and during that window old and new instances read each other's
writes. The rule costs a configuration switch per new format; its absence costs
unreadable objects halfway through a deploy.

**Calendar versioning.** It says when, not what changed, which is the one thing
a version number is for here.

## Consequences

**Positive.**

- An operator can tell from the version number whether an upgrade can break a
  dashboard, an alert, a cron job or a configuration file, and the answer for
  objects at rest is always no.
- Rolling upgrades within 1.x are safe by rule rather than by luck.
- Each promise names the test or document that holds it: the upgrade test for
  Tier 1, FORMAT §16 for versions, the `--json` field-set tests for the
  documents.

**Negative.**

- Tier 2 is a list to keep. A metric renamed in passing is now a major version,
  and review has to catch it; the metric names and JSON field sets are not yet
  pinned by a test the way the formats are.
- New wire formats cost a configuration switch and a release of delay before
  they become the default.
- The six-month window for a previous major is a commitment a project run by
  one person has to be able to keep.

**Before `v1.0.0`**, then: FORMAT §16 marks format `1` stable; each `--json`
command's help says to ignore unknown fields; a test pins the metric names; the
known-answer vectors are attached to the release as a versioned artifact; and
this ADR is Accepted.
