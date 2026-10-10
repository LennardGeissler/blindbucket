<!--
Thanks for the pull request. The checklist below is the one in CONTRIBUTING.md,
"Pull requests"; it is here so that nothing on it is a surprise in review.
Delete what does not apply rather than ticking it.
-->

Closes #

## What and why

<!-- What the change does for someone using the gateway, and why this way.
     Name the alternatives you rejected and what was wrong with them. -->

## What was run

<!-- Which of these, and against what. A green `go test ./...` without
     services is not proof: the provider tests skip silently without them. -->

- [ ] `make all` (`fmt`, `lint`, `test`)
- [ ] Integration tests relevant to the change, with their services up (MinIO, Garage, Vault, KMS)
- [ ] A test fails without the change

## Before review

- [ ] New behaviour has tests; security-relevant behaviour has a test that plays the hostile party and requires an error rather than plaintext
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`, written for a user of the gateway and stating the limits of what was added
- [ ] Every document the change affects is updated, not only the ones touched (`README.md`, `docs/`, the ADR index, `blindbucket.example.yaml`, the CLI's `usage()`)
- [ ] A decision later code has to live with is recorded in an ADR
- [ ] Commit messages explain why, as described in CONTRIBUTING.md, "Commit messages"
