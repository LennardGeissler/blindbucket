GO      ?= go
PKG     := ./...
BIN     := bin/blindbucket
FUZZTIME ?= 30s

# TLA+ tools for the formal model in spec/tla (M3.5). The jar is not committed.
TLA_VERSION ?= v1.7.4
TLA_TOOLS   ?= .tools/tla2tools.jar

##@ Build and test
.PHONY: all
all: fmt lint test ## Format, lint, and test the project.

.PHONY: help
help: ## List documented targets by section.
	@awk '/^##@ / { section = substr($$0, 5); if (shown) printf "\n"; printf "%s\n", section; shown = 0; next } /^[[:alnum:]_.-]+:.*##/ { target = $$1; sub(/:.*/, "", target); description = $$0; sub(/^[^#]*## ?/, "", description); printf "  %-18s %s\n", target, description; shown = 1 }' Makefile

.PHONY: build
build: ## Build the blindbucket binary.
	$(GO) build -o $(BIN) ./cmd/blindbucket

.PHONY: fmt
fmt: ## Format Go packages.
	$(GO) fmt $(PKG)

.PHONY: tidy
tidy: ## Synchronize go.mod and go.sum.
	$(GO) mod tidy

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet $(PKG)

.PHONY: lint
lint: ## Run golangci-lint.
	golangci-lint run

.PHONY: test
test: ## Run race-enabled Go tests.
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover: ## Run tests and report coverage.
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -n 1

##@ Fuzz and benchmarks

# Short fuzz run over every fuzz target, as used in CI on every push.
.PHONY: fuzz
fuzz: ## Run a short fuzz smoke test for each target.
	@for pkg in $$($(GO) list $(PKG)); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			echo "==> $$pkg $$target ($(FUZZTIME))"; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$target$$" -fuzztime=$(FUZZTIME) || exit 1; \
		done; \
	done

.PHONY: bench
bench: ## Run Go benchmarks.
	$(GO) test -run '^$$' -bench . -benchmem $(PKG)

##@ Formal model (spec/tla)

$(TLA_TOOLS):
	@mkdir -p $(dir $@)
	curl -sSLf -o $@ \
	  https://github.com/tlaplus/tlaplus/releases/download/$(TLA_VERSION)/tla2tools.jar

.PHONY: tla-tools
tla-tools: $(TLA_TOOLS)

# Regenerate the TLA+ translation of the PlusCal algorithm. Both live in
# Multipart.tla and both are committed; CI fails if they drift apart.
.PHONY: tla-translate
tla-translate: $(TLA_TOOLS) ## Regenerate the TLA+ translation.
	java -cp $(TLA_TOOLS) pcal.trans spec/tla/Multipart.tla
	@rm -f spec/tla/Multipart.cfg spec/tla/Multipart.old

# Run TLC over every configuration. Four of the five are expected to report a
# counterexample; check.sh treats a missing one as a failure.
.PHONY: tla
tla: $(TLA_TOOLS) ## Check every TLA+ model configuration.
	TLA_TOOLS=$(abspath $(TLA_TOOLS)) ./spec/tla/check.sh

##@ Reference decoder (ref/python)

# Needs `pip install cryptography`.
.PHONY: ref-vectors
ref-vectors: ## Check the Python reference against known vectors.
	cd ref/python && python3 test_vectors.py
	cd ref/python && python3 test_names_vectors.py

# Differential test against the Go decoder. COUNT is the number of inputs;
# The floor is 100000, which takes a few minutes.
COUNT ?= 100000

.PHONY: ref-diff
ref-diff: ## Compare the Python and Go decoders.
	cd ref/python && python3 difftest.py --count $(COUNT)
	cd ref/python && python3 difftest_names.py --count $(COUNT)

##@ Upgrade tests

# Every released version's objects, keyring and files read back by the current
# build. Needs the compose file's MinIO and the AWS CLI; see test/upgrade/.
.PHONY: upgrade-test
upgrade-test: ## Test reading data written by released versions.
	test/upgrade/upgrade.sh

##@ Demo recording (demo/)

# The terminal recording the README leads with. demo/README.md has the
# asciinema and agg invocations and the reason the terminal size matters.
.PHONY: demo-setup
demo-setup: ## Prepare the terminal demo.
	demo/setup.sh

.PHONY: demo
demo: ## Record the terminal demo.
	demo/demo.sh

.PHONY: demo-stop
demo-stop: ## Stop the demo services.
	demo/setup.sh stop

##@ Release and maintenance

# Validate the release configuration and build everything locally without
# publishing. Run this before tagging: a tag triggers the real thing.
.PHONY: release-check
release-check: ## Validate and build a release snapshot.
	goreleaser check
	goreleaser release --snapshot --clean --skip=publish

.PHONY: image
image: ## Build the container image.
	docker build -f deploy/Dockerfile -t blindbucket:dev --build-arg VERSION=dev .

.PHONY: vuln
vuln: ## Check dependencies for known vulnerabilities.
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: clean
clean: ## Remove generated files.
	rm -rf bin dist coverage.out
	rm -f spec/tla/*.old spec/tla/states
