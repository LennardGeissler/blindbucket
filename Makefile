GO      ?= go
PKG     := ./...
BIN     := bin/blindbucket
FUZZTIME ?= 30s

# TLA+ tools for the formal model in spec/tla (M3.5). The jar is not committed.
TLA_VERSION ?= v1.7.4
TLA_TOOLS   ?= .tools/tla2tools.jar

.PHONY: all
all: fmt lint test

##@ Help
.PHONY: help
help: ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' Makefile

##@ Build & Test
.PHONY: build
build: ## Build ./bin/blindbucket
	$(GO) build -o $(BIN) ./cmd/blindbucket

.PHONY: fmt
fmt: ## Format Go source files
	$(GO) fmt $(PKG)

.PHONY: tidy
tidy: ## Tidy and verify go.mod dependencies
	$(GO) mod tidy

.PHONY: vet
vet: ## Run go vet code analysis
	$(GO) vet $(PKG)

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: test
test: ## Run tests with race detection
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover: ## Run tests and print code coverage summary
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -n 1

# Short fuzz run over every fuzz target, as used in CI on every push.
.PHONY: fuzz
fuzz: ## Run short fuzz tests on all fuzz targets
	@for pkg in $$($(GO) list $(PKG)); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			echo "==> $$pkg $$target ($(FUZZTIME))"; \
			$(GO) test $$pkg -run '^$$' -fuzz "^$$target$$" -fuzztime=$(FUZZTIME) || exit 1; \
		done; \
	done

.PHONY: bench
bench: ## Run benchmark suite
	$(GO) test -run '^$$' -bench . -benchmem $(PKG)

##@ Formal Model (spec/tla)
$(TLA_TOOLS):
	@mkdir -p $(dir $@)
	curl -sSLf -o $@ \
	  https://github.com/tlaplus/tlaplus/releases/download/$(TLA_VERSION)/tla2tools.jar

.PHONY: tla-tools
tla-tools: $(TLA_TOOLS)

# Regenerate the TLA+ translation of the PlusCal algorithm. Both live in
# Multipart.tla and both are committed; CI fails if they drift apart.
.PHONY: tla-translate
tla-translate: $(TLA_TOOLS) ## Regenerate TLA+ translation of PlusCal algorithm
	java -cp $(TLA_TOOLS) pcal.trans spec/tla/Multipart.tla
	@rm -f spec/tla/Multipart.cfg spec/tla/Multipart.old

# Run TLC over every configuration. Four of the five are expected to report a
# counterexample; check.sh treats a missing one as a failure.
.PHONY: tla
tla: $(TLA_TOOLS) ## Run TLC model checker over all configurations
	TLA_TOOLS=$(abspath $(TLA_TOOLS)) ./spec/tla/check.sh

##@ Independent Reference Decoder (ref/python)
# Needs `pip install cryptography`.
.PHONY: ref-vectors
ref-vectors: ## Run test vectors against Python reference decoder
	cd ref/python && python3 test_vectors.py

# Differential test against the Go decoder. COUNT is the number of inputs;
# the floor is 100000, which takes a few minutes.
COUNT ?= 100000

.PHONY: ref-diff
ref-diff: ## Run differential tests against Python reference decoder
	cd ref/python && python3 difftest.py --count $(COUNT)

##@ Demo (demo/)
# The terminal recording the README leads with. demo/README.md has the
# asciinema and agg invocations and the reason the terminal size matters.
.PHONY: demo-setup
demo-setup: ## Set up environment for terminal demo recording
	demo/setup.sh

.PHONY: demo
demo: ## Run terminal demo recording script
	demo/demo.sh

.PHONY: demo-stop
demo-stop: ## Stop demo recording environment services
	demo/setup.sh stop

##@ Release & Maintenance
# Validate the release configuration and build everything locally without
# publishing. Run this before tagging: a tag triggers the real thing.
.PHONY: release-check
release-check: ## Validate GoReleaser config and build snapshot locally
	goreleaser check
	goreleaser release --snapshot --clean --skip=publish

.PHONY: image
image: ## Build development Docker image
	docker build -f deploy/Dockerfile -t blindbucket:dev --build-arg VERSION=dev .

.PHONY: vuln
vuln: ## Run govulncheck for known vulnerabilities
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: clean
clean: ## Remove build artifacts and temporary files
	rm -rf bin dist coverage.out
	rm -f spec/tla/*.old spec/tla/states
