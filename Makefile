GO      ?= go
PKG     := ./...
BIN     := bin/blindbucket
FUZZTIME ?= 30s

# TLA+ tools for the formal model in spec/tla (M3.5). The jar is not committed.
TLA_VERSION ?= v1.7.4
TLA_TOOLS   ?= .tools/tla2tools.jar

# promtool for the alerting rules in deploy/prometheus, run from the image so
# nothing needs installing.
PROMETHEUS_IMAGE ?= prom/prometheus:v3.15.0

# helm and kubeconform for the chart in deploy/helm, from their images as well.
HELM_IMAGE        ?= alpine/helm:4.3.0
KUBECONFORM_IMAGE ?= ghcr.io/yannh/kubeconform:v0.7.0
CHART             := deploy/helm/blindbucket

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
# Production code only: the test helpers are left out of the count. CI runs this
# with MinIO, Vault and the KMS emulator up (docker compose --profile keys) and
# Go 1.24; without them their tests skip and the total drops. Newer toolchains
# count blocks differently and report a few points more.
COVERPKG = $(shell $(GO) list $(PKG) | grep -v -e /internal/testprovider -e /test/ | paste -sd, -)
cover: ## Run tests and report coverage of production code.
	$(GO) test -race -count=1 -coverpkg=$(COVERPKG) -coverprofile=coverage.out $(PKG)
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

# Regenerate the TLA+ translations of the PlusCal algorithms. Each module holds
# its algorithm and its translation, both committed; CI fails if they drift apart.
TLA_MODULES := Multipart Migrate

.PHONY: tla-translate
tla-translate: $(TLA_TOOLS) ## Regenerate the TLA+ translations.
	@for m in $(TLA_MODULES); do \
		java -cp $(TLA_TOOLS) pcal.trans spec/tla/$$m.tla || exit 1; \
		rm -f spec/tla/$$m.cfg spec/tla/$$m.old; \
	done

# Run TLC over every configuration. Eleven of the thirteen are expected to report a
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

##@ Alerting rules (deploy/prometheus)

.PHONY: alerts
alerts: ## Check the Prometheus alerting rules and run their tests.
	docker run --rm -v "$(CURDIR)/deploy/prometheus:/rules:ro" -w /rules \
		--entrypoint promtool $(PROMETHEUS_IMAGE) check rules alerts.yaml
	docker run --rm -v "$(CURDIR)/deploy/prometheus:/rules:ro" -w /rules \
		--entrypoint promtool $(PROMETHEUS_IMAGE) test rules tests.yaml

##@ Helm chart (deploy/helm)

HELM = docker run --rm -v "$(CURDIR)/deploy/helm:/charts" -w /charts $(HELM_IMAGE)

# Lint, render with every optional part on, validate what renders against the
# Kubernetes schemas, and require the two refusals: no TLS, and no values at
# all. The chart's copy of the alerting rules must match deploy/prometheus.
.PHONY: chart
chart: ## Lint, render and validate the Helm chart.
	cmp deploy/prometheus/alerts.yaml $(CHART)/files/alerts.yaml
	$(HELM) lint blindbucket -f blindbucket/ci/full-values.yaml
	@mkdir -p bin
	$(HELM) template bb blindbucket -f blindbucket/ci/full-values.yaml > bin/chart.yaml
	docker run --rm -v "$(CURDIR)/bin:/w" $(KUBECONFORM_IMAGE) -strict -summary \
		-schema-location default \
		-schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
		/w/chart.yaml
	@! $(HELM) template bb blindbucket -f blindbucket/ci/full-values.yaml --set tls.existingSecret= >/dev/null 2>&1 \
		|| { echo "the chart rendered without TLS"; exit 1; }
	@echo "refuses to render without TLS: ok"
	@# The EKS shape: credentials from the ServiceAccount's role, no AWS key in
	@# any Secret, and the API token still not mounted (ADR-024).
	$(HELM) lint blindbucket -f blindbucket/ci/eks-values.yaml
	$(HELM) template bb blindbucket -f blindbucket/ci/eks-values.yaml > bin/chart-eks.yaml
	docker run --rm -v "$(CURDIR)/bin:/w" $(KUBECONFORM_IMAGE) -strict -summary -schema-location default /w/chart-eks.yaml
	@grep -q 'credential_source: web_identity' bin/chart-eks.yaml \
		&& grep -q 'eks.amazonaws.com/role-arn' bin/chart-eks.yaml \
		&& grep -q 'serviceAccountName: bb-blindbucket' bin/chart-eks.yaml \
		&& grep -q 'automountServiceAccountToken: false' bin/chart-eks.yaml \
		&& ! grep -q -e UPSTREAM_ACCESS_KEY_ID -e KMS_ACCESS_KEY_ID bin/chart-eks.yaml \
		|| { echo "the EKS render is not what the values ask for"; exit 1; }
	@echo "renders for IRSA with no AWS key in a Secret: ok"
	@! $(HELM) template bb blindbucket -f blindbucket/ci/full-values.yaml --set upstream.existingSecret= >/dev/null 2>&1 \
		|| { echo "the chart rendered static credentials without a Secret"; exit 1; }
	@! $(HELM) template bb blindbucket -f blindbucket/ci/eks-values.yaml --set upstream.credentialSource=sso >/dev/null 2>&1 \
		|| { echo "the chart rendered an unknown credential source"; exit 1; }
	@echo "refuses static without a Secret, and an unknown source: ok"

.PHONY: chart-e2e
chart-e2e: ## Install the chart in kind and put an object through it.
	test/helm/kind.sh

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
