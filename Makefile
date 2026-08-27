SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

BIN_NAME      := cortex
BIN_DIR       := bin
PKG           := github.com/vektcore/cortex
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS       := -s -w \
                 -X $(PKG)/internal/interfaces/cli.version=$(VERSION) \
                 -X $(PKG)/internal/interfaces/cli.commit=$(COMMIT) \
                 -X $(PKG)/internal/interfaces/cli.buildDate=$(BUILD_DATE)

GO            ?= go
# `go install` puts tools in GOPATH/bin, which is not on every PATH. Falling
# back to it means `make init && make lint` works without editing a shell
# profile first.
GOBIN_DIR     := $(shell $(GO) env GOPATH)/bin
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2>/dev/null || echo $(GOBIN_DIR)/golangci-lint)
GOVULNCHECK   ?= $(shell command -v govulncheck 2>/dev/null || echo $(GOBIN_DIR)/govulncheck)

## help: show available targets
help:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Setup

init: ## install dev tools (golangci-lint, govulncheck)
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || \
		$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO) mod download
	$(GO) mod tidy

##@ Build

build: ## build the cortex binary
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BIN_NAME) ./cmd/cortex

install: ## install cortex to GOPATH/bin
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/cortex

##@ Quality

fmt: ## format code
	$(GO) fmt ./...
	@command -v goimports >/dev/null 2>&1 && goimports -w . || true

lint: ## run golangci-lint
	$(GOLANGCI_LINT) run ./...

vet: ## run go vet
	$(GO) vet ./...

vuln: ## scan for known vulnerabilities
	$(GOVULNCHECK) ./...

tidy: ## tidy go.mod
	$(GO) mod tidy

##@ Test

test: test-unit ## run unit tests (default)

test-unit: ## run unit tests with race + coverage
	$(GO) test -race -count=1 -coverprofile=coverage.out -covermode=atomic \
		./internal/domain/... ./internal/application/...

test-integration: ## run integration tests
	$(GO) test -race -count=1 -tags=integration ./test/integration/...

# ESLint resolves plugins from inside the project it lints, and this one has
# none installed. Rather than committing one machine's node path, the global
# install is located here — same thing scripts/bench.sh does.
NPM_GLOBAL ?= $(shell npm root -g 2>/dev/null)

test-e2e: build ## run end-to-end tests against fixtures
	CORTEX_ESLINT_PLUGINS_DIR="$${CORTEX_ESLINT_PLUGINS_DIR:-$(NPM_GLOBAL)}" \
	CORTEX_ESLINT_FORMATTER="$${CORTEX_ESLINT_FORMATTER:-$(NPM_GLOBAL)/@microsoft/eslint-formatter-sarif}" \
	$(GO) test -count=1 -tags=e2e -timeout=10m ./test/e2e/...

test-all: test-unit test-integration test-e2e ## run all test suites

bench: build ## scan the real repositories in scripts/bench-repos.txt
	./scripts/bench.sh

coverage: test-unit ## show coverage in browser
	$(GO) tool cover -html=coverage.out

##@ Release

clean: ## remove build artifacts
	rm -rf $(BIN_DIR) dist coverage.out

.PHONY: help init build install fmt lint vet vuln tidy test test-unit test-integration test-e2e test-all bench coverage clean
