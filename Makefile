MODULE      := github.com/agentnameservice/ans-gateway-auth
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO          ?= go
GOFLAGS     ?= -trimpath
LDFLAGS     := -s -w -X main.version=$(VERSION)
COVER_PKGS  := ./authz/... ./extauthz/... ./replay/... ./config/... ./cmd/...
COVER_MIN   ?= 95

# Pinned agentgateway release binary used by the e2e suite and run-example.
AGW_OS       := $(shell uname -s | tr '[:upper:]' '[:lower:]')
AGW_ARCH     := $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
AGW_PLATFORM ?= $(AGW_OS)-$(AGW_ARCH)
AGW_BIN      := .cache/agentgateway-$(AGW_PLATFORM)
E2E_FLAGS    ?=

.PHONY: build test cover lint clean agentgateway-bin e2e e2e-agentrouter run-example docker

build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/ans-authz ./cmd/ans-authz

test:
	$(GO) test -race -count=1 ./...
	$(GO) vet -tags e2e ./tests/...

cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out $(COVER_PKGS)
	@$(GO) tool cover -func=coverage.out | awk -v min=$(COVER_MIN) '/^total:/ { gsub("%","",$$3); printf "total coverage: %s%% (minimum %s%%)\n", $$3, min; if ($$3+0 < min) exit 1 }'

# golangci-lint embeds its own go/types; its Go version must not be older than the
# toolchain that produced the export data, so pin the toolchain it runs under.
LINT_GOTOOLCHAIN ?= go1.26.0

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		GOTOOLCHAIN=$(LINT_GOTOOLCHAIN) golangci-lint run ./... && \
		GOTOOLCHAIN=$(LINT_GOTOOLCHAIN) golangci-lint run --build-tags e2e ./tests/...; \
	else echo "golangci-lint not installed, skipping"; fi

agentgateway-bin:
	@AGW_PLATFORM=$(AGW_PLATFORM) scripts/fetch-agentgateway.sh

# The suite builds ans-authz itself and needs an ANS reference checkout
# (ANS_E2E_ANS_REPO) with its demo stack running (scripts/demo/start.sh), or
# ANS_E2E_START_STACK=1 to start it. Missing prerequisites skip the suite;
# ANS_E2E_REQUIRED=1 turns those skips into failures for CI.
ANS_E2E_ANS_REPO ?= $(abspath ../opensource-ans)
e2e: agentgateway-bin
	ANS_E2E_ANS_REPO=$(ANS_E2E_ANS_REPO) ANS_E2E_AGENTGATEWAY_BIN=$(CURDIR)/$(AGW_BIN) \
		$(GO) test -tags e2e -count=1 -timeout 15m $(E2E_FLAGS) ./tests/agentgateway/...

# Agent Router suite (tests/agentrouter). AIGW_BIN must point at an aigw
# binary; tests/agentrouter/README.md says how to build or download it.
e2e-agentrouter: build
	@test -n "$(AIGW_BIN)" || { echo "AIGW_BIN is required (path to the aigw binary)" >&2; exit 2; }
	AIGW_BIN=$(AIGW_BIN) $(GO) test -tags e2e -count=1 -p 1 -timeout 25m $(E2E_FLAGS) ./tests/agentrouter/...

run-example: build agentgateway-bin
	AGENTGATEWAY_BIN=$(CURDIR)/$(AGW_BIN) scripts/run-example.sh $(EXAMPLE)

IMAGE ?= ans-authz:dev

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

clean:
	rm -rf bin coverage.out
