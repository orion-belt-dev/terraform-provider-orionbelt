VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLUGIN_DIR ?= $(HOME)/.terraform.d/plugins/registry.terraform.io/orion-belt-dev/orionbelt/$(VERSION)/$(GOOS)_$(GOARCH)

.DEFAULT_GOAL := help

.PHONY: help build install test testacc lint fmt vuln clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the provider into ./bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/terraform-provider-orionbelt .

install: ## Install provider into the local Terraform plugin directory
	mkdir -p $(PLUGIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(PLUGIN_DIR)/terraform-provider-orionbelt_v$(VERSION) .

test: ## Run unit tests with the race detector
	go test -race ./...

testacc: ## Run acceptance tests (needs ORIONBELT_URL and ORIONBELT_API_KEY)
	TF_ACC=1 go test ./internal/provider/ -run TestAcc -v -timeout 30m

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code and tidy modules
	gofmt -s -w .
	go mod tidy

vuln: ## Scan dependencies for known vulnerabilities
	govulncheck ./...

clean: ## Remove build artifacts
	rm -rf bin dist
