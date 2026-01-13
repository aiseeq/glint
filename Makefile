.PHONY: build install clean test test-coverage lint fmt check help

# Build variables
BINARY_NAME=glint
BUILD_DIR=bin
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default target
all: build

## Build

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/glint

install: build ## Install to ~/bin (recommended)
	@mkdir -p $(HOME)/bin
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/bin/$(BINARY_NAME)
	@echo "Installed to $(HOME)/bin/$(BINARY_NAME)"

install-gopath: ## Install to GOPATH/bin
	go install $(LDFLAGS) ./cmd/glint

clean: ## Remove build artifacts
	@rm -rf $(BUILD_DIR)
	@go clean

## Testing

test: ## Run all tests
	go test -v ./...

test-short: ## Run tests without long-running ones
	go test -short -v ./...

test-coverage: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-golden: ## Run golden tests
	go test -v ./pkg/rules/... -run Golden

test-golden-update: ## Update golden files
	go test -v ./pkg/rules/... -run Golden -update

## Quality

lint: ## Run linter
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

fmt: ## Format code
	go fmt ./...
	@echo "Code formatted"

fmt-check: ## Check if code is formatted
	@test -z "$$(gofmt -l .)" || (echo "Code is not formatted. Run 'make fmt'" && exit 1)

vet: ## Run go vet
	go vet ./...

check: fmt-check vet lint test ## Run all checks

## Development

run: build ## Build and run with default args
	./$(BUILD_DIR)/$(BINARY_NAME) check

run-verbose: build ## Build and run with verbose output
	./$(BUILD_DIR)/$(BINARY_NAME) check --verbose

deps: ## Download dependencies
	go mod download

deps-update: ## Update dependencies
	go get -u ./...
	go mod tidy

## Self-analysis

self-check: build ## Run glint on itself
	./$(BUILD_DIR)/$(BINARY_NAME) check ./...

## Help

help: ## Show this help
	@echo "Glint - Unified Code Analyzer"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
