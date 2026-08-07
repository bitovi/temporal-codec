.PHONY: fmt lint test clean help

## fmt: Format code with gofmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -w .
	@echo "✓ Code formatted"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "✓ go vet passed"

## lint: Run all linters (vet + gofmt)
lint: vet
	@echo "Running gofmt check..."
	@gofmt -l . | grep -q . && echo "✗ gofmt issues found" && exit 1 || echo "✓ gofmt passed"

## test: Run all tests
test:
	@echo "Running tests..."
	@go test ./... -v

## check: Format, lint, and test
check: fmt lint test
	@echo "✓ All checks passed"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@go clean
	@rm -f ./cmd/server/server
	@echo "✓ Clean complete"

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
