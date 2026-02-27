.PHONY: build test lint clean

# Build standalone linter binary
build:
	go build -o bin/logchecklint ./cmd/logchecklint

# Run all tests
test:
	go test -v -race ./pkg/analyzer/...

# Build custom golangci-lint with the plugin
build-plugin:
	golangci-lint custom

# Run the custom golangci-lint on a target project
lint: build-plugin
	./custom-gcl run ./...

# Clean build artifacts
clean:
	rm -f bin/logchecklint custom-gcl

# Run standalone linter on a target
run: build
	./bin/logchecklint ./...

# Download dependencies
deps:
	go mod tidy
	go mod download
