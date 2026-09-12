GO ?= go
export GOTOOLCHAIN ?= auto

.PHONY: build test lint fmt
build:
	$(GO) build -ldflags "-X main.Version=$$(git describe --tags --always --dirty)" -o bin/sage-gateway ./cmd/sage-gateway

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -l -w .
