BINARY     := dexpose
MODULE     := github.com/zuhayrb/dexpose
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE       ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: all build test lint clean release snapshot tidy

all: build

## build: compile the binary for the current platform
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## test: run all tests with the race detector
test:
	go test -race -count=1 ./...

## test-cover: run tests and open coverage report
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

## lint: run go vet and staticcheck
lint:
	go vet ./...
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed; skipping"

## tidy: tidy and verify module dependencies
tidy:
	go mod tidy
	go mod verify

## clean: remove build artifacts
clean:
	rm -f $(BINARY) coverage.out

## snapshot: build a local goreleaser snapshot (no publish)
snapshot:
	goreleaser release --snapshot --clean

## release: tag and push; CI triggers the actual release
release:
	@test -n "$(TAG)" || (echo "usage: make release TAG=v0.1.0" && exit 1)
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)

help:
	@grep -E '^## ' Makefile | sed 's/## //'
