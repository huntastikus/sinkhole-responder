.DEFAULT_GOAL := help

VERSION ?= dev
FUZZTIME ?= 15s
BINARY := ./bin/sinkhole-responder

.PHONY: help build test test-race fuzz lint tidy run docker compose-up compose-down ca test-e2e playwright clean

help:
	@printf '%s\n' \
		'build         Build ./bin/sinkhole-responder' \
		'test          Run the test suite' \
		'test-race     Run the test suite with the race detector' \
		'fuzz          Run all four fuzz targets (FUZZTIME=$(FUZZTIME) each)' \
		'lint          Run go vet and check gofmt' \
		'tidy          Run go mod tidy' \
		'run           Build and run with config.example.yaml' \
		'docker        Build sinkhole-responder:$(VERSION)' \
		'compose-up    Build and start the Compose service' \
		'compose-down  Stop the Compose service' \
		'ca            Create a lab-only local CA in ./ca' \
		'test-e2e      Install and run the Playwright end-to-end suite' \
		'playwright    Alias for test-e2e' \
		'clean         Remove ./bin and ./ca'

# Web and responder assets are embedded by Go; no separate asset build is needed.
build:
	@mkdir -p ./bin
	CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/sinkhole-responder

test:
	go test ./...

test-race:
	go test ./... -race

fuzz:
	go test ./internal/rules -run=^$$ -fuzz=^FuzzHostNormalizeAndMatch$$ -fuzztime=$(FUZZTIME)
	go test ./internal/rules -run=^$$ -fuzz=^FuzzRuleCompile$$ -fuzztime=$(FUZZTIME)
	go test ./internal/httpserver -run=^$$ -fuzz=^FuzzHostHeader$$ -fuzztime=$(FUZZTIME)
	go test ./internal/respond -run=^$$ -fuzz=^FuzzSelect$$ -fuzztime=$(FUZZTIME)

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

tidy:
	go mod tidy

run: build
	$(BINARY) -config config.example.yaml

docker:
	docker build --build-arg VERSION=$(VERSION) -t sinkhole-responder:$(VERSION) .

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

# Lab use only: the generated CA can impersonate any HTTPS site once trusted.
ca: build
	$(BINARY) create-ca -dir ./ca -cn "Sinkhole Local CA"

test-e2e:
	cd playwright && npm ci && npx playwright test

playwright: test-e2e

clean:
	rm -rf ./bin ./ca
