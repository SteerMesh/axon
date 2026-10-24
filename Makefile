.PHONY: build test test-race coverage vet fmt web-build web-test check

build:
	mkdir -p bin
	go build -o bin/mesh-axon ./cmd/mesh-axon
	go build -o bin/axon-relay ./cmd/axon-relay

test:
	go test ./...

test-race:
	go test -race ./...

coverage:
	go test -coverpkg=./internal/...,./pkg/... -coverprofile=coverage.out ./...
	@total="$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%", "", $$3); print $$3}')"; \
		awk -v total="$$total" 'BEGIN { if (total + 0 < 90) exit 1 }'; \
		echo "Go coverage: $$total%"

vet:
	go vet ./...

fmt:
	gofmt -w $$(find cmd internal pkg -name '*.go' -type f)

web-build:
	cd web && npm ci && npm run build

web-test:
	cd web && npm test

check: fmt vet test-race coverage build web-test web-build
