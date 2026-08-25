BINARY := goscan
LDFLAGS := -s -w
GOVULNCHECK_VERSION := v1.7.0

.PHONY: build test test-race vet verify tidy-check security check release-check release-dist install clean

build:
	mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/goscan

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

verify:
	go mod verify

tidy-check:
	go mod tidy -diff

security:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

check: test vet build
	./bin/$(BINARY) version

release-check: tidy-check verify test-race vet build security
	./bin/$(BINARY) version

release-dist:
	./build.sh

install:
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/goscan

clean:
	rm -rf bin coverage.out dist
