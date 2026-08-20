BINARY := goscan
LDFLAGS := -s -w

.PHONY: build test vet check install clean

build:
	mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/goscan

test:
	go test ./...

vet:
	go vet ./...

check: test vet build
	./bin/$(BINARY) version

install:
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/goscan

clean:
	rm -rf bin
