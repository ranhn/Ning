BIN := argus
GO  ?= go

.PHONY: all build vet test race selftest demo docker clean

all: vet test build selftest

build:
	$(GO) build -trimpath -ldflags "-s -w" -o bin/$(BIN) ./cmd/argus

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

selftest: build
	./bin/$(BIN) selftest

demo: build
	./bin/$(BIN) demo

docker:
	docker build -t argus:local .

clean:
	rm -rf bin data
