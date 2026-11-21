ARCH := $(shell uname -m)
BPF_CFLAGS := -O2 -g -Wall -I/usr/include/$(ARCH)-linux-gnu
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all deps generate build test vet e2e clean

all: generate build

deps:
	go mod tidy

# Compile bpf/*.bpf.c and generate Go bindings (needs clang + libbpf headers).
generate:
	cd internal/firewall && go run github.com/cilium/ebpf/cmd/bpf2go \
		-go-package firewall -target bpfel -tags linux -no-strip \
		-type event -type lpm_key -type settings \
		firewall ../../bpf/firewall.bpf.c -- $(BPF_CFLAGS)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/sbx ./cmd/sbx

test:
	go test -race ./...

vet:
	go vet ./...

# End-to-end tests against the real kernel. Needs root.
e2e: build
	sudo BIN=./bin/sbx ./scripts/e2e.sh

clean:
	rm -rf bin internal/firewall/firewall_bpfel.go internal/firewall/firewall_bpfel.o
