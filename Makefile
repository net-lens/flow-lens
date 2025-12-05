SHELL := /usr/bin/env bash

## Toolchain -------------------------------------------------------------------
CLANG        ?= clang
LLC          ?= llc
GO           ?= go
BPFOBJ_STRIP ?= llvm-strip

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	BPF_ARCH := __TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
	BPF_ARCH := __TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
	BPF_ARCH := __TARGET_ARCH_arm64
else ifeq ($(UNAME_M),armv7l)
	BPF_ARCH := __TARGET_ARCH_arm
else ifeq ($(UNAME_M),armv6l)
	BPF_ARCH := __TARGET_ARCH_arm
else ifeq ($(UNAME_M),ppc64)
	BPF_ARCH := __TARGET_ARCH_powerpc
else ifeq ($(UNAME_M),ppc64le)
	BPF_ARCH := __TARGET_ARCH_powerpc
else ifeq ($(UNAME_M),s390x)
	BPF_ARCH := __TARGET_ARCH_s390
else ifeq ($(UNAME_M),riscv64)
	BPF_ARCH := __TARGET_ARCH_riscv
else
	$(error Unsupported arch: $(UNAME_M))
endif

KERNEL_RELEASE := $(shell uname -r)
BPF_SRC_DIR    := bpf
BPF_SRCS       := $(wildcard $(BPF_SRC_DIR)/*/*.c)
BPF_OBJS       := $(patsubst %.c,%.o,$(BPF_SRCS))
VMLINUX_H      := bpf/include/vmlinux.h

BPF_CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__BPF_TRACING__ \
	-D$(BPF_ARCH) \
	-Ibpf/include \
	-I/usr/include \
	-I/usr/src/linux-headers-$(KERNEL_RELEASE)/include

GO_MAIN   := ./src/main.go
GO_BIN    := bin/flow-lens
GO_FLAGS ?=

REGISTRY ?= ghcr.io/net-lens/flow-lens
TAG      ?= dev

## Meta ------------------------------------------------------------------------
.PHONY: help
help:
	@echo "Flow Lens build targets"
	@echo "  make all        - build eBPF object and Go binary"
	@echo "  make ebpf       - build only the eBPF object file"
	@echo "  make go         - build Go binary into ./bin"
	@echo "  make run        - run the Go control-plane locally"
	@echo "  make docker     - build and push container image"
	@echo "  make clean      - remove build artifacts"

## Aggregate targets -----------------------------------------------------------
.PHONY: all
all: ebpf go

.PHONY: ebpf
ebpf: $(BPF_OBJS)

.PHONY: go
go: $(GO_BIN)

.PHONY: test
test:
	$(GO) test ./...

.PHONY: run
run: $(BPF_OBJS)
	$(GO) run $(GO_FLAGS) $(GO_MAIN)

## eBPF build ------------------------------------------------------------------
$(VMLINUX_H):
	@mkdir -p $(@D)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_SRC_DIR)/%.o: $(BPF_SRC_DIR)/%.c $(VMLINUX_H)
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPFOBJ_STRIP) -g $@

## Go build --------------------------------------------------------------------
$(GO_BIN): $(shell find internal cmd src -name '*.go' 2>/dev/null)
	@mkdir -p $(@D)
	$(GO) build $(GO_FLAGS) -o $@ $(GO_MAIN)

## Container image -------------------------------------------------------------
.PHONY: docker
docker: $(BPF_OBJS)
	docker build -t $(REGISTRY):$(TAG) .
	docker tag $(REGISTRY):$(TAG) $(REGISTRY):latest
	docker push $(REGISTRY):$(TAG)
	docker push $(REGISTRY):latest

## Cleanup ---------------------------------------------------------------------
.PHONY: clean
clean:
	rm -f $(BPF_OBJS)
	rm -rf bin
