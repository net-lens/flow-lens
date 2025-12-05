CC := clang
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
TARGET_ARCH := __TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
TARGET_ARCH := __TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
TARGET_ARCH := __TARGET_ARCH_arm64
else ifeq ($(UNAME_M),s390x)
TARGET_ARCH := __TARGET_ARCH_s390
else ifeq ($(UNAME_M),riscv64)
TARGET_ARCH := __TARGET_ARCH_riscv
else ifeq ($(UNAME_M),ppc64le)
TARGET_ARCH := __TARGET_ARCH_powerpc
else ifeq ($(UNAME_M),ppc64)
TARGET_ARCH := __TARGET_ARCH_powerpc
else ifeq ($(UNAME_M),armv7l)
TARGET_ARCH := __TARGET_ARCH_arm
else ifeq ($(UNAME_M),armv6l)
TARGET_ARCH := __TARGET_ARCH_arm
else
$(error Unsupported arch: $(UNAME_M))
endif
CFLAGS := -O2 -g -target bpf -I/usr/include -I/usr/src/linux-headers-$(shell uname -r)/include -D__BPF_TRACING__ -D$(TARGET_ARCH)
SRC := ./bpf/tcpmonitor/tcp_monitor.c
OBJ := ./bpf/tcpmonitor/tcp_monitor.o
VMLINUX_H := ./bpf/include/vmlinux.h

DOCKER_TOKEN := $(shell echo $(DOCKER_TOKEN))
TAG := $(shell echo $(TAG))

all: build_ebpf build_go

build_ebpf: $(VMLINUX_H) $(OBJ)

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(OBJ): $(SRC) $(VMLINUX_H)
	$(CC) $(CFLAGS) -c $< -o $@ || (echo "Error building eBPF program"; exit 1)  # Stop on error

build_go:
	sudo go run ./src/main.go || (echo "Error running Go program"; exit 1)  # Stop on error

docker:
	echo $(DOCKER_TOKEN) | docker login ghcr.io -u net-lens --password-stdin
	docker build -t ghcr.io/net-lens/flow-lens:$(TAG) .
	docker push ghcr.io/net-lens/flow-lens:$(TAG)
	docker tag ghcr.io/net-lens/flow-lens:$(TAG) ghcr.io/net-lens/flow-lens:latest
	docker push ghcr.io/net-lens/flow-lens:latest

clean:
	rm -f $(OBJ) 

.PHONY: all build_ebpf build_go clean
