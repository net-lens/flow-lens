#!/usr/bin/env bash
set -euo pipefail

arch="$(uname -m)"
case "$arch" in
  x86_64) TARGET="__TARGET_ARCH_x86" ;;
  aarch64|arm64) TARGET="__TARGET_ARCH_arm64" ;;
  armv7l|armv6l|armhf) TARGET="__TARGET_ARCH_arm" ;;
  s390x) TARGET="__TARGET_ARCH_s390" ;;
  riscv64) TARGET="__TARGET_ARCH_riscv" ;;
  ppc64le|ppc64) TARGET="__TARGET_ARCH_powerpc" ;;
  *) echo "Unsupported arch: $arch"; exit 1 ;;
esac

clang -O2 -g -target bpf \
  -I./bpf/include \
  -D${TARGET} \
  -c ./bpf/tcpmonitor/tcp_monitor.c \
  -o ./bpf/tcpmonitor/tcp_monitor.o