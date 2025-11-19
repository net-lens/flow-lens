clang -O2 -g -target bpf \
  -I./bpf/include \
  -D __TARGET_ARCH_x86 \
  -c ./bpf/tcpmonitor/tcp_monitor.c \
  -o ./bpf/tcpmonitor/tcp_monitor.o