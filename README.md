# flow-lens

In-container, eBPF-powered network metrics with near-zero overhead — without a node-exporter sidecar.

### Why
- **Avoid costly sidecars**: Node-level exporters scrape everything and force sidecars per workload. This adds CPU/memory and operational cost.
- **Container-scoped visibility**: Collect metrics where they occur (inside the container namespace) with precise attribution.
- **Low overhead**: eBPF attaches to kernel hooks and streams only the data you need.

### What it does (today)
- Implements TCP retransmission metrics. We correlate process PID to retransmissions by:
  - Hooking `tcp_v4_connect` (kprobe/kretprobe) to observe the final 5‑tuple and network namespace.
  - Recording a `flow_key_t` → `pid` mapping in a BPF LRU map.
  - Listening to `tracepoint/tcp/tcp_retransmit_skb` and building the same key to look up the PID.
  - Emitting an event and incrementing Prometheus counters.

The network namespace (`netns`) is part of the key, so flows are correctly attributed inside containers.

### Repository layout
- `bpf/` — eBPF C code and headers.
  - `tcpmonitor/tcp_monitor.c` — attach points, flow→pid mapping, and retransmit event emission.
  - `include/common.h` `include/helper.h` — shared BPF structs/helpers.
  - `include/vmlinux.h` — auto-generated BTF header (see Build).
- `internal/` — Go helpers and the TCP monitor module.
  - `tcpmonitor/` — load/attach/run, Prometheus metric definitions.
  - `common/` — eBPF loader, perf event polling, Prometheus registry.
- `src/main.go` — wires modules together and runs the monitor.

### Metrics
Exported counters (current effective labels used at runtime):
- `ebpf_tcp_connect_total{ip_version,src_ip,src_port,dst_ip,dst_port,pid}`
- `ebpf_tcp_retransmit_total{ip_version,src_ip,src_port,dst_ip,dst_port,pid}`

Example PromQL:
- Per-process retransmissions: `sum by (pid) (rate(ebpf_tcp_retransmit_total[5m]))`
- By 5‑tuple: `sum by (src_ip,src_port,dst_ip,dst_port) (increase(ebpf_tcp_retransmit_total[10m]))`

### Requirements
- Linux kernel with BTF (`/sys/kernel/btf/vmlinux`).
- `clang` and `bpftool` available.
- Root privileges to load eBPF programs.

### Build
The build auto-detects target arch for the BPF compile (`__TARGET_ARCH_*`) and generates `vmlinux.h` if needed.

```bash
cd flow-lens
make build_ebpf         # generates bpf/include/vmlinux.h and builds tcp_monitor.o
```

Under the hood:
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h`
- `clang -target bpf -D__TARGET_ARCH_<auto> ... -c bpf/tcpmonitor/tcp_monitor.c`

Alternatively, direct compile:

```bash
./run_clang.sh          # uses uname -m to set the right __TARGET_ARCH_*
```

### Run
```bash
sudo go run ./src/main.go
```
You’ll see logs for retransmissions while counters are incremented in the in-process Prometheus registry.

### Expose metrics (Prometheus)
The code registers metrics in a custom registry (`internal/common.MetricsRegistry`). Expose it via HTTP:

```go
// Add this to your main (example):
import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/net-lens/flow-lens/internal/common"
)

go func() {
	http.Handle("/metrics", promhttp.HandlerFor(common.MetricsRegistry, promhttp.HandlerOpts{}))
	_ = http.ListenAndServe(":2112", nil)
}()
```

Then run Prometheus (updates the target IP and scrapes port 2112):

```bash
./run_prom.sh
```

Prometheus config lives in `prom_config/prometheus.yml`.

### How it works (details)
- `kprobe/tcp_v4_connect`: stash the `struct sock*` per PID.
- `kretprobe/tcp_v4_connect`: on success, extract final 5‑tuple and `netns`, store `flow_key_t -> pid` in `flow_pid_map` (LRU).
- `tracepoint/tcp/tcp_retransmit_skb`: build the same key, resolve PID, emit perf event; userspace handler increments Prometheus counters.

### Notes and limitations
- Currently focuses on IPv4 paths in the BPF program.
- Requires root to attach kprobes/tracepoints.
- If you run inside a container, ensure CAPs (e.g., `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`) and host BTF are available.

### Roadmap
- IPv6 flow correlation.
- Container metadata enrichment (pod/container/namespace labels) in userspace.
- Additional TCP metrics (rtt, drops, resets) and other protocols.

### License
GPL for eBPF code; see `LICENSE` for details.
# flow-lens