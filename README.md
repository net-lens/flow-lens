## Overview
Flow Lens is an in-container eBPF agent that correlates network metrics with the specific Kubernetes pod/container experiencing them, avoiding host-level exporters or per-pod sidecars.

## Motivation & Approach
Container-level network telemetry is still hard to expose: host exporters blur pod boundaries, while per-pod sidecars add operational and performance overhead. Flow Lens uses eBPF hooks to keep the logic in the kernel, correlates network alerts with their originating workloads, and exposes pod-scoped TCP health without extra sidecars.

## Cons
- Requires root/capabilities to load eBPF and access `/sys/kernel/btf/vmlinux`.
- Currently IPv4-only; IPv6 flows are ignored.

## Deploy (DaemonSet)
```bash
# create namespace & service account
kubectl apply -f deploy/ebpf/namespace.yaml
kubectl apply -f deploy/ebpf/serviceaccount.yaml

# deploy the agent
kubectl apply -f deploy/ebpf/daemonset.yaml
```
The DaemonSet expects the container image published from `.github/workflows/release.yaml` (tags like `ghcr.io/net-lens/flow-lens:v0.0.1`). Update the manifest if you host the image elsewhere.

## Exposed Metrics
| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `flow_lens_tcp_retransmit_total` | Counter | `source_ip`, `destination_ip`, `destination_port`, `target_pod`, `target_container`, `target_namespace`, `state` | Counts retransmissions with the current TCP state (e.g., `established`, `fin_wait_1`) so you can alert on pods stuck in specific phases. |
| `flow_lens_tcp_reset_total` | Counter | `source_ip`, `destination_ip`, `destination_port`, `target_pod`, `target_container`, `target_namespace`, `state`, `direction` | Captures TCP resets. `direction` indicates whether the pod sent (`outbound`) or received (`inbound`) the RST, enabling separate alert policies. |
