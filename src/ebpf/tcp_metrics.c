#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define AF_INET6 10

// Struct for holding the event details, I defined it based on the output of- 
//sudo cat /sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/format
struct event {
    __u64 timestamp;
    __u32 pid;
    __u16 sport, dport;
    __u8 saddr[4], daddr[4];
    __u8 saddr_v6[16], daddr_v6[16];
    __u16 family;
    int state;
    enum type {
        TCP_RETRANSMIT = 1,
        TCP_CONNECT = 0
    } type;
    __u32 netns;
};

// Struct to receive context from tracepoint
struct tcp_retransmit_skb_ctx {
    __u64 _pad0;
    void *skbaddr;
    void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct tcp_retransmit_skb_ctx *ctx)
{

    struct event event = {};

    struct sock *sk = ctx->skaddr;
    struct net *net; 
    __u32 inum;

    bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net); 
    bpf_core_read(&inum, sizeof(inum), &net->ns.inum);


    event.type = TCP_RETRANSMIT;

    event.timestamp = bpf_ktime_get_ns(); //getting the time from here as opposed to userspace to be more accurate
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.sport = ctx->sport; //source port
    event.dport = ctx->dport; // destination port
    event.family = ctx->family; // IP family - added this coz of IPv6. 
    event.state = ctx->state; //TCP state
    event.netns = inum;

    // Reads the IPv4 or IPv6 address based on the family
    if (event.family == AF_INET) {
        bpf_probe_read(event.saddr, sizeof(event.saddr), ctx->saddr);
        bpf_probe_read(event.daddr, sizeof(event.daddr), ctx->daddr);
    } else if (event.family == AF_INET6) {
        bpf_probe_read(event.saddr_v6, sizeof(event.saddr_v6), ctx->saddr_v6);
        bpf_probe_read(event.daddr_v6, sizeof(event.daddr_v6), ctx->daddr_v6);
    }

    // Sends the event to the perf event BPF map using the current CPU
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("tracepoint/tcp/tcp_connect")
int tracepoint__tcp__tcp_connect(struct tcp_retransmit_skb_ctx *ctx)
{
    struct event event = {};

    struct sock *sk = ctx->skaddr;
    struct net *net; 
    __u32 inum;

    bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net); 
    bpf_core_read(&inum, sizeof(inum), &net->ns.inum);

    event.type = TCP_CONNECT;

    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.sport = ctx->sport;
    event.dport = ctx->dport;
    event.family = ctx->family;
    event.state = 0; // not applicable here
    event.netns = inum;

    // Reads the IPv4 or IPv6 address based on the family
    if (event.family == AF_INET) {
        bpf_probe_read(event.saddr, sizeof(event.saddr), ctx->saddr);
        bpf_probe_read(event.daddr, sizeof(event.daddr), ctx->daddr);
    } else if (event.family == AF_INET6) {
        bpf_probe_read(event.saddr_v6, sizeof(event.saddr_v6), ctx->saddr_v6);
        bpf_probe_read(event.daddr_v6, sizeof(event.daddr_v6), ctx->daddr_v6);
    }

    // Sends the event to the perf event BPF map using the current CPU
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";


