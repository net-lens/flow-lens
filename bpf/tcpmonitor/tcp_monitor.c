// bpf/tcpmonitor/tcp_monitor.bpf.c
#include "vmlinux.h"
#include "common.h"
#include "helper.h"
#include "helper.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

/* Event structure sent to userspace via perf buffer */
struct event {
    __u64 timestamp;          // 8 bytes

    pid_t pid;                // pid_t is 32-bit on Linux
    int state;              // int is 32-bit in kernel
    __u32 type;
    __u32 netns;

    __u16 sport;
    __u16 dport;
    __u16 family;

    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

/* tracepoint context layout used (partial) */
struct tcp_tp_ctx {
    __u64 _pad0;
    void *skbaddr;
    void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

/* perf event map for user-space events */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct sock *);
} connect_sk_map SEC(".maps");


static inline int tcp_helper(struct tcp_tp_ctx *ctx, __u32 type) {
    struct event evt = {};
    struct flow_key_t key = {};
    struct sock *sk = NULL;
    struct net *netp = NULL;
    __u32 inum = 0;

    /* read sk pointer from ctx */
    bpf_probe_read_kernel(&sk, sizeof(sk), &ctx->skaddr);
    if (!sk)
        return 0;

    bpf_probe_read_kernel(&netp, sizeof(netp), &sk->__sk_common.skc_net.net);
    if (!netp)
        return 0;

    bpf_probe_read_kernel(&inum, sizeof(inum), &netp->ns.inum);


    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;
    evt.type = type;
    evt.timestamp = bpf_ktime_get_ns();
    evt.sport = sport;
    evt.dport = dport;
    evt.family = ctx->family;
    evt.state = ctx->state;
    evt.netns = inum;
    evt.pid = 0;

    /* Build key and copy addresses according to family */
    if (evt.family == AF_INET) {
        /* IPv4 path: ctx->saddr and ctx->daddr are arrays of 4 bytes */
        __builtin_memcpy(evt.saddr, ctx->saddr, 4);
        __builtin_memcpy(evt.daddr, ctx->daddr, 4);
        fill_key_ipv4(&key, inum, evt.saddr, evt.daddr, sport, dport);
    }
    else {
        return 0;
    }

    pid_t *pid = bpf_map_lookup_elem(&flow_pid_map, &key);
    if (pid) {
        evt.pid = *pid;
    }

    /* emit connect event to userspace */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}


/* tracepoint: tcp_retransmit_skb */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct tcp_tp_ctx *ctx)
{
    return tcp_helper(ctx, 1);
}

SEC("kprobe/tcp_v4_connect")
int bpf_tcp_v4_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Store sk for use in the retprobe
    bpf_map_update_elem(&connect_sk_map, &pid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int bpf_ret_tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);  // return code from tcp_v4_connect
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = bpf_map_lookup_elem(&connect_sk_map, &pid);
    if (!skpp)
        return 0;

    struct sock *sk = *skpp;
    bpf_map_delete_elem(&connect_sk_map, &pid);

    if (!sk)
        return 0;

    if (ret != 0) {
        // connect() failed, so skip
        return 0;
    }

    struct net *netp = NULL;
    __u32 inum = 0;

    // --- Read netns ---
    bpf_probe_read_kernel(&netp, sizeof(netp), &sk->__sk_common.skc_net.net);
    if (!netp)
        return 0;

    bpf_probe_read_kernel(&inum, sizeof(inum), &netp->ns.inum);

    // --- Read final socket parameters ---
    __be32 saddr_be = 0, daddr_be = 0;
    __u16 sport_host = 0;
    __be16 dport_be = 0;

    bpf_probe_read_kernel(&saddr_be, sizeof(saddr_be), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr_be, sizeof(daddr_be), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport_host, sizeof(sport_host), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);

    // Convert to byte arrays for your key
    __u8 saddr[4], daddr[4];
    be32_to_bytes(saddr_be, saddr);
    be32_to_bytes(daddr_be, daddr);

    struct flow_key_t key = {};
    fill_key_ipv4(&key, inum, saddr, daddr,
                  sport_host,
                  bpf_ntohs(dport_be));
    
    bpf_printk("tcp_v4_connect(ret) saddr=%x sport=%u netns=%u\n", *(__u32 *)key.saddr, key.sport, inum);

    // Record pid for this flow
    bpf_map_update_elem(&flow_pid_map, &key, &pid, BPF_ANY);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
