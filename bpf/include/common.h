#ifndef __COMMON_H
#define __COMMON_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct flow_key_t {
    __u32 netns;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u16 sport;
    __u16 dport;
};

#ifndef FLOW_PID_MAP_MAX_ENTRIES
#define FLOW_PID_MAP_MAX_ENTRIES 131072
#endif


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLOW_PID_MAP_MAX_ENTRIES);     // up to 128k flows
    __type(key, struct flow_key_t);
    __type(value, pid_t);
} flow_pid_map SEC(".maps");

#endif /* __COMMON_H */
