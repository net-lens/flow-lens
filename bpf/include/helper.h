#ifndef __HELPER_H
#define __HELPER_H

#include "vmlinux.h"

static __always_inline void be32_to_bytes(__be32 val, __u8 out[4])
{
	__builtin_memcpy(out, &val, sizeof(val));
}

static __always_inline void be16_to_bytes(__be16 val, __u8 out[2])
{
	__builtin_memcpy(out, &val, sizeof(val));
}

/* helper: fill IPv4 key */
static __always_inline void fill_key_ipv4(struct flow_key_t *k,
    __u32 netns,
    const void *saddr,
    const void *daddr,
    __u16 sport, __u16 dport)
{
    k->netns = netns;
    __builtin_memcpy(k->saddr, saddr, 4);
    __builtin_memcpy(k->daddr, daddr, 4);
    k->sport = sport;
    k->dport = dport;
}

#endif /* __HELPER_H */

