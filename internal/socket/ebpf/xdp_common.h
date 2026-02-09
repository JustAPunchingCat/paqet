#pragma once
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CAP_LEN 2048

static __always_inline int parse_tcp(void *data, void *data_end,
                                     struct tcphdr **tcp)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return 0;
    if (ip->protocol != IPPROTO_TCP) return 0;

    struct tcphdr *t = (void *)(ip + 1);
    if ((void *)(t + 1) > data_end) return 0;

    *tcp = t;
    return 1;
}
