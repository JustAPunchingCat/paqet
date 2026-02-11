#pragma once
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CAP_LEN 2048

// Define VLAN constants/structs manually to avoid dependency on linux/if_vlan.h
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int parse_tcp(void *data, void *data_end,
                                     struct tcphdr **tcp)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    
    __u16 h_proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    // Handle VLANs (802.1Q and 802.1ad)
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end) return 0;
        h_proto = vlan->h_vlan_encapsulated_proto;
        cursor = (void *)(vlan + 1);
    }

    if (h_proto != bpf_htons(ETH_P_IP)) return 0;

    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end) return 0;
    if (ip->protocol != IPPROTO_TCP) return 0;

    // Calculate variable IP header length (IHL is in 32-bit words)
    __u32 ip_len = ip->ihl * 4;
    if (ip_len < 20) return 0;

    struct tcphdr *t = (void *)((unsigned char *)ip + ip_len);
    if ((void *)(t + 1) > data_end) return 0;

    *tcp = t;
    return 1;
}
