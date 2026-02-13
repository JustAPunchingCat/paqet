#pragma once
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
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
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int parse_tcp(void *data, void *data_end,
                                     struct tcphdr **tcp,
                                     __u32 *dst_ipv4,
                                     struct in6_addr *dst_ipv6,
                                     __u16 *l3_proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;

    *l3_proto = 0;
    
    __u16 h_proto = eth->h_proto;
    void *cursor = (void *)(eth + 1);

    // Handle VLANs (802.1Q and 802.1ad) - Manual unroll for verifier safety
    // Level 1
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end) return 0;
        h_proto = vlan->h_vlan_encapsulated_proto;
        cursor = (void *)(vlan + 1);

        // Level 2 (QinQ)
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vlan2 = cursor;
            if ((void *)(vlan2 + 1) > data_end) return 0;
            h_proto = vlan2->h_vlan_encapsulated_proto;
            cursor = (void *)(vlan2 + 1);
        }
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end) return 0;
        if (ip->protocol != IPPROTO_TCP) return 0;

        // Manually read IHL to avoid bitfield issues and ensure byte access
        // volatile forces the compiler to emit a byte load, preventing optimization
        // into a larger load that might confuse the verifier.
        __u8 ver_ihl = *((__u8 *)ip);
        __u32 ip_len = (ver_ihl & 0x0F) << 2;
        
        if (ip_len < 20) return 0;
        
        // Verify variable length IP header is within bounds
        if ((void *)((unsigned char *)ip + ip_len) > data_end) return 0;

        struct tcphdr *t = (void *)((unsigned char *)ip + ip_len);
        if ((void *)(t + 1) > data_end) return 0;

        *tcp = t;
        *l3_proto = ETH_P_IP;
        *dst_ipv4 = ip->daddr;
        return 1;
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end) return 0;
        
        // We only handle TCP directly following IPv6 header (no extension headers for now)
        if (ip6->nexthdr != IPPROTO_TCP) return 0;

        struct tcphdr *t = (void *)(ip6 + 1);
        if ((void *)(t + 1) > data_end) return 0;

        *tcp = t;
        *l3_proto = ETH_P_IPV6;
        *dst_ipv6 = ip6->daddr;
        return 1;
    }

    return 0;
}
