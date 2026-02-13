// +build ignore

#include "xdp_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);
} packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, __u8);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, struct in6_addr);
    __type(value, __u8);
} allowed_ips_v6 SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 dst_ipv4 = 0;
    struct in6_addr dst_ipv6;
    __u16 l3_proto = 0;
    struct tcphdr *tcp;

    if (!parse_tcp(data, data_end, &tcp, &dst_ipv4, &dst_ipv6, &l3_proto))
        return XDP_PASS;

    // Re-verify bounds to satisfy verifier on older kernels
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u16 dest = bpf_ntohs(tcp->dest);

    // --- SAFETY SWITCH ---
    // Never intercept SSH (22). If your VPS uses a custom SSH port, add it here.
    if (dest == 22) return XDP_PASS;

    if (!bpf_map_lookup_elem(&allowed_ports, &dest))
        return XDP_PASS;

    // Filter by Destination IP
    if (l3_proto == ETH_P_IP) {
        if (!bpf_map_lookup_elem(&allowed_ips_v4, &dst_ipv4))
            return XDP_PASS;
    } else if (l3_proto == ETH_P_IPV6) {
        if (!bpf_map_lookup_elem(&allowed_ips_v6, &dst_ipv6))
            return XDP_PASS;
    }

    __u64 len = data_end - data;
    if (len > CAP_LEN) len = CAP_LEN;
    
    // Verifier workaround for "R2 unbounded size" on older kernels (5.10):
    // Use a CONSTANT reservation size.
    #define RES_SIZE (4 + CAP_LEN)
    
    void *buf = bpf_ringbuf_reserve(&packets, RES_SIZE, 0);
    if (!buf) return XDP_DROP;

    // Write the actual length at the start
    __u32 *len_ptr = (__u32 *)buf;
    *len_ptr = (__u32)len;

    // Pointer to data area
    __u8 *dst = (__u8 *)(len_ptr + 1);
    __u8 *src = (__u8 *)data;

    // Manual copy loop
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < CAP_LEN; i++) {
        if (i >= len) break;
        if ((void*)(src + i + 1) > data_end) break;
        dst[i] = src[i];
    }

    bpf_ringbuf_submit(buf, 0);
    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
