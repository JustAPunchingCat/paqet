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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} allowed_client_ips_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct in6_addr);
    __type(value, __u8);
} allowed_client_ips_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u8);
} config_map SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 src_ipv4 = 0;
    __u32 dst_ipv4 = 0;
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
    __u16 l3_proto = 0;
    struct tcphdr *tcp;

    // Note: src_ipv6/dst_ipv6 are not initialized to 0, but only used if l3_proto == ETH_P_IPV6
    if (!parse_tcp(data, data_end, &tcp, &src_ipv4, &dst_ipv4, &src_ipv6, &dst_ipv6, &l3_proto))
        return XDP_PASS;

    // Re-verify bounds to satisfy verifier on older kernels
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u16 dest = bpf_ntohs(tcp->dest);
    __u16 source = bpf_ntohs(tcp->source);

    // --- SAFETY SWITCH ---
    // Never intercept SSH (22). If your VPS uses a custom SSH port, add it here.
    if (dest == 22 || source == 22) return XDP_PASS;

    __u32 zero = 0;
    __u8 *role = bpf_map_lookup_elem(&config_map, &zero);
    __u8 is_client = role ? *role : 0;

    if (is_client) {
        // Client: match if the registered port is the source OR dest. The client's
        // own injected packets loop back through the bridge (source == registered
        // port), and server replies arrive with dest == registered port.
        if (!bpf_map_lookup_elem(&allowed_ports, &dest) && !bpf_map_lookup_elem(&allowed_ports, &source)) {
            return XDP_PASS;
        }
    } else {
        // Server: strictly match destination port to avoid blocking local outgoing traffic.
        if (!bpf_map_lookup_elem(&allowed_ports, &dest)) {
            return XDP_PASS;
        }
    }



    // Filter by Destination IP
    if (l3_proto == ETH_P_IP) {
        if (!bpf_map_lookup_elem(&allowed_ips_v4, &dst_ipv4))
            return XDP_PASS;
    } else if (l3_proto == ETH_P_IPV6) {
        if (!bpf_map_lookup_elem(&allowed_ips_v6, &dst_ipv6))
            return XDP_PASS;
    }

    // Filter by client source IP (server only, when allowlist enabled).
    // config_map[1] is zero when allowed_client_ips is empty -> allow all.
    __u32 one = 1;
    __u8 *allow_on = bpf_map_lookup_elem(&config_map, &one);
    if (allow_on && *allow_on && !is_client) {
        if (l3_proto == ETH_P_IP) {
            if (!bpf_map_lookup_elem(&allowed_client_ips_v4, &src_ipv4))
                return XDP_DROP;
        } else if (l3_proto == ETH_P_IPV6) {
            if (!bpf_map_lookup_elem(&allowed_client_ips_v6, &src_ipv6))
                return XDP_DROP;
        }
    }

    __u64 len = data_end - data;
    if (len > CAP_LEN) len = CAP_LEN;
    len &= 0xFFF;

    // Optimal path for modern kernels (5.8+)
    // Uses built-in helper for efficient copy
    bpf_ringbuf_output(&packets, data, len, 0);

    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
