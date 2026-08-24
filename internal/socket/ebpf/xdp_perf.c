// +build ignore

#include "xdp_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_client_ips_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
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

    __u8 ip_match = 0;
    __u8 port_match = 0;

    if (is_client) {
        // Client: match any packet whose source OR dest IP is a registered server.
        // This drops ALL server traffic (including stale-port packets from a
        // lingering server session) so it never leaks to the kernel, which would
        // otherwise emit an RST and tear the tunnel down.
        if (l3_proto == ETH_P_IP) {
            if (map_has(&allowed_ips_v4, &src_ipv4)) ip_match = 1;
            if (map_has(&allowed_ips_v4, &dst_ipv4)) ip_match = 1;
        } else if (l3_proto == ETH_P_IPV6) {
            if (map_has(&allowed_ips_v6, &src_ipv6)) ip_match = 1;
            if (map_has(&allowed_ips_v6, &dst_ipv6)) ip_match = 1;
        }
        if (!ip_match) return XDP_PASS;

        // Ringbuf only the current registered port; silently drop stale ports.
        if (map_has(&allowed_ports, &dest)) port_match = 1;
        if (map_has(&allowed_ports, &source)) port_match = 1;
    } else {
        // Server: strictly match destination port + destination IP to avoid
        // blocking local outgoing traffic.
        if (!bpf_map_lookup_elem(&allowed_ports, &dest)) return XDP_PASS;
        if (l3_proto == ETH_P_IP) {
            if (!bpf_map_lookup_elem(&allowed_ips_v4, &dst_ipv4)) return XDP_PASS;
        } else if (l3_proto == ETH_P_IPV6) {
            if (!bpf_map_lookup_elem(&allowed_ips_v6, &dst_ipv6)) return XDP_PASS;
        }
        port_match = 1;
    }

    // Filter by client source IP (server only, when allowlist enabled).
    // config_map[1] is zero when allowed_client_ips is empty -> allow all.
    __u32 one = 1;
    __u8 *allow_on = bpf_map_lookup_elem(&config_map, &one);
    if (allow_on && *allow_on && !is_client) {
        if (l3_proto == ETH_P_IP) {
            struct ipv4_lpm_key lpm = {};
            lpm.prefixlen = 32;
            __builtin_memcpy(lpm.data, &src_ipv4, 4);
            if (!bpf_map_lookup_elem(&allowed_client_ips_v4, &lpm))
                return XDP_DROP;
        } else if (l3_proto == ETH_P_IPV6) {
            struct ipv6_lpm_key lpm = {};
            lpm.prefixlen = 128;
            __builtin_memcpy(lpm.data, &src_ipv6, 16);
            if (!bpf_map_lookup_elem(&allowed_client_ips_v6, &lpm))
                return XDP_DROP;
        }
    }

    // Silently drop server traffic that isn't on our current port (no leak, no RST).
    if (!port_match) return XDP_DROP;

    // Pass the EXACT packet size. Any cap or bitmask on len destroys the
    // verifier's ability to track 'data + len' within packet bounds and is
    // rejected with 'helper access to the packet is not allowed' (verified on
    // both 5.10 and 6.x). data + (data_end - data) = data_end always verifies.
    bpf_perf_event_output(ctx, &packets,
                          BPF_F_CURRENT_CPU,
                          data, data_end - data);
    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
