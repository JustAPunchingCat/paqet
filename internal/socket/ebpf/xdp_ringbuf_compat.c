// +build ignore

#include "xdp_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);
} packets SEC(".maps");

// Per-branch counters for field debugging: 0=passed(not ours), 1=consumed
// (ringbuf), 2=ringbuf-full passed to kernel, 3=dropped (allowlist),
// 4=parse fail (passed). Dump with: bpftool map dump name xdp_stats.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&xdp_stats, &idx);
    if (c) (*c)++;
}

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

    if (!parse_tcp(data, data_end, &tcp, &src_ipv4, &dst_ipv4, &src_ipv6, &dst_ipv6, &l3_proto)) {
        bump(4);
        return XDP_PASS;
    }

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
        if (!ip_match) { bump(0); return XDP_PASS; }

        // Port-agnostic: consume EVERY packet to/from the server IP and let
        // the Go dispatch layer (listeners map) decide. The old port gate
        // here dropped server traffic whenever the client's allowed_ports
        // set didn't contain the packet's ports — which is exactly what
        // killed inbound traffic after a server-port hop when the client's
        // registered port set went stale. The server IP is the identity;
        // ports change per hop and must never gate the client's capture.
        port_match = 1;
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
    if (!port_match) { bump(3); return XDP_DROP; }

    __u64 len = data_end - data;
    if (len > CAP_LEN) len = CAP_LEN;
    
    // Verifier workaround for "R2 unbounded size" on older kernels (5.10):
    // Use a CONSTANT reservation size.
    #define RES_SIZE (4 + CAP_LEN)
    
    void *buf = bpf_ringbuf_reserve(&packets, RES_SIZE, 0);
    // Ringbuf full: pass the packet to the kernel so the OS TCP stack sees it
    // and emits an RST — our client OnRST handler reacts with a forced port
    // hop. (XDP_DROP here would silently swallow the packet and the RST would
    // never fire; KCP retransmission alone recovers much slower.)
    if (!buf) { bump(2); return XDP_PASS; }

    // Write the actual length at the start
    __u32 *len_ptr = (__u32 *)buf;
    *len_ptr = (__u32)len;

    // Pointer to data area
    __u8 *dst = (__u8 *)(len_ptr + 1);
    __u8 *src = (__u8 *)data;

    // Zero out the entire buffer first using 32-bit blocks (since dst is offset by 4 bytes).
    // This avoids branch explosion in the verifier without unaligned memory access.
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < CAP_LEN / 4; i++) {
        // Volatile prevents Clang from "optimizing" this loop into a memset() call,
        // which the BPF backend doesn't support.
        *(volatile __u32 *)(dst + i * 4) = 0;
    }

    // Manual copy loop. 
    // We use early breaks because forcing the verifier to evaluate all 2048 
    // iterations without breaking (e.g. using if/else) causes a 1M instruction 
    // branch explosion on 5.10. Since we zeroed the entire buffer above,
    // early breaks are now 100% safe and leak no uninitialized memory!
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < CAP_LEN; i++) {
        if (i >= len) break;
        if ((void*)(src + i + 1) > data_end) break;
        dst[i] = src[i];
    }

    bpf_ringbuf_submit(buf, 0);
    bump(1);
    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
