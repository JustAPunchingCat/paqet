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

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct tcphdr *tcp;
    if (!parse_tcp(data, data_end, &tcp))
        return XDP_PASS;

    __u16 dest = bpf_ntohs(tcp->dest);

    // --- SAFETY SWITCH ---
    // Never intercept SSH (22). If your VPS uses a custom SSH port, add it here.
    if (dest == 22) return XDP_PASS;

    if (!bpf_map_lookup_elem(&allowed_ports, &dest))
        return XDP_PASS;

    __u64 len = data_end - data;
    if (len > CAP_LEN) len = CAP_LEN;
    
    // REMOVED: len &= 0xFFF; 
    // Masking breaks the verifier's ability to track 'len' as being within packet bounds.
    // bpf_perf_event_output needs to know that 'data + len' is safe.
    // The 'if (len > CAP_LEN)' check above is sufficient for safety, 
    // and without the mask, the verifier remembers the relationship to data_end.

    bpf_perf_event_output(ctx, &packets,
                          BPF_F_CURRENT_CPU,
                          data, len);
    return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
