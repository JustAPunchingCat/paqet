// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer
} packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, __u8);
} allowed_ports SEC(".maps");

SEC("classifier")
int cls_main(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    // Check destination port against allowed_ports map
    __u16 dest = bpf_ntohs(tcp->dest);
    __u8 *val = bpf_map_lookup_elem(&allowed_ports, &dest);
    if (!val) return TC_ACT_OK;

    // Capture packet to ringbuf
    // We reserve space for length (u32) + packet data
    __u32 len = skb->len;
    if (len > 2048) len = 2048; // Cap capture size

    void *buf = bpf_ringbuf_reserve(&packets, sizeof(__u32) + len, 0);
    if (!buf) return TC_ACT_OK;

    *(__u32 *)buf = len;
    // Copy packet data into ringbuf
    bpf_skb_load_bytes(skb, 0, buf + sizeof(__u32), len);

    bpf_ringbuf_submit(buf, 0);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
