#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKLIST_ENTRIES 100000

struct ip_key {
    __u32 ip;
    __u8  prefix;
};

struct {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __type(key, struct ip_key);
    __type(value, __u32);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __uint(map_extra, 5);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10000);
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} stats SEC(".maps");

#define RATE_LIMIT_PPS 1000
#define XDP_ACTION_PASS XDP_PASS
#define XDP_ACTION_DROP XDP_DROP

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 *stat;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 h_proto = eth->h_proto;

    __u32 ip_src = 0;
    if (h_proto == __bpf_constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        ip_src = ip->saddr;
    } else if (h_proto == __bpf_constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        __builtin_memcpy(&ip_src, &ip6->saddr, 4);
    } else {
        return XDP_PASS;
    }

    struct ip_key key = {.ip = ip_src, .prefix = 32};
    if (bpf_map_lookup_elem(&blocklist, &key)) {
        stat = bpf_map_lookup_elem(&stats, &(__u32){0});
        if (stat) __sync_fetch_and_add(stat, 1);
        return XDP_ACTION_DROP;
    }

    __u64 *count = bpf_map_lookup_elem(&rate_limit, &ip_src);
    if (count) {
        if (*count > RATE_LIMIT_PPS)
            return XDP_ACTION_DROP;
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&rate_limit, &ip_src, &one, BPF_NOEXIST);
    }

    return XDP_ACTION_PASS;
}

char _license[] SEC("license") = "GPL";
