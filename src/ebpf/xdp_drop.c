/* SPDX-License-Identifier: GPL-2.0 */
/*
 * LIDRA XDP drop program — BTF-compatible map definitions.
 *
 * Uses standard libbpf macros (SEC, __uint, __type, etc.) from
 * bpf_helpers.h.  The standalone Python loader parses the BTF section
 * to discover map types/sizes and creates them via bpf() syscall,
 * bypassing libbpf's strict BTF DATASEC validation.
 *
 * Compile:  bash build_xdp.sh
 * Load:     sudo python3 src/ebpf/xdp_loader.py load eth0
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ================================================================
 * BTF-compatible map definitions
 * With BTF, the .maps section stores zeros; actual map metadata is
 * in the .BTF ELF section as BTF type info.
 * ================================================================ */

/* Blocklist: IPv4 source -> 1 (present) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

/* Rate limit count: IPv4 source -> packets in current window */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit SEC(".maps");

/* Stats: index 0 = dropped */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 zero = 0;
    __u64 *stat;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    /* Blocklist check */
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked) {
        stat = bpf_map_lookup_elem(&stats, &zero);
        if (stat) __sync_fetch_and_add(stat, 1);
        return XDP_DROP;
    }

    /* Rate limiting */
    __u64 *count = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (count) {
        if (*count > 1000)
            return XDP_DROP;
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&rate_limit, &src_ip, &one, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
