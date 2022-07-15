// +build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

struct bpf_lpm_ip_key_st {
	__u32 prefixLen;
	__u32 ip[4];
} __attribute__((packed));

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct bpf_lpm_ip_key_st); // source IPv4 address
	__type(value, __u32);                  // packet count
	__uint(map_flags, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_lpm_stats_map SEC(".maps");

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

SEC("xdp_pinning")
int xdp_prog_func(struct xdp_md *ctx) {
	struct bpf_lpm_ip_key_st key;
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}
	memset(&key, 0, sizeof(key));
	key.prefixLen    = 32;
	key.ip[0]        = ip;
	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_lpm_stats_map, &key);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_lpm_stats_map, &key, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
