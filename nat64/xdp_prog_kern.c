/* SPDX-License-Identifier: GPL-2.0-only
   Copyright (c) 2019-2022 @bhaskar792 @rohitmp */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#include <stdio.h>

#ifndef AF_INET
#define AF_INET 1
#endif

#ifndef AF_INET6
#define AF_INET6 6
#endif


#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") static_redirect_8b = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u8),
	.value_size = sizeof(__u32),
	.max_entries = 256,
};
struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)
#define IPV4_SRC_ADDRESS bpf_htonl(0x0a000201) // 10.0.2.1 src address from v6 to v4 (at egress of nat)
SEC("v6_side")
int xdp_nat_v6_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	__u32 dst_v4;

	struct ethhdr eth_cpy;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	struct bpf_fib_lookup fib_params = {};
	int action = XDP_PASS;
	struct iphdr dst_hdr = {
		.version = 4,
                .ihl = 5,
                .frag_off = bpf_htons(1<<14),
        };

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
	{
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	
	if (h_proto == bpf_htons(ETH_P_IPV6))
	{
		bpf_printk("IPv6 packet");
		
		__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
		ip6h = data + nh_off;

		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}
		dst_v4 = ip6h->daddr.s6_addr32[3];
		dst_hdr.daddr = dst_v4;
        dst_hdr.saddr = IPV4_SRC_ADDRESS; // 10.0.2.1
        dst_hdr.protocol = ip6h->nexthdr;
        dst_hdr.ttl = ip6h->hop_limit;
        dst_hdr.tos = ip6h->priority << 4 | (ip6h->flow_lbl[0] >> 4);
        dst_hdr.tot_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(dst_hdr));


		if (bpf_xdp_adjust_head(ctx, (int)sizeof(*ip6h) - (int)sizeof(&dst_hdr)))
			return -1;

		eth = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (eth + 1 > data_end)
			return -1;

		__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
		eth->h_proto = bpf_htons(ETH_P_IP);
		iph = (void *)(eth + sizeof(*eth) +1);

		if (iph + 1 > data_end) {
			return -1;
		}
		*iph = dst_hdr;

		fib_params.family = AF_INET;
		fib_params.ipv4_dst = dst_v4;
		fib_params.ifindex = ctx->ingress_ifindex;

		rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if (rc == BPF_FIB_LKUP_RET_SUCCESS)
		{
			memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
			memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
			action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		}
	}
out:
		return xdp_stats_record_action(ctx, action);
}

SEC("v4_side")
int xdp_nat_v4_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	int iphdr_len;
	struct in6_addr v6_prefix;
	v6_prefix.s6_addr[1] = 0x64;
	v6_prefix.s6_addr[2] = 0xff;
	v6_prefix.s6_addr[3] = 0x9b;
	struct ethhdr eth_cpy;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	struct bpf_fib_lookup fib_params = {};
	struct in6_addr *fib_dst = (struct in6_addr *)fib_params.ipv6_dst;
	int action = XDP_PASS;
	struct ipv6hdr dst_hdr = {
		.version = 6,
		.saddr = v6_prefix,
		.daddr = v6_prefix
	};


	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
	{
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	
	if (h_proto == bpf_htons(ETH_P_IP))
	{
		bpf_printk("IPv4 packet");
		
		__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}
		if (iph->daddr != IPV4_SRC_ADDRESS)
		{
			goto out;
		}
		iphdr_len = iph->ihl * 4;
        if (iphdr_len != sizeof(struct iphdr) || (iph->frag_off & ~bpf_htons(1<<14))) 
		{
                bpf_printk("v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\n",
                    &iph->daddr, &iph->saddr);
                goto out;
        }
		 dst_hdr.saddr.s6_addr32[3] = iph->saddr;
        dst_hdr.daddr.s6_addr[15] = 0x02;
        dst_hdr.nexthdr = iph->protocol;
        dst_hdr.hop_limit = iph->ttl;
        dst_hdr.priority = (iph->tos & 0x70) >> 4;
        dst_hdr.flow_lbl[0] = iph->tos << 4;
        dst_hdr.payload_len = bpf_htons(bpf_ntohs(iph->tot_len) - iphdr_len);


		if (bpf_xdp_adjust_head(ctx, (int)sizeof(*iph) - (int)sizeof(&dst_hdr)))
			return -1;

		eth = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (eth + 1 > data_end)
			return -1;

		__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
		eth->h_proto = bpf_htons(ETH_P_IPV6);
		ip6h = (void *)(eth + sizeof(*eth) +1);

		if (ip6h + 1 > data_end) {
			return -1;
		}
		*ip6h = dst_hdr;

		fib_params.family = AF_INET6;
		*fib_dst = dst_hdr.daddr;
		fib_params.ifindex = ctx->ingress_ifindex;

		rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if (rc == BPF_FIB_LKUP_RET_SUCCESS)
		{
			memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
			memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
			action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		}
	}
out:
		return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
