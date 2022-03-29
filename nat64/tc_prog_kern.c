/* SPDX-License-Identifier: GPL-2.0-only
   Copyright (c) 2019-2022 @rohitmp */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <string.h>
#include <stdio.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

#include "newip.h"

#define ETH_P_NEWIP 0x88b6

struct lbf_skb_cb
{
    int val;
};

SEC("tc_router")
int tc_router_func(struct __sk_buff *ctx){
    void *data = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data_meta = (void *)(unsigned long)ctx->data_meta;
    struct lbf_skb_cb *cb = (struct lbf_skb_cb *)ctx->cb;
    struct meta_info *meta = data_meta;
    struct ethhdr *eth = data;
    int action = TC_ACT_UNSPEC;
    __u16 h_proto;

    if (data + sizeof(struct ethhdr) > data_end)
    {
        action = TC_ACT_SHOT;
        goto out;
    }
    h_proto = eth->h_proto;
    
    if(h_proto != bpf_htons(ETH_P_NEWIP)){
        goto out;
    }

    if(meta + 1 > data){
        goto out;
    }

    action =  bpf_redirect(meta->ifindex, 0);

out:
    cb->val = 65;
    // for(int i=0; i<5; i++){
    //     ctx->cb[i]=65+i;
    // }
    return action;
}

char _license[] SEC("license") = "GPL";