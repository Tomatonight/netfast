#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_redirect_config.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, netfast_xdp_config);
} netfast_cfg SEC(".maps");

#define IPV4_FRAG_MORE        0x2000U
#define IPV4_FRAG_OFFSET      0x1fffU

static __always_inline int xdp_parse_ethernet_protocol(
    void** data, void* data_end, __u16* eth_proto)
{
    struct ethhdr *eth = *data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 proto = eth->h_proto;
    *data = eth + 1;

    /* Basic single VLAN (802.1Q/AD) handling. */
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct {
            __be16 tci;
            __be16 encap_proto;
        } *vh = *data;
        if ((void *)(vh + 1) > data_end)
            return -1;
        proto = vh->encap_proto;
        *data = vh + 1;
    }

    *eth_proto = bpf_ntohs(proto);
    return 0;
}

static __always_inline int xdp_l4_destination_is_userspace(
    __u8 protocol, __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    __u16 destination;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (void*)cursor;
        if ((void*)(tcp + 1) > data_end)
            return 0;
        destination = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr* udp = (void*)cursor;
        if ((void*)(udp + 1) > data_end)
            return 0;
        destination = bpf_ntohs(udp->dest);
    } else {
        return 0;
    }
    return destination >= config->source_port_first &&
           destination <= config->source_port_last;
}

static __always_inline int xdp_redirect_current_queue(struct xdp_md* ctx)
{
    __u32 qid = ctx->rx_queue_index;
    if (!bpf_map_lookup_elem(&xsks_map, &qid))
        return XDP_PASS;
    return bpf_redirect_map(&xsks_map, qid, 0);
}

static __always_inline int xdp_ipv6_should_redirect(
    void* data, void* data_end, const netfast_xdp_config* config)
{
    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > data_end)
        return 0;

    __u8 nh = ip6->nexthdr;
    __u8 *cursor = (__u8 *)(ip6 + 1);

    /* Keep this parser deliberately small: old kernels reject the large
     * verifier state space produced by an unrolled extension-header loop.
     * The common one-extension and Fragment-header forms are covered; other
     * chains safely fall back to the kernel. */
    if (nh == IPPROTO_FRAGMENT)
        return config->redirect_fragments;
    if (nh == IPPROTO_UDP || nh == IPPROTO_TCP)
        return xdp_l4_destination_is_userspace(nh, cursor, data_end, config);

    if (nh != IPPROTO_HOPOPTS && nh != IPPROTO_ROUTING &&
        nh != IPPROTO_DSTOPTS)
        return 0;
    if (cursor + 2 > (__u8 *)data_end)
        return 0;

    __u8 next = cursor[0];
    __u32 hdr_len = ((__u32)cursor[1] + 1u) * 8u;
    if (hdr_len < 8u || cursor + hdr_len > (__u8 *)data_end)
        return 0;
    cursor += hdr_len;
    if (next == IPPROTO_FRAGMENT)
        return config->redirect_fragments;
    return xdp_l4_destination_is_userspace(next, cursor, data_end, config);
}

/* This program is used with AF_XDP multi-buffer receive enabled.  The
 * frags variant tells the kernel that the XDP program is safe to run on
 * frames carrying XDP_PKT_CONTD fragments. */
SEC("xdp.frags")
int xdp_redirect(struct xdp_md *ctx)
{
    __u32 config_key = NETFAST_XDP_CONFIG_KEY;
    const netfast_xdp_config* config =
        bpf_map_lookup_elem(&netfast_cfg, &config_key);
    if (!config)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 eth_proto = 0;
    if (xdp_parse_ethernet_protocol(&data, data_end, &eth_proto) != 0)
        return XDP_PASS;

    /* Only configured transport ports (and optionally fragments) are owned. */
    if (eth_proto == ETH_P_IPV6) {
        if (!xdp_ipv6_should_redirect(data, data_end, config))
            return XDP_PASS;
        return xdp_redirect_current_queue(ctx);
    }
    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* ip = data;
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ihl < 5 || (void*)ip + ((__u32)ip->ihl * 4u) > data_end)
        return XDP_PASS;

    /* IPv4 multicast is handled by the normal kernel path.  Do not
     * redirect it to AF_XDP; otherwise multicast destination MACs (01:00:5e)
     * reach userspace and are rejected later by ether_recv(). */
    if ((bpf_ntohl(ip->daddr) & 0xf0000000U) == 0xe0000000U)
        return XDP_PASS;

    __u16 frag_off = bpf_ntohs(ip->frag_off);
    if (frag_off & (IPV4_FRAG_MORE | IPV4_FRAG_OFFSET))
        return config->redirect_fragments
            ? xdp_redirect_current_queue(ctx) : XDP_PASS;

    __u8* l4 = (__u8*)ip + ((__u32)ip->ihl * 4u);
    if (xdp_l4_destination_is_userspace(ip->protocol, l4, data_end, config))
        return xdp_redirect_current_queue(ctx);


    /* other protocols: pass */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
