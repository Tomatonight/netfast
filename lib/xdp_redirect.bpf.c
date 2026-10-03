#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
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

#define IPV4_FRAG_MORE    0x2000U
#define IPV4_FRAG_OFFSET  0x1fffU
#define XDP_MAX_V6_EXT    4

static __always_inline int xdp_port_owned(
    __u16 port, const netfast_xdp_config* config)
{
    return port >= config->source_port_first &&
           port <= config->source_port_last;
}

/* XDP sees ingress packets.  For a normal TCP/UDP ingress packet, only the
 * destination port belongs to the local NetFast socket. */
static __always_inline int xdp_ingress_port_owned(
    const __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    const __be16* ports = (const __be16 *)cursor;
    if ((const void *)(ports + 2) > data_end)
        return 0;

    return xdp_port_owned(bpf_ntohs(ports[1]), config);
}

/* An ICMP error received by the host quotes the packet that caused the
 * error.  For a packet sent by a local NetFast socket, that quoted packet's
 * source port is the local port, so ICMP needs a separate source-port test. */
static __always_inline int xdp_quoted_source_port_owned(
    const __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    const __be16* ports = (const __be16 *)cursor;
    if ((const void *)(ports + 2) > data_end)
        return 0;

    return xdp_port_owned(bpf_ntohs(ports[0]), config);
}

static __always_inline int xdp_ipv4_icmp_error(
    const __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    const struct icmphdr* icmp = (const void *)cursor;
    if ((const void *)(icmp + 1) > data_end)
        return 0;

    if (icmp->type != ICMP_DEST_UNREACH &&
        icmp->type != ICMP_TIME_EXCEEDED &&
        icmp->type != ICMP_PARAMETERPROB)
        return 0;

    const struct iphdr* quoted = (const void *)(icmp + 1);
    if ((const void *)(quoted + 1) > data_end ||
        quoted->version != 4 || quoted->ihl < 5)
        return 0;

    __u32 header_len = (__u32)quoted->ihl * 4u;
    if ((const __u8 *)quoted + header_len > (const __u8 *)data_end)
        return 0;
    if (quoted->protocol != IPPROTO_TCP &&
        quoted->protocol != IPPROTO_UDP)
        return 0;

    return xdp_quoted_source_port_owned((const __u8 *)quoted + header_len,
                                        data_end, config);
}

static __always_inline int xdp_ipv6_quoted_ports(
    const __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    const struct ipv6hdr* quoted = (const void *)cursor;
    if ((const void *)(quoted + 1) > data_end)
        return 0;

    __u8 next_header = quoted->nexthdr;
    const __u8* next = (const __u8 *)(quoted + 1);

#pragma unroll
    for (int i = 0; i < XDP_MAX_V6_EXT; i++) {
        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP)
            return xdp_quoted_source_port_owned(next, data_end, config);

        if (next_header == IPPROTO_HOPOPTS ||
            next_header == IPPROTO_ROUTING ||
            next_header == IPPROTO_DSTOPTS) {
            if (next + 2 > (const __u8 *)data_end)
                return 0;
            __u32 header_len = ((__u32)next[1] + 1u) * 8u;
            if (header_len < 8u ||
                next + header_len > (const __u8 *)data_end)
                return 0;
            next_header = next[0];
            next += header_len;
            continue;
        }

        if (next_header == IPPROTO_FRAGMENT) {
            if (next + 8 > (const __u8 *)data_end)
                return 0;
            /* A non-first fragment does not contain TCP/UDP ports. */
            __be16 fragment_offset = *(__be16 *)(next + 2);
            if (bpf_ntohs(fragment_offset) & 0xfff8u)
                return 0;
            next_header = next[0];
            next += 8;
            continue;
        }

        if (next_header == IPPROTO_AH) {
            if (next + 2 > (const __u8 *)data_end)
                return 0;
            __u32 header_len = ((__u32)next[1] + 2u) * 4u;
            if (header_len < 8u ||
                next + header_len > (const __u8 *)data_end)
                return 0;
            next_header = next[0];
            next += header_len;
            continue;
        }

        return 0;
    }
    return 0;
}

static __always_inline int xdp_ipv6_icmp_error(
    const __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    if (cursor + 1 > (const __u8 *)data_end)
        return 0;

    /* ICMPv6 error types are 1 through 4. */
    if (cursor[0] < 1 || cursor[0] > 4)
        return 0;
    if (cursor + sizeof(struct icmphdr) > (const __u8 *)data_end)
        return 0;

    return xdp_ipv6_quoted_ports(cursor + sizeof(struct icmphdr),
                                 data_end, config);
}

static __always_inline int xdp_l4_owned(
    __u8 protocol, const __u8* cursor, void* data_end,
    const netfast_xdp_config* config)
{
    if (protocol == IPPROTO_ICMP)
        return xdp_ipv4_icmp_error(cursor, data_end, config);
    if (protocol == IPPROTO_ICMPV6)
        return xdp_ipv6_icmp_error(cursor, data_end, config);
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;
    return xdp_ingress_port_owned(cursor, data_end, config);
}

static __always_inline int xdp_parse_ethernet(
    void** data, void* data_end, __u16* protocol)
{
    struct ethhdr* eth = *data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __be16 proto = eth->h_proto;
    *data = eth + 1;

    /* Keep this bounded for old BPF verifiers while accepting QinQ frames. */
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) &&
            proto != bpf_htons(ETH_P_8021AD))
            break;
        struct {
            __be16 tci;
            __be16 encap_proto;
        } *vlan = *data;
        if ((void *)(vlan + 1) > data_end)
            return -1;
        proto = vlan->encap_proto;
        *data = vlan + 1;
    }

    *protocol = bpf_ntohs(proto);
    return 0;
}

static __always_inline int xdp_redirect_current_queue(struct xdp_md* ctx)
{
    __u32 queue = ctx->rx_queue_index;
    if (!bpf_map_lookup_elem(&xsks_map, &queue))
        return XDP_PASS;
    return bpf_redirect_map(&xsks_map, queue, 0);
}

static __always_inline int xdp_ipv6_owned(
    void* data, void* data_end, const netfast_xdp_config* config)
{
    struct ipv6hdr* ip6 = data;
    if ((void *)(ip6 + 1) > data_end)
        return 0;

    __u8 next_header = ip6->nexthdr;
    __u8* cursor = (__u8 *)(ip6 + 1);

    if (next_header == IPPROTO_FRAGMENT)
        return config->redirect_fragments;
    if (xdp_l4_owned(next_header, cursor, data_end, config))
        return 1;

    /* Handle one outer extension chain.  Complex or encrypted chains remain
     * on the kernel path instead of being guessed at in XDP. */
    if (next_header != IPPROTO_HOPOPTS &&
        next_header != IPPROTO_ROUTING &&
        next_header != IPPROTO_DSTOPTS)
        return 0;
    if (cursor + 2 > (__u8 *)data_end)
        return 0;

    __u8 next = cursor[0];
    __u32 header_len = ((__u32)cursor[1] + 1u) * 8u;
    if (header_len < 8u || cursor + header_len > (__u8 *)data_end)
        return 0;
    cursor += header_len;
    if (next == IPPROTO_FRAGMENT)
        return config->redirect_fragments;
    return xdp_l4_owned(next, cursor, data_end, config);
}

static __always_inline int xdp_ipv4_owned(
    void* data, void* data_end, const netfast_xdp_config* config)
{
    struct iphdr* ip = data;
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
        return 0;

    __u32 header_len = (__u32)ip->ihl * 4u;
    if ((void *)ip + header_len > data_end)
        return 0;

    /* Multicast remains with the kernel stack. */
    if ((bpf_ntohl(ip->daddr) & 0xf0000000U) == 0xe0000000U)
        return 0;

    __u16 fragment = bpf_ntohs(ip->frag_off);
    if (fragment & (IPV4_FRAG_MORE | IPV4_FRAG_OFFSET))
        return config->redirect_fragments;

    return xdp_l4_owned(ip->protocol, (__u8 *)ip + header_len,
                        data_end, config);
}

SEC("xdp.frags")
int xdp_redirect(struct xdp_md* ctx)
{
    __u32 config_key = NETFAST_XDP_CONFIG_KEY;
    const netfast_xdp_config* config =
        bpf_map_lookup_elem(&netfast_cfg, &config_key);
    if (!config)
        return XDP_PASS;

    void* data = (void *)(long)ctx->data;
    void* data_end = (void *)(long)ctx->data_end;
    __u16 protocol;
    if (xdp_parse_ethernet(&data, data_end, &protocol) < 0)
        return XDP_PASS;

    int owned;
    if (protocol == ETH_P_IP)
        owned = xdp_ipv4_owned(data, data_end, config);
    else if (protocol == ETH_P_IPV6)
        owned = xdp_ipv6_owned(data, data_end, config);
    else
        owned = 0;

    return owned ? xdp_redirect_current_queue(ctx) : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
