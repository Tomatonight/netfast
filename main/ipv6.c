#include "ipv6.h"
#include "ip.h"
#include "skbuff.h"
#include "base.h"
#include "init.h"
#include "route_arp_ndp.h"
#include "ether.h"
#include "udp.h"
#include "tcp.h"
#include "log.h"
#include "worker.h"
#include "ipv6_ext.h"
#include "icmp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

int ipv6_init(void)
{
    return 0;
}

/* ── 跳过扩展头，找到 L4 协议号 ────────────────────────── */
/* Parse extension headers after the fixed IPv6 header has been consumed. */
static int ipv6_skip_exthdrs(skbuff* skb, uint8_t initial_nh,
                             uint8_t* out_proto)
{
    uint8_t nh = initial_nh;
    uint32_t offset = 0;

    *out_proto = nh;

    /* 最多跳过 8 个扩展头，防止无限循环 */
    for (int i = 0; i < 8; i++) {
        switch (nh) {
        case IPV6_NEXTHDR_HOPOPT:
        case IPV6_NEXTHDR_DSTOPTS:
        case IPV6_NEXTHDR_ROUTING:
            /* 长度编码为 (hdr_ext_len + 1) * 8 */
            {
                uint8_t ext[2];
                if (!skb_copy_bits(skb, offset, ext, sizeof(ext)))
                    return -1;
                nh = ext[0];
                uint32_t hdr_len = (uint32_t)(ext[1] + 1u) * 8u;
                if (hdr_len < 8u || hdr_len > skb_data_len(skb) - offset)
                    return -1;
                offset += hdr_len;
            }
            break;
        case IPV6_NEXTHDR_FRAG:
            {
                ipv6_frag_hdr fh;
                if (!skb_copy_bits(skb, offset, &fh, sizeof(fh)))
                    return -1;
                nh = fh.next_hdr;
                offset += sizeof(fh);
            }
            break;
        case IPV6_NEXTHDR_NONEXT:
            *out_proto = nh;
            return -1;  /* 无上层协议 */
        default:
            /* TCP / UDP / ICMPv6 或其他 */
            goto done;
        }
        *out_proto = nh;
        if (offset > skb_data_len(skb))
                return -1;
    }

done:
    *out_proto = nh;
    if (offset > 0) {
        /* Extension headers may straddle UMEM frames.  Consume across the
         * complete skb rather than requiring the whole chain in data[0]. */
        if (skb_consume(skb, offset, false) != offset)
            return -1;
    }
    return 0;
}

static inline worker* get_ipv6_frag_worker(const ipv6_hdr* ip6)
{
    if (g_worker_num <= 1)
        return get_current_worker();

    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < 16; ++i) {
        h = (h ^ ip6->saddr[i]) * 16777619u;
        h = (h ^ ip6->daddr[i]) * 16777619u;
    }
    return &g_workers[h % (uint32_t)g_worker_num];
}

/* ── IPv6 首部校验 ────────────────────────────────────── */
static bool check_ipv6_hdr(skbuff* skb)
{
    ipv6_hdr* ip6 = skb->ipv6_hdr;

    if (IPV6_VERSION(ip6) != 6)
        return false;
    if (ip6->hop_limit == 0)
        return false;

    uint32_t total = IPV6_HDR_LEN + ntohs(ip6->payload_len);
    if (skb_data_len(skb) < total)
        return false;
    if (skb_data_len(skb) > total)
        skb_truncate(skb, total);

    return true;
}

/* ── IPv6 接收 ────────────────────────────────────────── */
int ipv6_recv(skbuff* skb)
{
    int ret = 0;
    skb->family = AF_INET6;

    if (skb_data0_len(skb) < IPV6_HDR_LEN)
        return -1;

    ipv6_hdr* ip6 = (ipv6_hdr*)skb_start(skb);
    skb->ipv6_hdr = ip6;

    if (!check_ipv6_hdr(skb))
        return -1;

    bool fragmented = ipv6_has_frag(skb);
    if (fragmented &&
        get_ipv6_frag_worker(ip6) != get_current_worker()) {
        transmit_skb_2_worker(get_ipv6_frag_worker(ip6), skb, ipv6_recv);
        return 0;
    }

    if (set_skb_route(skb, AF_INET6, ip6->daddr) < 0)
        return -1;

    route_info* route = skb->route;
    if (!route_is_local_host(route)) {
        DEBUG_LOG("Forwarding IPv6 packet");
        return ipv6_forward(skb);
    }

    /* 分片重组（必须在 consume IPv6 头之前，已重组包跳过） */
    if (!skb->flag.is_defrag && fragmented) {
        skbuff* reassembled = ipv6_defrag(skb);
        if (!reassembled)
            return 0;  /* 等待更多分片 */
        skb = reassembled;
        skb->ipv6_hdr = (ipv6_hdr*)skb_start(skb);
    }

    uint8_t initial_next_hdr = skb->ipv6_hdr->next_hdr;

    if (skb_consume(skb, IPV6_HDR_LEN, false) != IPV6_HDR_LEN)
        goto fail_reassembled;

    /* 处理扩展头，找到 L4 协议 */
    uint8_t protocol;
    if (ipv6_skip_exthdrs(skb, initial_next_hdr, &protocol) < 0) {
        if (protocol == IPV6_NEXTHDR_NONEXT)
            goto done;  /* No Next Header，静默丢弃 */
        DEBUG_LOG("IPv6 extension header parse failed, next_hdr=%u", protocol);
        ret = -1;
        goto done;
    }
    skb->protocol = protocol;

    switch (protocol) {
    case IPPROTO_TCP:
        ret = tcp_recv(skb);
        break;
    case IPPROTO_UDP:
        ret = udp_recv(skb);
        break;
    case IPPROTO_ICMPV6:
        ret = icmp6_recv(skb);
        break;
    default:
        DEBUG_LOG("Unsupported IPv6 next header: %u", protocol);
        ret = -1;
    }

done:
    if (skb->flag.is_defrag)
        PUT_REF(skb);
    return ret;

fail_reassembled:
    if (skb->flag.is_defrag)
        PUT_REF(skb);
    return -1;
}

/* ── IPv6 输出 ────────────────────────────────────────── */
int ipv6_output(skbuff* skb)
{
    route_info* route = skb->route;
    if (!skb->flag.is_forward) {
        const uint8_t* dip = skb->sock->dip6;
        const uint8_t* sip = skb->sock->sip6;

        if (set_skb_route(skb, AF_INET6, dip) < 0)
            return -1;
        route = skb->route;

        if (skb_data_len(skb) > UINT16_MAX)
            return -1;
        ipv6_hdr* ip6 = (ipv6_hdr*)skb_data_push(skb, IPV6_HDR_LEN);
        if (!ip6)
            return -1;

        memset(ip6, 0, IPV6_HDR_LEN);
        ip6->vtf = ipv6_make_vtf(0, 0);
        ip6->payload_len = htons((uint16_t)(skb_data_len(skb) - IPV6_HDR_LEN));
        ip6->next_hdr = (uint8_t)skb->protocol;
        ip6->hop_limit = 64;
        memcpy(ip6->saddr, sip, 16);
        memcpy(ip6->daddr, dip, 16);

        skb->ipv6_hdr = ip6;
        skb->family = AF_INET6;
    }

    uint32_t total_size = skb_data_len(skb);
    if (total_size > route->if_info->mtu) {
        if (!ipv6_frag(skb)) {
            WARN_LOG("IPv6 fragmentation failed size=%u mtu=%u",
                     total_size, route->if_info->mtu);
            return -1;
        }
        return skb_send_frags(skb);
    }

    return route->if_info->ops->send(route->if_info, skb);
}

/* ── IPv6 转发 ────────────────────────────────────────── */
int ipv6_forward(skbuff* skb)
{
    if (!g_cfg.ipv6_forward) {
        DEBUG_LOG("IPv6 forwarding disabled, dropping packet");
        return -1;
    }
    if (skb->ipv6_hdr->hop_limit <= 1) {
        DEBUG_LOG("Cannot forward IPv6 packet with expired hop limit");
        return -1;
    }

    skb->flag.is_forward = 1;
    skb->ipv6_hdr->hop_limit--;

    return ipv6_output(skb);
}
