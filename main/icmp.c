#include "icmp.h"

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "ip.h"
#include "ipv6.h"
#include "ipv6_ext.h"
#include "socket.h"
#include "skbuff.h"
#include "stack.h"
#include "worker.h"
#include "log.h"
#include "route_arp_ndp.h"
#include "ether.h"

static bool icmp_checksum_ok(const skbuff* skb, uint32_t len)
{
    return skb_checksum(skb, len, 0) == 0;
}

static int icmp_extract_inner4(const uint8_t* payload, uint32_t payload_len,
                               icmp_error_info* info)
{
    if (!payload || payload_len < sizeof(ipv4_hdr))
        return -1;

    const ipv4_hdr* ip = (const ipv4_hdr*)payload;
    if (IPV4_VHL_VERSION(ip->vhl) != 4)
        return -1;

    uint32_t ihl = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
    if (ihl < sizeof(ipv4_hdr) || ihl > payload_len)
        return -1;

    info->family = AF_INET;
    memcpy(info->src_ip, &ip->saddr, sizeof(ip->saddr));
    memcpy(info->dst_ip, &ip->daddr, sizeof(ip->daddr));
    info->protocol = ip->protocol;

    const uint8_t* l4 = payload + ihl;
    uint32_t l4_len = payload_len - ihl;

    if ((info->protocol != IPPROTO_UDP && info->protocol != IPPROTO_TCP) ||
        l4_len < 2u * sizeof(uint16_t))
        return -1;

    memcpy(&info->src_port, l4, sizeof(info->src_port));
    memcpy(&info->dst_port, l4 + sizeof(info->src_port),
           sizeof(info->dst_port));
    if (info->protocol == IPPROTO_TCP && l4_len >= 2u * sizeof(uint32_t)) {
        uint32_t seq;
        memcpy(&seq, l4 + 2u * sizeof(uint16_t), sizeof(seq));
        info->tcp_seq = ntohl(seq);
        info->has_tcp_seq = true;
    }
    return 0;
}

static int icmp_extract_inner6(const uint8_t* payload, uint32_t payload_len,
                               icmp_error_info* info)
{
    if (!payload || payload_len < sizeof(ipv6_hdr))
        return -1;

    const ipv6_hdr* ip6 = (const ipv6_hdr*)payload;
    if (IPV6_VERSION(ip6) != 6)
        return -1;

    info->family = AF_INET6;
    memcpy(info->src_ip, ip6->saddr, sizeof(info->src_ip));
    memcpy(info->dst_ip, ip6->daddr, sizeof(info->dst_ip));

    uint8_t next = ip6->next_hdr;
    uint32_t offset = sizeof(*ip6);
    for (uint32_t count = 0; count < 8; count++) {
        if (next == IPV6_NEXTHDR_HOPOPT ||
            next == IPV6_NEXTHDR_ROUTING ||
            next == IPV6_NEXTHDR_DSTOPTS) {
            if (payload_len - offset < 2u)
                return -1;
            uint32_t header_len = ((uint32_t)payload[offset + 1] + 1u) * 8u;
            if (header_len > payload_len - offset)
                return -1;
            next = payload[offset];
            offset += header_len;
            continue;
        }
        if (next == IPV6_NEXTHDR_FRAG) {
            if (payload_len - offset < sizeof(ipv6_frag_hdr))
                return -1;
            const ipv6_frag_hdr* frag = (const ipv6_frag_hdr*)(payload + offset);
            if (ntohs(frag->frag_off) & IPV6_FRAG_OFFSET_MASK)
                return -1;
            next = frag->next_hdr;
            offset += sizeof(*frag);
            continue;
        }
        if (next == IPV6_NEXTHDR_AH) {
            if (payload_len - offset < 2u)
                return -1;
            uint32_t header_len = ((uint32_t)payload[offset + 1] + 2u) * 4u;
            if (header_len > payload_len - offset)
                return -1;
            next = payload[offset];
            offset += header_len;
            continue;
        }
        break;
    }

    info->protocol = next;
    if ((next != IPPROTO_UDP && next != IPPROTO_TCP) ||
        payload_len - offset < 2u * sizeof(uint16_t))
        return -1;

    const uint8_t* l4 = payload + offset;
    memcpy(&info->src_port, l4, sizeof(info->src_port));
    memcpy(&info->dst_port, l4 + sizeof(info->src_port),
           sizeof(info->dst_port));
    if (next == IPPROTO_TCP && payload_len - offset >= 2u * sizeof(uint32_t)) {
        uint32_t seq;
        memcpy(&seq, l4 + 2u * sizeof(uint16_t), sizeof(seq));
        info->tcp_seq = ntohl(seq);
        info->has_tcp_seq = true;
    }
    return 0;
}

static int icmp_code_to_errno(uint8_t code)
{
    switch (code) {
    case ICMP_NET_UNREACH:
        return ENETUNREACH;
    case ICMP_HOST_UNREACH:
        return EHOSTUNREACH;
    case ICMP_PORT_UNREACH:
        return ECONNREFUSED;
    case ICMP_PROT_UNREACH:
        return EPROTONOSUPPORT;
    default:
        return EHOSTUNREACH;
    }
}

static int icmp6_error_to_errno(uint8_t type, uint8_t code)
{
    switch (type) {
    case ICMP6_DEST_UNREACH:
        switch (code) {
        case ICMP6_NO_ROUTE:
            return ENETUNREACH;
        case ICMP6_ADMIN_PROHIBITED:
        case ICMP6_POLICY_FAIL:
        case ICMP6_REJECT_ROUTE:
            return EACCES;
        case ICMP6_PORT_UNREACH:
            return ECONNREFUSED;
        case ICMP6_BEYOND_SCOPE:
        case ICMP6_ADDR_UNREACH:
        default:
            return EHOSTUNREACH;
        }
    case ICMP6_PACKET_TOO_BIG:
        return EMSGSIZE;
    case ICMP6_TIME_EXCEEDED:
        return EHOSTUNREACH;
    case ICMP6_PARAMETER_PROBLEM:
        return EPROTO;
    default:
        return 0;
    }
}

static void icmp_deliver_error(skbuff* skb, const icmp_error_info* info,
                               int err, int (*resume)(skbuff*))
{
    hash* tuple_hash;
    if (info->protocol == IPPROTO_UDP)
        tuple_hash = info->family == AF_INET6
            ? g_stack_maps->udp.tuple_hash6 : g_stack_maps->udp.tuple_hash4;
    else if (info->protocol == IPPROTO_TCP)
        tuple_hash = info->family == AF_INET6
            ? g_stack_maps->tcp.tuple_hash6 : g_stack_maps->tcp.tuple_hash4;
    else
        return;

    worker* aim;
    Socket* sock;
    if (info->family == AF_INET6) {
        sock = search_socket_by_tuple6(info->src_ip, info->src_port,
                                       info->dst_ip, info->dst_port,
                                       tuple_hash, &aim);
    } else {
        uint32_t src_ip, dst_ip;
        memcpy(&src_ip, info->src_ip, sizeof(src_ip));
        memcpy(&dst_ip, info->dst_ip, sizeof(dst_ip));
        sock = search_socket_by_tuple(src_ip, info->src_port,
                                      dst_ip, info->dst_port,
                                      tuple_hash, &aim);
    }
    if (!sock)
        return;

    if (aim != get_current_worker()) {
        transmit_skb_2_worker(aim, skb, resume);
        return;
    }

    if (sock->protocol_ops->icmp_process)
        sock->protocol_ops->icmp_process(sock, info, err);
}


int icmp_recv(skbuff* skb)
{ 
    if (skb_data0_len(skb) < sizeof(icmp_hdr))
        return -1;

    icmp_hdr* icmp = (icmp_hdr*)skb_start(skb);
    skb->icmp_hdr = icmp;

    uint32_t icmp_len = skb_data_len(skb);
    if (!icmp_checksum_ok(skb, icmp_len))
        return -1;

    if (icmp->type != ICMP_DEST_UNREACH)
        return 0;

    /* Need at least: icmp_hdr + quoted ipv4 hdr + 8 bytes */
    if (icmp_len < sizeof(icmp_hdr) + sizeof(ipv4_hdr) + 8) {
        DEBUG_LOG("icmp_recv: dest unreach too short len=%u", icmp_len);
        return -1;
    }

    uint8_t code = icmp->code;
    uint32_t payload_len = icmp_len - (uint32_t)sizeof(icmp_hdr);

    uint32_t quote_len = min(payload_len, (uint32_t)(MAX_IP_HDR_WITH_OPT_LEN + 8));
    uint8_t quote[MAX_IP_HDR_WITH_OPT_LEN + 8];
    if (!skb_copy_bits(skb, sizeof(icmp_hdr), quote, quote_len))
        return -1;

    icmp_error_info info = {0};
    if (icmp_extract_inner4(quote, quote_len, &info) < 0) {
        return 0;
    }

    int err = icmp_code_to_errno(code);

    icmp_deliver_error(skb, &info, err, icmp_recv);

    return 0;
}

int icmp6_recv(skbuff* skb)
{
    if (skb_data0_len(skb) < sizeof(icmp_hdr))
        return -1;

    icmp_hdr* icmp6 = (icmp_hdr*)skb_start(skb);
    skb->icmp_hdr = icmp6;
    uint32_t icmp6_len = skb_data_len(skb);

    bool checksum_ok = skb->flag.is_hw_rcv_checksum;
    if (!checksum_ok)
        checksum_ok = skb_checksum_protocol6(
            skb, icmp6_len, skb->ipv6_hdr->saddr, skb->ipv6_hdr->daddr,
            IPPROTO_ICMPV6) == 0;
    if (!checksum_ok)
        return -1;

    int err = icmp6_error_to_errno(icmp6->type, icmp6->code);
    if (!err)
        return 0;

    uint32_t payload_len = icmp6_len - (uint32_t)sizeof(*icmp6);
    if (payload_len < sizeof(ipv6_hdr) + 2u * sizeof(uint16_t)) {
        DEBUG_LOG("icmp6_recv: error quote too short len=%u", icmp6_len);
        return -1;
    }

    enum { ICMP6_QUOTE_MAX = 1280 };
    uint32_t quote_len = min(payload_len, (uint32_t)ICMP6_QUOTE_MAX);
    uint8_t quote[ICMP6_QUOTE_MAX];
    if (!skb_copy_bits(skb, sizeof(*icmp6), quote, quote_len))
        return -1;

    icmp_error_info info = {0};
    if (icmp_extract_inner6(quote, quote_len, &info) < 0)
        return 0;
    if (icmp6->type == ICMP6_PACKET_TOO_BIG)
        info.mtu = ntohl(icmp6->un.unused32);

    icmp_deliver_error(skb, &info, err, icmp6_recv);
    return 0;
}

/* Build and send ICMP Destination Unreachable.
 * RFC792 requires to include original IP header + 8 bytes of its payload.
 */
int icmp_send_dest_unreach(skbuff* orig_skb, uint8_t code)
{
	if (!orig_skb || !orig_skb->ipv4_hdr)
		return -1;
    ipv4_hdr* oip = orig_skb->ipv4_hdr;

    /* Only generate errors for unicast IPv4 packets (best-effort). */
    if (oip->saddr == 0 || oip->daddr == 0)
        return -1;

    /* How many bytes of original packet to quote: ip header (including options) + 8 bytes */
    uint32_t oihl = (uint32_t)IPV4_VHL_IHL(oip->vhl) * 4u;
    if (oihl < sizeof(ipv4_hdr) || oihl > MAX_IP_HDR_WITH_OPT_LEN) {
        return -1;
    }

	if (!orig_skb->l4_hdr) {
        return -1;
	}

	uint8_t quote[MAX_IP_HDR_WITH_OPT_LEN + 8];
	memcpy(quote, oip, oihl);
	memcpy(quote + oihl, orig_skb->l4_hdr, 8);
	uint32_t icmp_payload_len = oihl + 8u;
    uint32_t icmp_len = (uint32_t)sizeof(icmp_hdr) + icmp_payload_len;

	/* Look up the route to the original sender for L2 header sizing. */
	route_key rkey = { .ip_family = AF_INET };
	memcpy(rkey.dip, &oip->saddr, sizeof(oip->saddr));
	route_info* icmp_route = search_route_table(&rkey);
	uint32_t icmp_l2_len = icmp_route ? icmp_route->if_info->l2_len
	                                  : (uint32_t)sizeof(ether_hdr);
	uint32_t alloc_len = icmp_l2_len + MAX_IP_HDR_WITH_OPT_LEN + icmp_len;
	skbuff* skb = skb_alloc(alloc_len);
    if (!skb) {
        PUT_REF(icmp_route);
        return -1;
	}
	skb_reserve(skb, icmp_l2_len + MAX_IP_HDR_WITH_OPT_LEN);

	skb->route = icmp_route;  /* ipv4_output will use this route */
    skb->family = AF_INET;
    skb->protocol = IPPROTO_ICMP;

	Socket tmp = {0};
    skb->sock = &tmp;
    tmp.sip = oip->daddr;
    tmp.dip = oip->saddr;


    /* Build ICMP message */
    icmp_hdr* icmp = (icmp_hdr*)skb_data_put(skb, icmp_len);
	if (!icmp) {
		PUT_REF(skb);
		return -1;
	}
    memset(icmp, 0, sizeof(*icmp));
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = code;
    icmp->checksum = 0;

	memcpy((uint8_t*)icmp + sizeof(icmp_hdr), quote, icmp_payload_len);
	icmp->checksum = skb_checksum(skb, icmp_len, 0);

    int ret = ipv4_output(skb);

	skb->sock = NULL;
    PUT_REF(skb);

    return ret;
}
