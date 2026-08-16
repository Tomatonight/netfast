#include "ip.h"
#include "base.h"
#include "init.h"
#include "ip_frag.h"
#include "route_arp_ndp.h"
#include "skbuff.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "log.h"
#include "worker.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>


static _Atomic(uint32_t) ip_id;
static const uint8_t default_ttl = 64;

static void ip_id_init(void)
{
    atomic_store_explicit(&ip_id, (uint32_t)get_current_time_ms(),
                          memory_order_relaxed);
}

int ipv4_init(void)
{
    ip_id_init();
    if (route_init() < 0)
        return -1;
    return tcp_metrics_init();
}

static bool check_ipv4_hdr(skbuff* skb)
{
    ipv4_hdr* ip = skb->ipv4_hdr;
    if (IPV4_VHL_VERSION(ip->vhl) != 4)
        return false;

    uint32_t hdr_len = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
    if (hdr_len < sizeof(*ip) || hdr_len > skb_data0_len(skb))
        return false;
    if (!ip->ttl)
        return false;

    uint32_t total_len = ntohs(ip->tot_len);
    if (total_len < hdr_len || total_len > skb_data_len(skb))
        return false;

    if (!skb->flag.is_hw_rcv_checksum)
    {
        if (checksum(ip, hdr_len, 0) != 0)
            return false;
    }

    if (skb_data_len(skb) > total_len)
        skb_truncate(skb, total_len);
    return true;
}

static worker* get_frag_worker(const ipv4_hdr* hdr)
{
    if (g_worker_num <= 1)
        return get_current_worker();
    uint32_t hash = hdr->saddr ^ hdr->daddr ^ hdr->id ^ hdr->protocol;
    return &g_workers[hash % (uint32_t)g_worker_num];
}

/* Some virtual NICs expose several RX queues but deliver all XDP traffic to
 * queue 0.  Steer non-fragmented TCP packets to the same worker selected for
 * the eventual accepted socket before doing checksum, route and TCP work.
 * SYN/handshake packets may make one extra hop back to the listener owner;
 * established traffic then stays on its tuple worker. */
static worker* ipv4_tcp_software_rss_worker(skbuff* skb, ipv4_hdr* ip)
{
    if (g_worker_num <= 1 || IPV4_VHL_VERSION(ip->vhl) != 4 ||
        IPV4_VHL_IHL(ip->vhl) < 5 || ip->protocol != IPPROTO_TCP ||
        ipv4_is_frag(ip))
        return get_current_worker();

    uint32_t header_len = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
    struct {
        uint16_t sport;
        uint16_t dport;
    } ports;
    if (header_len > skb_data_len(skb) ||
        !skb_copy_bits(skb, header_len, &ports, sizeof(ports)))
        return get_current_worker();

    /* Match the NIC's inbound RSS tuple order and tcp_accept(): peer/wire
     * source first, local/wire destination second. */
    return select_worker_by_tuple(AF_INET,
        (const uint8_t*)&ip->saddr, (const uint8_t*)&ip->daddr,
        ports.sport, ports.dport);
}

int ipv4_recv(skbuff* skb)
{
    skb->family = AF_INET;

    if (skb_data0_len(skb) < sizeof(ipv4_hdr))
        return -1;

    ipv4_hdr* ip = (ipv4_hdr*)skb_start(skb);
    skb->ipv4_hdr = ip;
    if (!check_ipv4_hdr(skb))
        return -1;

    worker* frag_worker = get_frag_worker(ip);
    if (ipv4_is_frag(ip) && frag_worker != get_current_worker()) {
        transmit_skb_2_worker(frag_worker, skb, ipv4_recv);
        return 0;
    }

    worker* rss_worker = ipv4_tcp_software_rss_worker(skb, ip);
    if (rss_worker != get_current_worker()) {
        transmit_skb_2_worker(rss_worker, skb, ipv4_recv);
        return 0;
    }

    if (set_skb_route(skb, AF_INET, (const uint8_t*)&ip->daddr) < 0)
        return -1;
    route_info* route = skb->route;

	if (!route_is_local_host(route) && !route_is_broadcast(route)) {
        DEBUG_LOG("Forwarding IPv4 packet to " IP_STR, IP_ARG(ip->daddr));
		return ipv4_forward(skb);
	}

    if (ipv4_is_frag(ip)) {
        skb->flag.is_frag = 1;
        skbuff* reassembled_skb = ipv4_defrag(skb);
        if (!reassembled_skb)
            return 0;
        skb = reassembled_skb;
    }

    ip = skb->ipv4_hdr;
    uint32_t ipv4_hdr_len = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
    if (skb_consume(skb, ipv4_hdr_len, true) != ipv4_hdr_len) {
        if (skb->flag.is_defrag)
            PUT_REF(skb);
        return -1;
    }

    int ret = 0;

    switch (ip->protocol) {
    case IPPROTO_TCP:
        ret = tcp_recv(skb);
        break;
    case IPPROTO_UDP:
        ret = udp_recv(skb);
        break;
    case IPPROTO_ICMP:
        ret = icmp_recv(skb);
        break;
    default:
        DEBUG_LOG("Unsupported IPv4 protocol: %u", ip->protocol);
        ret = -1;
    }
    if (skb->flag.is_defrag)
        PUT_REF(skb);
    return ret;
}

int ipv4_output(skbuff* skb)
{
    route_info* route = skb->route;
    if (!skb->flag.is_forward) {
        uint32_t dip = skb->sock->dip;
        uint32_t sip = skb->sock->sip;

        if (set_skb_route(skb, AF_INET, (const uint8_t*)&dip) < 0)
            return -1;
        route = skb->route;

        if (skb_data_len(skb) > UINT16_MAX - sizeof(ipv4_hdr))
            return -1;

        ipv4_hdr* ip = (ipv4_hdr*)skb_data_push(skb, sizeof(ipv4_hdr));
        if (!ip)
            return -1;
        memset(ip, 0, sizeof(*ip));
        ip->vhl = IPV4_MAKE_VHL(4, 5);
        ip->tot_len = htons((uint16_t)skb_data_len(skb));
        ip->id = htons((uint16_t)atomic_fetch_add_explicit(
            &ip_id, 1u, memory_order_relaxed));
        ip->ttl = default_ttl;
        ip->protocol = (uint8_t)skb->protocol;
        ip->saddr = sip;
        ip->daddr = dip;
        ip->check = checksum(ip, sizeof(*ip), 0);
        skb->ipv4_hdr = ip;
    }

    uint32_t total_size = skb_data_len(skb);
    if (total_size <= route->if_info->mtu)
        return route->if_info->ops->send(route->if_info, skb);

    if (!ipv4_frag(skb)) {
        WARN_LOG("IPv4 fragmentation failed");
        return -1;
    }
    return skb_send_frags(skb);
}

int ipv4_forward(skbuff* skb){
    if (!g_cfg.ipv4_forward) {
        DEBUG_LOG("IPv4 forwarding disabled, dropping packet");
        return -1;
    }
    if (skb->ipv4_hdr->ttl <= 1) {
        DEBUG_LOG("Cannot forward packet with expired TTL");
        return -1;
    }
    skb->flag.is_forward=1;
    skb->ipv4_hdr->ttl--;
    skb->ipv4_hdr->check = 0;
    skb->ipv4_hdr->check=checksum((uint16_t*)skb->ipv4_hdr, ((uint32_t)IPV4_VHL_IHL(skb->ipv4_hdr->vhl) * 4u),0);
    return ipv4_output(skb);
}
