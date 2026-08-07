#include "ether.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "ipv6.h"
#include "log.h"
#include "route_arp_ndp.h"
#include "skbuff.h"
#include "xdp.h"

#define ETH_ALEN 6

typedef struct ether_vlan_hdr {
    uint16_t tci;
    uint16_t encap_proto;
} ether_vlan_hdr;

bool mac_same(const uint8_t* a, const uint8_t* b)
{
	return memcmp(a, b, ETH_ALEN) == 0;
}

bool mac_boardcast(const uint8_t* mac)
{
    static const uint8_t broadcast_mac[ETH_ALEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    return mac_same(mac, broadcast_mac);
}

int ether_up(if_info* info){
    if (xdp_if_start(info) < 0) {
        ERR_LOG("ether_up: failed to start XDP on %s", info->name);
        return -1;
    }
    return 0;
}
int ether_down(if_info* info){
    return xdp_if_stop(info);
}
static void update_ether_attr(if_info* info, struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);
    struct rtattr *rta;
    int rta_len = IFLA_PAYLOAD(nlh);

    info->ifindex = ifinfo->ifi_index;
    info->flags = ifinfo->ifi_flags;

    for (rta = IFLA_RTA(ifinfo); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        switch (rta->rta_type) {
        case IFLA_IFNAME:
            if (RTA_PAYLOAD(rta) > 0) {
                size_t len = (size_t)RTA_PAYLOAD(rta);
                if (len >= sizeof(info->name))
                    len = sizeof(info->name) - 1;
                memcpy(info->name, RTA_DATA(rta), len);
                info->name[len] = '\0';
            }
            break;
        case IFLA_MTU:
            if (RTA_PAYLOAD(rta) >= (int)sizeof(uint32_t))
                memcpy(&info->mtu, RTA_DATA(rta), sizeof(info->mtu));
            break;
        case IFLA_ADDRESS:
            if (RTA_PAYLOAD(rta) >= ETH_ALEN)
                memcpy(info->l2_addr, RTA_DATA(rta), ETH_ALEN);
            break;
        default:
            break;
        }
    }
}
int ether_recv(if_info* info, skbuff* skb)
{
    if (skb_data0_len(skb) < sizeof(ether_hdr))
        return -1;

    ether_hdr ether;
    memcpy(&ether, skb_start(skb), sizeof(ether));
    skb_consume(skb, sizeof(ether), true);

    if (!mac_same(ether.dmac, info->l2_addr) &&
        !mac_boardcast(ether.dmac))
        return -1;

    uint16_t ethertype = ntohs(ether.ether_type);

    /* Strip one or more VLAN tags (802.1Q / 802.1AD QinQ).
       Some NICs do hardware VLAN offload, but if the tag reaches us
       we need to skip it to find the real L3 protocol. */
    while (ethertype == ETHER_TYPE_8021Q || ethertype == ETHER_TYPE_8021AD) {
        if (skb_data0_len(skb) < sizeof(ether_vlan_hdr))
            return -1;

        ether_vlan_hdr vlan;
        memcpy(&vlan, skb_start(skb), sizeof(vlan));
        ethertype = ntohs(vlan.encap_proto);
        skb_consume(skb, sizeof(vlan), true);
    }

    switch (ethertype) {
        case ETHER_TYPE_IPV4:
            return ipv4_recv(skb);
		case ETHER_TYPE_IPV6:
			return ipv6_recv(skb);
        default:
            DEBUG_LOG("ether type 0x%04x not handled", ethertype);
            return -1;
    }
}
int ether_send(if_info* info, skbuff* skb)
{
    ndp_key nkey = { .ip_family = skb->family, .ifindex = (uint32_t)info->ifindex };

    get_route_gw(skb->route, nkey.neigh_ip);

    /* A zero gateway denotes a directly connected destination. */
    if (skb->family == AF_INET6) {
        static const uint8_t zero16[16];
        if (memcmp(nkey.neigh_ip, zero16, 16) == 0)
            memcpy(nkey.neigh_ip, skb->ipv6_hdr->daddr, 16);
    } else {
        static const uint8_t zero4[4];
        if (memcmp(nkey.neigh_ip, zero4, sizeof(zero4)) == 0)
            memcpy(nkey.neigh_ip, &skb->ipv4_hdr->daddr, sizeof(zero4));
    }

    arp_info* neighbor = search_ndp_table(&nkey);
    if (!neighbor) {
        DEBUG_LOG("No neighbor entry for next hop, family=%d ifindex=%u",
                  skb->family, info->ifindex);
        return -EHOSTUNREACH;
    }

    ether_hdr* eth = (ether_hdr*)skb_data_push(skb, sizeof(ether_hdr));
    if (!eth) {
        PUT_REF(neighbor);
        return -ENOMEM;
    }
    memcpy(eth->smac, info->l2_addr, sizeof(eth->smac));
    memcpy(eth->dmac, neighbor->mac, sizeof(eth->dmac));
    PUT_REF(neighbor);

    eth->ether_type = (skb->family == AF_INET6)
        ? htons(ETHER_TYPE_IPV6) : htons(ETHER_TYPE_IPV4);

    skb->ether_hdr = eth;

    return xdp_transmit_skb(info, skb);
}
void ether_update(if_info* new_info, struct nlmsghdr *nlh){
    update_ether_attr(new_info, nlh);
}
int ether_create(if_info* new_info, struct nlmsghdr *nlh){
    new_info->l2_addr = malloc(ETH_ALEN);
    if (!new_info->l2_addr)
        return -ENOMEM;
    new_info->l2_len = sizeof(ether_hdr);  /* 14 bytes */
    update_ether_attr(new_info, nlh);

    return 0;
}
void ether_destroy(if_info* info){
    free(info->l2_addr);
}
const if_ops ether_ops={
    .send=ether_send,
    .recv=ether_recv,
    .update = ether_update,
    .create=ether_create,
    .destroy=ether_destroy,
    .up=ether_up,
    .down=ether_down,
};

