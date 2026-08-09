#include "loopback.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "ip.h"
#include "ipv6.h"
#include "log.h"
#include "route_arp_ndp.h"
#include "skbuff.h"

int loopback_send(if_info* info, skbuff* skb)
{
    (void)info;
    skb->flag.is_forward = 0;
    return skb->family == AF_INET6 ? ipv6_recv(skb) : ipv4_recv(skb);
}

int loopback_create(if_info* info, struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);

    info->ifindex = ifinfo->ifi_index;
    info->flags = ifinfo->ifi_flags;
    info->mtu = 65536;

    return 0;
}

void loopback_update(if_info* info, struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);

    info->ifindex = ifinfo->ifi_index;
    info->flags = ifinfo->ifi_flags;
}

const if_ops loopback_ops = {
    .recv = loopback_send,
    .send = loopback_send,
    .update = loopback_update,
    .create = loopback_create,
};

int loopback_init(void)
{
    /* Check if a loopback interface already exists by querying the
     * interface list for one with loopback ops. */
    if (if_has_loopback())
        return 0;

    IF_WRLOCK();

    /* Create and publish the interface under the list lock.  Address helpers
     * acquire the same lock internally, so they must run after it is
     * released; pthread rwlocks are not recursive. */
    if_info* lo = if_create_virtual_loopback();
    if (!lo) {
        IF_UNLOCK();
        ERR_LOG("loopback_init: failed to create loopback interface");
        return -1;
    }
    IF_UNLOCK();

    /* 127.0.0.1/8 on loopback — host scope, primary */
    uint32_t lo_ip = inet_addr("127.0.0.1");
    (void)if_add_addr(lo, AF_INET, (const uint8_t*)&lo_ip, 8,
                      ADDR_SCOPE_HOST, true);

    /* ::1/128 on loopback — host scope, primary */
    static const uint8_t lo_ip6[16] = { 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1 };
    (void)if_add_addr(lo, AF_INET6, lo_ip6, 128,
                      ADDR_SCOPE_HOST, true);

    /* inject local routes */
    route_info r;
    memset(&r, 0, sizeof(r));
    r.ip_family = AF_INET;
    r.if_info = lo;
    r.ifindex = (uint32_t)lo->ifindex;
    snprintf(r.if_name, sizeof(r.if_name), "%s", lo->name);
    r.metric = 0;

    /* 127.0.0.0/8 dev loopback (local, whole /8 like Linux) */
    r.type = RTN_LOCAL;
    r.dst_mask = 8;
    uint32_t lo_net = inet_addr("127.0.0.0");
    memcpy(r.dst_ip, &lo_net, sizeof(lo_net));
    memset(r.gw_ip, 0, sizeof(r.gw_ip));
    (void)route_add_entry(&r);

    /* 127.0.0.1/32 local */
    r.type = RTN_LOCAL;
    r.dst_mask = 32;
    uint32_t lo_host = inet_addr("127.0.0.1");
    memcpy(r.dst_ip, &lo_host, sizeof(lo_host));
    memcpy(r.prefsrc, &lo_host, sizeof(lo_host));
    (void)route_add_entry(&r);

    /* ::1/128 local (IPv6 loopback) */
    memset(&r, 0, sizeof(r));
    r.ip_family = AF_INET6;
    r.type      = RTN_LOCAL;
    r.dst_mask  = 128;
    memcpy(r.dst_ip,  lo_ip6, 16);
    memcpy(r.prefsrc, lo_ip6, 16);
    r.if_info = lo;
    r.ifindex = (uint32_t)lo->ifindex;
    snprintf(r.if_name, sizeof(r.if_name), "%s", lo->name);
    (void)route_add_entry(&r);

    return 0;
}
