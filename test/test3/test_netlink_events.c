#include <arpa/inet.h>
#include <errno.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "base.h"
#include "if.h"
#include "init.h"
#include "netlink.h"
#include "route_arp_ndp.h"

#include "test_common.h"

#include <linux/if_arp.h>

static int add_attr(struct nlmsghdr *nlh, size_t capacity, uint16_t type,
                    const void *data, size_t len)
{
    size_t offset = NLMSG_ALIGN(nlh->nlmsg_len);
    size_t attr_len = RTA_LENGTH(len);
    size_t total = RTA_ALIGN(attr_len);
    if (offset + total > capacity)
        return -1;
    struct rtattr *attr = (struct rtattr *)((uint8_t *)nlh + offset);
    attr->rta_type = type;
    attr->rta_len = (uint16_t)attr_len;
    memcpy(RTA_DATA(attr), data, len);
    if (total > attr_len)
        memset((uint8_t *)attr + attr_len, 0, total - attr_len);
    nlh->nlmsg_len = (uint32_t)(offset + total);
    return 0;
}

static void init_link_message(struct nlmsghdr *nlh, uint16_t type,
                              int ifindex, uint32_t flags)
{
    memset(nlh, 0, 512);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_type = type;
    struct ifinfomsg *ifi = NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = ARPHRD_LOOPBACK;
    ifi->ifi_index = ifindex;
    ifi->ifi_flags = flags;
}

static void init_addr_message(struct nlmsghdr *nlh, uint16_t type,
                              int ifindex, uint8_t prefix_len)
{
    memset(nlh, 0, 512);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = type;
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix_len;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_index = (uint32_t)ifindex;
}

static void init_route_message(struct nlmsghdr *nlh, uint16_t type)
{
    memset(nlh, 0, 512);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = type;
    struct rtmsg *rtm = NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = 24;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_type = RTN_UNICAST;
}

static void init_neighbor_message(struct nlmsghdr *nlh, uint16_t type,
                                  int ifindex)
{
    memset(nlh, 0, 512);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    nlh->nlmsg_type = type;
    struct ndmsg *ndm = NLMSG_DATA(nlh);
    ndm->ndm_family = AF_INET;
    ndm->ndm_ifindex = ifindex;
    ndm->ndm_state = NUD_REACHABLE;
}

static int test_link_and_address_events(int ifindex)
{
    uint8_t buffer[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    init_link_message(nlh, RTM_NEWLINK, ifindex, IFF_UP | IFF_RUNNING |
                                           IFF_LOOPBACK);
    const char ifname[] = "lo";
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), IFLA_IFNAME, ifname,
                         sizeof(ifname)) == 0);
    TEST_ASSERT(parse_link_event(nlh) == 0);

    if_info *info = search_if_by_index((uint32_t)ifindex);
    TEST_ASSERT(info != NULL);
    PUT_REF(info);

    init_addr_message(nlh, RTM_NEWADDR, ifindex, 24);
    uint32_t address = inet_addr("198.51.100.2");
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), IFA_LOCAL, &address,
                         sizeof(address)) == 0);
    TEST_ASSERT(parse_addr_event(nlh) == 0);
    info = search_if_by_index((uint32_t)ifindex);
    TEST_ASSERT(info && if_has_addr(info, AF_INET, (uint8_t *)&address));
    PUT_REF(info);

    init_addr_message(nlh, RTM_DELADDR, ifindex, 24);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), IFA_LOCAL, &address,
                         sizeof(address)) == 0);
    TEST_ASSERT(parse_addr_event(nlh) == 0);
    info = search_if_by_index((uint32_t)ifindex);
    TEST_ASSERT(info && !if_has_addr(info, AF_INET, (uint8_t *)&address));
    PUT_REF(info);

    init_link_message(nlh, RTM_NEWLINK, ifindex, IFF_LOOPBACK);
    TEST_ASSERT(parse_link_event(nlh) == 0);
    init_link_message(nlh, RTM_NEWLINK, ifindex, IFF_UP | IFF_RUNNING |
                                           IFF_LOOPBACK);
    TEST_ASSERT(parse_link_event(nlh) == 0);
    return 0;
}

static int test_route_events(int ifindex)
{
    uint8_t buffer[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    uint32_t destination = inet_addr("198.51.100.0");
    uint32_t gateway = inet_addr("198.51.100.1");
    uint32_t metric = 11;
    uint32_t mtu = 1400;
    uint8_t metrics[32] = {0};
    struct rtattr *metric_attr = (struct rtattr *)metrics;
    metric_attr->rta_type = RTAX_MTU;
    metric_attr->rta_len = RTA_LENGTH(sizeof(mtu));
    memcpy(RTA_DATA(metric_attr), &mtu, sizeof(mtu));

    init_route_message(nlh, RTM_NEWROUTE);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_DST, &destination,
                         sizeof(destination)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_GATEWAY, &gateway,
                         sizeof(gateway)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_OIF, &ifindex,
                         sizeof(ifindex)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_PRIORITY, &metric,
                         sizeof(metric)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_METRICS, metrics,
                         RTA_ALIGN(metric_attr->rta_len)) == 0);
    TEST_ASSERT(parse_route_event(nlh) == 0);

    route_key key = {.ip_family = AF_INET};
    uint32_t target = inet_addr("198.51.100.77");
    memcpy(key.dip, &target, sizeof(target));
    route_info *route = search_route_table(&key);
    TEST_ASSERT(route && route->ifindex == (uint32_t)ifindex &&
                route->dst_mask == 24 && route->metric == metric &&
                get_route_mtu(route) == mtu);
    TEST_ASSERT(route_include_nexthop(route, (uint8_t *)&target));
    PUT_REF(route);

    init_route_message(nlh, RTM_DELROUTE);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_DST, &destination,
                         sizeof(destination)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_GATEWAY, &gateway,
                         sizeof(gateway)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_OIF, &ifindex,
                         sizeof(ifindex)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), RTA_PRIORITY, &metric,
                         sizeof(metric)) == 0);
    TEST_ASSERT(parse_route_event(nlh) == 0);
    TEST_ASSERT(search_route_table(&key) == NULL);
    return 0;
}

static int test_neighbor_events(int ifindex)
{
    uint8_t buffer[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    uint32_t ip = inet_addr("198.51.100.1");
    uint8_t mac[] = {0x02, 0, 0, 0, 0, 1};
    init_neighbor_message(nlh, RTM_NEWNEIGH, ifindex);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), NDA_DST, &ip, sizeof(ip)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), NDA_LLADDR, mac, sizeof(mac)) == 0);
    TEST_ASSERT(parse_neighbor_event(nlh) == 0);

    ndp_key key = {.ip_family = AF_INET, .ifindex = (uint32_t)ifindex};
    memcpy(key.neigh_ip, &ip, sizeof(ip));
    ndp_info *entry = search_ndp_table(&key);
    TEST_ASSERT(entry && memcmp(entry->mac, mac, sizeof(mac)) == 0 &&
                entry->state == NUD_REACHABLE);
    PUT_REF(entry);

    init_neighbor_message(nlh, RTM_DELNEIGH, ifindex);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), NDA_DST, &ip, sizeof(ip)) == 0);
    TEST_ASSERT(add_attr(nlh, sizeof(buffer), NDA_LLADDR, mac, sizeof(mac)) == 0);
    TEST_ASSERT(parse_neighbor_event(nlh) == 0);
    TEST_ASSERT(search_ndp_table(&key) == NULL);
    return 0;
}

static int test_xsk_feature_query(int ifindex)
{
    uint64_t features = UINT64_MAX;
    TEST_ASSERT(netlink_get_xsk_features(0, &features) == -EINVAL);
    TEST_ASSERT(netlink_get_xsk_features((uint32_t)ifindex, NULL) == -EINVAL);
    int ret = netlink_get_xsk_features((uint32_t)ifindex, &features);
    TEST_ASSERT(ret == 0 || ret < 0);
    if (ret < 0)
        TEST_ASSERT(features == 0);
    return 0;
}

int main(void)
{
    int ifindex = (int)if_nametoindex("lo");
    if (!ifindex) {
        fprintf(stderr, "SKIP: loopback interface is unavailable\n");
        return 0;
    }

    if_cfg selected_if = {.queues = 1};
    snprintf(selected_if.name, sizeof(selected_if.name), "lo");
    g_cfg.ifs = &selected_if;
    g_cfg.ifs_count = 1;
    current_time_ms = read_now_ms();
    TEST_ASSERT(route_init() == 0);
    TEST_RUN_CALL("test_link_and_address_events",
                  test_link_and_address_events(ifindex));
    TEST_RUN_CALL("test_route_events", test_route_events(ifindex));
    TEST_RUN_CALL("test_neighbor_events", test_neighbor_events(ifindex));
    TEST_RUN_CALL("test_xsk_feature_query", test_xsk_feature_query(ifindex));

    uint8_t buffer[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    init_link_message(nlh, RTM_DELLINK, ifindex, IFF_LOOPBACK);
    TEST_ASSERT(parse_link_event(nlh) == 0);
    route_arp_clear_tables();
    puts("All Netlink event tests passed.");
    return 0;
}
