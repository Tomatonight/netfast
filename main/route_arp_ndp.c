#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include "route_arp_ndp.h"
#include "log.h"
#include "base.h"
#include "init.h"
#include "netlink.h"
#include "skbuff.h"
#include "socket.h"

/* ── ARP ping rate limiting ───────────────────────────────────
 * Don't ping the same (ip, ifindex) more than once per cooldown
 * interval.  Uses a small fixed-size cache per worker. */
#define ARP_PING_COOLDOWN_MS  1000
#define ARP_PING_CACHE_SIZE   16
#define NDP_PING_COOLDOWN_MS  1000
#define NDP_PING_CACHE_SIZE   16

static _Thread_local struct {
    uint32_t ip;
    uint32_t ifindex;
    uint64_t last_ms;
} g_arp_ping_cache[ARP_PING_CACHE_SIZE];
static _Thread_local uint32_t g_arp_ping_cache_idx;

static bool arp_ping_allowed(uint32_t ip, uint32_t ifindex, uint64_t now_ms)
{
    for (int i = 0; i < ARP_PING_CACHE_SIZE; i++) {
        if (g_arp_ping_cache[i].ip == ip &&
            g_arp_ping_cache[i].ifindex == ifindex) {
            if (now_ms - g_arp_ping_cache[i].last_ms < ARP_PING_COOLDOWN_MS)
                return false;
            g_arp_ping_cache[i].last_ms = now_ms;
            return true;
        }
    }
    uint32_t idx = g_arp_ping_cache_idx++ % ARP_PING_CACHE_SIZE;
    g_arp_ping_cache[idx].ip      = ip;
    g_arp_ping_cache[idx].ifindex = ifindex;
    g_arp_ping_cache[idx].last_ms = now_ms;
    return true;
}

/* ── NDP ping rate limiting (IPv6) ──────────────────────────── */
static _Thread_local struct {
    uint8_t  ip[16];
    uint32_t ifindex;
    uint64_t last_ms;
} g_ndp_ping_cache[NDP_PING_CACHE_SIZE];
static _Thread_local uint32_t g_ndp_ping_cache_idx;

static bool ndp_ping_allowed(const uint8_t* ip, uint32_t ifindex, uint64_t now_ms)
{
    for (int i = 0; i < NDP_PING_CACHE_SIZE; i++) {
        if (memcmp(g_ndp_ping_cache[i].ip, ip, 16) == 0 &&
            g_ndp_ping_cache[i].ifindex == ifindex) {
            if (now_ms - g_ndp_ping_cache[i].last_ms < NDP_PING_COOLDOWN_MS)
                return false;
            g_ndp_ping_cache[i].last_ms = now_ms;
            return true;
        }
    }
    uint32_t idx = g_ndp_ping_cache_idx++ % NDP_PING_CACHE_SIZE;
    memcpy(g_ndp_ping_cache[idx].ip, ip, 16);
    g_ndp_ping_cache[idx].ifindex = ifindex;
    g_ndp_ping_cache[idx].last_ms = now_ms;
    return true;
}

static bool ndp_entry_usable(const ndp_info* entry)
{
    static const uint8_t zero_mac[6] = {0};
    if (!entry || memcmp(entry->mac, zero_mac, sizeof(zero_mac)) == 0)
        return false;

    return (entry->state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY |
                            NUD_PROBE | NUD_PERMANENT | NUD_NOARP)) != 0;
}

static void trigger_neighbor_probe(sa_family_t family, const uint8_t* ip,
                                   uint32_t ifindex)
{
    if_info* info = search_if_by_index(ifindex);
    if (!info)
        return;

    uint64_t now_ms = get_current_time_ms();
    bool allowed;
    if (family == AF_INET6) {
        allowed = ndp_ping_allowed(ip, ifindex, now_ms);
    } else {
        uint32_t ip4;
        memcpy(&ip4, ip, sizeof(ip4));
        allowed = arp_ping_allowed(ip4, ifindex, now_ms);
    }

    if (allowed) {
        char ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(family, ip, ip_str, sizeof(ip_str))) {
            char cmd[256];
            int len = family == AF_INET6
                ? snprintf(cmd, sizeof(cmd),
                           "ping -6 -I %s -c 1 -W 1 %s >/dev/null 2>&1 &",
                           info->name, ip_str)
                : snprintf(cmd, sizeof(cmd),
                           "ping -I %s -c 1 -W 1 %s >/dev/null 2>&1 &",
                           info->name, ip_str);
            if (len >= 0 && len < (int)sizeof(cmd) && system(cmd) == -1)
                DEBUG_LOG("failed to start neighbor probe via if=%s", info->name);
        }
    }
    PUT_REF(info);
}

static void free_route_info(void* ptr);

static int route4_add_cb(trie_node* node, uint64_t info);
static int route4_delete_cb(trie_node* node, uint64_t info);
static uint64_t route4_search_cb(trie_node* node, void* argv);
static int route6_add_cb(trie_node* node, uint64_t info);
static int route6_delete_cb(trie_node* node, uint64_t info);
static uint64_t route6_search_cb(trie_node* node, void* argv);
static int arp_add_cb(trie_node* node, uint64_t info);
static int arp_delete_cb(trie_node* node, uint64_t info);
static uint64_t arp_search_cb(trie_node* node, void* argv);
static int ndp_add_cb(trie_node* node, uint64_t info);
static int ndp_delete_cb(trie_node* node, uint64_t info);
static uint64_t ndp_search_cb(trie_node* node, void* argv);

DEFINE_TRIE(ipv4_route_table, TRIE_IPV4, route4_add_cb, route4_delete_cb, route4_search_cb, true);
DEFINE_TRIE(ipv6_route_table, TRIE_IPV6, route6_add_cb, route6_delete_cb, route6_search_cb, true);

DEFINE_TRIE(arp_table,  TRIE_IPV4, arp_add_cb,  arp_delete_cb,  arp_search_cb,  true);
DEFINE_TRIE(ndp_table, TRIE_IPV6, ndp_add_cb, ndp_delete_cb, ndp_search_cb, true);


int route_init(void)
{
    return 0;
}

route_info* search_route_table(const route_key* key)
{
    if (key->ip_family == AF_INET6) {
        uint64_t ret = search_trie_element(&ipv6_route_table,
            (uint64_t)(uintptr_t)key->dip, 128, true, (void*)key);
        return (route_info*)ret;
    }

    uint32_t dest_ip;
    memcpy(&dest_ip, key->dip, sizeof(dest_ip));
    uint64_t ret = search_trie_element(&ipv4_route_table, dest_ip, 32, true, (void*)key);
    return (route_info*)ret;
}

/* ── 统一设置 skb 路由（v4 / v6）──────────────────────── */
int set_skb_route(skbuff* skb, sa_family_t family, const uint8_t* dip)
{
    route_info* route = skb->route;
    if (route_info_check(route))
        return 0;
    if (route) {
        PUT_REF(skb->route);
        skb->route = NULL;
        route = NULL;
    }

    route_key key = { .ip_family = family };

    if (family == AF_INET6) {
        if (skb->sock)
            key.ifindex = skb->sock->dip6_scope_id;
        memcpy(key.dip, dip, 16);
    } else {
        memcpy(key.dip, dip, 4);
    }

    route = search_route_table(&key);
    if (!route) {
        DEBUG_LOG("No route found");
        return -1;
    }
    skb->route = route;
    return 0;
}

ndp_info* search_ndp_table(const ndp_key* key)
{
    uint64_t ret;
    if (key->ip_family == AF_INET6) {
        ret = search_trie_element(&ndp_table,
            (uint64_t)(uintptr_t)key->neigh_ip, 128, false, (void*)key);
    } else if (key->ip_family == AF_INET) {
        uint32_t ip;
        memcpy(&ip, key->neigh_ip, sizeof(ip));
        ret = search_trie_element(&arp_table, ip, 32, false, (void*)key);
    } else {
        return NULL;
    }

    return (ndp_info*)ret;
}

int resolve_neighbor_entry(const ndp_key* key, ndp_info** result)
{
    if (result)
        *result = NULL;

    ndp_info* entry = search_ndp_table(key);
    if (entry && (entry->state & NUD_FAILED)) {
        PUT_REF(entry);
        return -EHOSTUNREACH;
    }

    if (ndp_entry_usable(entry)) {
        if (result)
            *result = entry;
        else
            PUT_REF(entry);
        return 0;
    }

    PUT_REF(entry);
    if (key->ifindex)
        trigger_neighbor_probe(key->ip_family, key->neigh_ip, key->ifindex);
    return -EINPROGRESS;
}

static route_info* create_route_info(const route_info* info)
{
    CREATE_REF(route_info, route, free_route_info);
    if (!route)
        return NULL;

    memcpy(route, info, offsetof(route_info, if_info));

    if_info* ifi = NULL;
    if (REF_USABLE(info->if_info)) {
        GET_REF(ifi, info->if_info);
    } else if (route->if_name[0]) {
        ifi = search_if_by_name(route->if_name);
    }
    if (!ifi && route->ifindex)
        ifi = search_if_by_index(route->ifindex);
    if (!ifi) {
        WARN_LOG("[ROUTE] if_info not found: ifname=%s ifindex=%u",
                 route->if_name, route->ifindex);
        DESTROY_REF(route);
        return NULL;
    }

    MOVE_REF(route->if_info, ifi);
    return route;
}

static void free_route_info(void* ptr)
{
    route_info* info = (route_info*)ptr;
    PUT_REF(info->if_info);
    free(info);
}

static void free_ndp_info(void* ptr)
{
    ndp_info* info = (ndp_info*)ptr;
    free(info);
}

static ndp_info* create_ndp_info(const ndp_info* in)
{
    if (!in)
        return NULL;
    CREATE_REF(ndp_info, ndp, free_ndp_info);
    if (!ndp)
        return NULL;
    uint32_t copy_size = offsetof(ndp_info, ref);
    memcpy(ndp, in, copy_size);
    return ndp;
}

static bool route_same(const route_info* a, const route_info* b)
{
    if (a == b)
        return true;
    if (!a || !b)
        return false;

    if (a->ip_family != b->ip_family)
        return false;
    if (a->type != b->type)
        return false;
    if (a->dst_mask != b->dst_mask)
        return false;

    if (a->ip_family == AF_INET) {
        if (memcmp(a->dst_ip, b->dst_ip, 4) != 0)
            return false;
        if (memcmp(a->gw_ip, b->gw_ip, 4) != 0)
            return false;
    } else {
        if (memcmp(a->dst_ip, b->dst_ip, 16) != 0)
            return false;
        if (memcmp(a->gw_ip, b->gw_ip, 16) != 0)
            return false;
    }

    if (a->ifindex != b->ifindex)
        return false;
    if (a->ifindex == 0) {
        if (strncmp(a->if_name, b->if_name, IF_NAME_MAX) != 0)
            return false;
    }
    return a->metric == b->metric;
}

static void route_copy_attr(route_info* dst, const route_info* src)
{
    dst->mtu = src->mtu;
    memcpy(dst->prefsrc, src->prefsrc, sizeof(dst->prefsrc));
}

static int route4_add_cb(trie_node* node, uint64_t info)
{
    route_info* in = (route_info*)info;
    bool created_head = false;
    if (!node->exist_element) {
        node->element = (uint64_t)create_list_node(0);
        if (!node->element)
            return -1;
        node->exist_element = true;
        created_head = true;
    }

    list_node* head = (list_node*)node->element;
    route_info* it;
    FOR_EACH_LIST_OFFSET(head, it, route_info, list) {
        if (route_same(it, in)) {
            route_copy_attr(it, in);
            return 0;
        }
    }

    route_info* route = create_route_info(in);
    if (!route) {
        if (created_head) {
            destroy_list_node(head, NULL);
            node->element = 0;
            node->exist_element = false;
        }
        return -1;
    }
    add_list_node(head, &route->list);
    return 0;
}

static int route4_delete_cb(trie_node* node, uint64_t info)
{
    route_info* in = (route_info*)info;
    if (!node->exist_element)
        return 0;

    list_node* head = (list_node*)node->element;
    route_info* it;
    list_node* tmp_node;
    FOR_EACH_LIST_SAFE_OFFSET(head, it, tmp_node, route_info, list) {
        if (route_same(it, in)) {
            remove_list_node(&it->list);
            DESTROY_REF(it);
            break;
        }
    }

    if (!head->next) {
        destroy_list_node(head, NULL);
        node->element = 0;
        node->exist_element = false;
    }
    return 0;
}

static uint64_t route4_search_cb(trie_node* node, void* argv)
{
    (void)argv;
    if (!node->exist_element)
        return 0;
    list_node* head = (list_node*)node->element;
    route_info* element;
    route_info* selected = NULL;
    uint32_t min_metric = 0xFFFFFFFF;
    FOR_EACH_LIST_OFFSET(head, element, route_info, list) {
        if (element->metric < min_metric) {
            min_metric = element->metric;
            selected = element;
        }
    }

    if (selected)
        INC_REF(selected);
    return (uint64_t)selected;
}

static uint64_t route6_search_cb_impl(trie_node* node, void* argv)
{
    const route_key* key = (const route_key*)argv;
    if (!node || !node->exist_element)
        return 0;

    list_node* head = (list_node*)node->element;
    route_info* element;
    route_info* selected = NULL;
    uint32_t min_metric = UINT32_MAX;
    FOR_EACH_LIST_OFFSET(head, element, route_info, list) {
        if (key->ifindex && element->ifindex != key->ifindex)
            continue;
        if (element->metric < min_metric) {
            min_metric = element->metric;
            selected = element;
        }
    }
    if (selected)
        INC_REF(selected);
    return (uint64_t)selected;
}

static int arp_add_cb(trie_node* node, uint64_t info)
{
    ndp_info* in = (ndp_info*)info;
    bool created_head = false;
    if (!node->exist_element) {
        node->element = (uint64_t)create_list_node(0);
        if (!node->element)
            return -1;
        node->exist_element = true;
        created_head = true;
    }

    list_node* head = (list_node*)node->element;
    ndp_info* entry;
    FOR_EACH_LIST_OFFSET(head, entry, ndp_info, list) {
        if (entry->ifindex == in->ifindex) {
            memcpy(entry, in, offsetof(ndp_info, ref));
            return 0;
        }
    }

    ndp_info* new_entry = create_ndp_info(in);
    if (!new_entry) {
        if (created_head) {
            destroy_list_node(head, NULL);
            node->element = 0;
            node->exist_element = false;
        }
        return -1;
    }
    add_list_node(head, &new_entry->list);
    return 0;
}

static int arp_delete_cb(trie_node* node, uint64_t info)
{
    ndp_info* in = (ndp_info*)info;
    if (!node->exist_element || !node->element)
        return 0;

    list_node* head = (list_node*)node->element;
    ndp_info* entry;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(head, entry, tmp, ndp_info, list) {
        if (!in || entry->ifindex == in->ifindex) {
            remove_list_node(&entry->list);
            DESTROY_REF(entry);
        }
    }
    if (!head->next) {
        destroy_list_node(head, NULL);
        node->element = 0;
        node->exist_element = false;
    }
    return 0;
}

static uint64_t arp_search_cb(trie_node* node, void* argv)
{
    const ndp_key* key = (const ndp_key*)argv;
    if (!node->exist_element)
        return 0;
    list_node* head = (list_node*)node->element;
    ndp_info* entry;
    FOR_EACH_LIST_OFFSET(head, entry, ndp_info, list) {
        if (key->ifindex == 0 || entry->ifindex == key->ifindex) {
            INC_REF(entry);
            return (uint64_t)entry;
        }
    }
    return 0;
}

/* ── IPv6 callback stubs (identical logic, different trie type) ── */
static int ndp_add_cb(trie_node* node, uint64_t info)
    { return arp_add_cb(node, info); }
static int ndp_delete_cb(trie_node* node, uint64_t info)
    { return arp_delete_cb(node, info); }
static uint64_t ndp_search_cb(trie_node* node, void* argv)
    { return arp_search_cb(node, argv); }

static int route6_add_cb(trie_node* node, uint64_t info)
    { return route4_add_cb(node, info); }
static int route6_delete_cb(trie_node* node, uint64_t info)
    { return route4_delete_cb(node, info); }
static uint64_t route6_search_cb(trie_node* node, void* argv)
    { return route6_search_cb_impl(node, argv); }

int ndp_add_entry(const ndp_info* info)
{
    if (info->ip_family == AF_INET6)
        return add_trie_element(&ndp_table, (uint64_t)(uintptr_t)info->ip,
                                128, (uint64_t)info);
    uint32_t ip;
    memcpy(&ip, info->ip, sizeof(ip));
    return add_trie_element(&arp_table, ip, 32, (uint64_t)info);
}

int ndp_delete_entry(const ndp_info* info)
{
    if (info->ip_family == AF_INET6)
        return delete_trie_element(&ndp_table, (uint64_t)(uintptr_t)info->ip,
                                   128, (uint64_t)info);
    uint32_t ip;
    memcpy(&ip, info->ip, sizeof(ip));
    return delete_trie_element(&arp_table, ip, 32, (uint64_t)info);
}

int route_add_entry(const route_info* info)
{
    if (info->ip_family == AF_INET6)
        return add_trie_element(&ipv6_route_table,
                                (uint64_t)(uintptr_t)info->dst_ip,
                                info->dst_mask, (uint64_t)info);
    uint32_t dst;
    memcpy(&dst, info->dst_ip, sizeof(dst));
    return add_trie_element(&ipv4_route_table, dst, info->dst_mask, (uint64_t)info);
}

int route_delete_entry(const route_info* info)
{
    if (info->ip_family == AF_INET6)
        return delete_trie_element(&ipv6_route_table,
                                   (uint64_t)(uintptr_t)info->dst_ip,
                                   info->dst_mask, (uint64_t)info);
    uint32_t dst;
    memcpy(&dst, info->dst_ip, sizeof(dst));
    return delete_trie_element(&ipv4_route_table, dst, info->dst_mask, (uint64_t)info);
}

static void parse_route_metrics(route_info* info, const struct rtattr* metrics)
{
    int len = RTA_PAYLOAD(metrics);
    struct rtattr* attr = RTA_DATA(metrics);
    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == RTAX_MTU && RTA_PAYLOAD(attr) >= sizeof(uint32_t))
            memcpy(&info->mtu, RTA_DATA(attr), sizeof(info->mtu));
    }
}

int parse_route_event(struct nlmsghdr *nlh)
{
    if (nlh->nlmsg_type != RTM_NEWROUTE && nlh->nlmsg_type != RTM_DELROUTE)
        return 0;
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg)))
        return -1;

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6)
        return 0;
    if (rtm->rtm_table != RT_TABLE_MAIN && rtm->rtm_table != RT_TABLE_LOCAL)
        return 0;

    route_info info;
    memset(&info, 0, sizeof(info));
    info.ip_family = rtm->rtm_family;
    info.type      = rtm->rtm_type;
    info.dst_mask  = rtm->rtm_dst_len;

    int len = RTM_PAYLOAD(nlh);
    struct rtattr *rta;
    for (rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch (rta->rta_type) {
        case RTA_DST:
            memcpy(info.dst_ip, RTA_DATA(rta),
                   RTA_PAYLOAD(rta) < 16 ? RTA_PAYLOAD(rta) : 16);
            break;
        case RTA_GATEWAY:
            memcpy(info.gw_ip, RTA_DATA(rta),
                   RTA_PAYLOAD(rta) < 16 ? RTA_PAYLOAD(rta) : 16);
            break;
        case RTA_OIF:
            if (RTA_PAYLOAD(rta) >= 4) {
                memcpy(&info.ifindex, RTA_DATA(rta), 4);
                if_indextoname(info.ifindex, info.if_name);
                if (filter_ifname(info.if_name))
                    return 0;
            }
            break;
        case RTA_PRIORITY:
            if (RTA_PAYLOAD(rta) >= 4)
                memcpy(&info.metric, RTA_DATA(rta), 4);
            break;
        case RTA_PREFSRC:
            memcpy(info.prefsrc, RTA_DATA(rta),
                   RTA_PAYLOAD(rta) < 16 ? RTA_PAYLOAD(rta) : 16);
            break;
        case RTA_METRICS:
            parse_route_metrics(&info, rta);
            break;
        }
    }

    if (nlh->nlmsg_type == RTM_NEWROUTE)
        return route_add_entry(&info);
    return route_delete_entry(&info);
}

int parse_neighbor_event(struct nlmsghdr *nlh)
{
    if (nlh->nlmsg_type != RTM_NEWNEIGH && nlh->nlmsg_type != RTM_DELNEIGH)
        return 0;
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ndmsg)))
        return -1;

    struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nlh);
    if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6)
        return 0;

    ndp_info info;
    memset(&info, 0, sizeof(info));
    info.ip_family = ndm->ndm_family;
    info.ifindex   = ndm->ndm_ifindex;
    info.state     = (uint8_t)ndm->ndm_state;
    if_indextoname(info.ifindex, info.if_name);

    bool has_ip = false;
    int len = (int)nlh->nlmsg_len - NLMSG_SPACE(sizeof(*ndm));
    struct rtattr *rta;
    for (rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
         RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch (rta->rta_type) {
        case NDA_DST:
            memcpy(info.ip, RTA_DATA(rta),
                   RTA_PAYLOAD(rta) < 16 ? RTA_PAYLOAD(rta) : 16);
            has_ip = true;
            break;
        case NDA_LLADDR:
            if (RTA_PAYLOAD(rta) >= 6) {
                memcpy(info.mac, RTA_DATA(rta), 6);
                snprintf(info.mac_str, MAC_STR_MAX,
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         info.mac[0], info.mac[1], info.mac[2],
                         info.mac[3], info.mac[4], info.mac[5]);
            }
            break;
        case NDA_CACHEINFO:  /* IPv6 reachable/retrans timer */
        case NDA_PROBES:     /* IPv6 unicast probes */
            /* accepted but not cached; NDP state machine is external */
            break;
        }
    }

    if (!has_ip)
        return 0;
    if (nlh->nlmsg_type == RTM_NEWNEIGH)
        return ndp_add_entry(&info);
    return ndp_delete_entry(&info);
}

bool route_info_check(const route_info* info)
{
    return REF_USABLE(info) && REF_USABLE(info->if_info);
}

bool search_best_saddr_by_daddr(const route_key* key, route_key* answer)
{
    route_info* info = search_route_table(key);
    if (!info) {
        DEBUG_LOG("No route found, cannot determine best source address");
        return false;
    }

    memset(answer, 0, sizeof(*answer));
    answer->ip_family = key->ip_family;

    uint32_t addr_len = key->ip_family == AF_INET6 ? 16u : 4u;
    static const uint8_t zero[16];
    if (memcmp(info->prefsrc, zero, addr_len) != 0) {
        memcpy(answer->dip, info->prefsrc, addr_len);
        PUT_REF(info);
        return true;
    }

    bool found = if_search_best_saddr_by_daddr(
        info->if_info, key->ip_family, key->dip, answer->dip);
    if (!found) {
        if (key->ip_family == AF_INET) {
            uint32_t dip;
            memcpy(&dip, key->dip, sizeof(dip));
            DEBUG_LOG("No suitable source IP on interface for " IP_STR, IP_ARG(dip));
        } else {
            WARN_LOG("No suitable IPv6 source address on interface");
        }
    }
    PUT_REF(info);
    return found;
}

static void free_route_element(uint64_t element)
{
    list_node* head = (list_node*)element;

    route_info* it;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(head, it, tmp, route_info, list) {
        remove_list_node(&it->list);
        DESTROY_REF(it);
    }
    destroy_list_node(head, NULL);
}

static void free_arp_element(uint64_t element)
{
    list_node* head = (list_node*)element;
    ndp_info* entry;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(head, entry, tmp, ndp_info, list) {
        remove_list_node(&entry->list);
        DESTROY_REF(entry);
    }
    destroy_list_node(head, NULL);
}

void route_arp_clear_tables(void)
{
    trie_clear(&ipv4_route_table, free_route_element);
    trie_clear(&ipv6_route_table, free_route_element);
    trie_clear(&arp_table, free_arp_element);
    trie_clear(&ndp_table, free_arp_element);
}

uint32_t get_route_mtu(const route_info* info)
{
    if (info->mtu)
        return info->mtu;
    return info->if_info->mtu;
}
