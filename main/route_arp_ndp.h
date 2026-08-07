#ifndef ROUTE_ARP_NDP_H
#define ROUTE_ARP_NDP_H

#include <stdint.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include "trie.h"
#include "list.h"
#include "base.h"
#include "if.h"

#define IF_NAME_MAX 16
#define MAC_STR_MAX 18

/* ── 统一 IP 地址 key（v4 用前 4 字节网络序，v6 用 16 字节）── */

typedef struct route_key {
    sa_family_t ip_family;  /* AF_INET / AF_INET6 */
    uint32_t ifindex;       /* IPv6 scope/interface, 0 = any */
    uint8_t     dip[16];    /* 目的 IP（v4 存于前 4 字节网络序） */
} route_key;

typedef struct ndp_key {
    sa_family_t ip_family;  /* AF_INET / AF_INET6 */
    uint8_t     neigh_ip[16];
    uint32_t    ifindex;    /* 0 = any interface */
} ndp_key;

/* ── 路由信息 ─────────────────────────────────────────────── */

typedef struct route_info {
    sa_family_t ip_family;  /* AF_INET / AF_INET6 */
    uint32_t type;          /* RTN_LOCAL / UNICAST / MULTICAST / BROADCAST */
    uint32_t dst_mask;      /* v4: 0-32;  v6: 0-128 */
    uint8_t  dst_ip[16];    /* 网络字节序，v4 存于前 4 字节 */
    uint8_t  gw_ip[16];
    char     if_name[IF_NAME_MAX];
    uint32_t ifindex;
    uint32_t metric;
    uint32_t mtu;
    uint8_t  prefsrc[16];   /* RTA_PREFSRC (v4 前4字节, v6 全16字节) */
    /* cache */
    if_info* if_info;
    ref_info ref;
    list_node list;
} route_info;

/* ── 邻居信息（ARP / NDP 统一）────────────────────────────── */

typedef struct ndp_info {
    sa_family_t ip_family;  /* AF_INET / AF_INET6 */
    uint8_t  ip[16];            /* 邻居 IP */
    uint8_t  mac[6];
    char     mac_str[MAC_STR_MAX];
    char     if_name[IF_NAME_MAX];
    uint32_t ifindex;
    uint8_t  state;             /* NUD_REACHABLE / STALE / PROBE ... */
    ref_info ref;
    list_node list;
} ndp_info;

/* 向后兼容别名 */
typedef ndp_info arp_info;
typedef ndp_key  arp_key;

/* ── 通用搜索 / 增删接口 ─────────────────────────────────── */

route_info* search_route_table(const route_key* key);
ndp_info*   search_ndp_table(const ndp_key* key);
bool        search_best_saddr_by_daddr(const route_key* key, route_key* answer);

int route_add_entry(const route_info* info);
int route_delete_entry(const route_info* info);

int ndp_add_entry(const ndp_info* info);
int ndp_delete_entry(const ndp_info* info);

/* v4 向后兼容（内部转发到通用接口） */
static inline route_info* search_ipv4_route_table(const route_key* key)
    { return search_route_table(key); }
static inline ndp_info* search_arp_table(const ndp_key* key)
    { return search_ndp_table(key); }
static inline int route4_add_route(const route_info* info)
    { return route_add_entry(info); }
static inline int route4_delete_route(const route_info* info)
    { return route_delete_entry(info); }
static inline int arp4_add_entry(const ndp_info* info)
    { return ndp_add_entry(info); }
static inline int arp4_delete_entry(const ndp_info* info)
    { return ndp_delete_entry(info); }

/* ── 生命周期 / 事件解析 ─────────────────────────────────── */

void route_arp_clear_tables(void);
int  route_init(void);

int  parse_route_event(struct nlmsghdr *nlh);
int  parse_neighbor_event(struct nlmsghdr *nlh);

struct skbuff;
int set_skb_route(struct skbuff* skb, sa_family_t family, const uint8_t* dip);

/* ── 内联辅助函数 ─────────────────────────────────────────── */

static inline void get_route_gw(const route_info* info, uint8_t* dst)
{
    memcpy(dst, info->gw_ip, (info->ip_family == AF_INET6) ? 16 : 4);
}

static inline bool route_is_local_host(const route_info* info)
    { return info->type == RTN_LOCAL; }

static inline bool route_is_multicast(const route_info* info)
    { return info->type == RTN_MULTICAST; }

static inline bool route_is_broadcast(const route_info* info)
    { return info->type == RTN_BROADCAST; }

static inline bool route_include_nexthop(const route_info* info, const uint8_t* nexthop)
{
    if (!info || !nexthop)
        return false;
    if (info->dst_mask == 0)
        return true;

    if (info->ip_family == AF_INET) {
        if (info->dst_mask > 32u)
            return false;
        uint32_t mask = ~((1u << (32u - info->dst_mask)) - 1u);
        uint32_t dst;
        uint32_t nh;
        memcpy(&dst, info->dst_ip, sizeof(dst));
        memcpy(&nh, nexthop, sizeof(nh));
        return (ntohl(dst) & mask) == (ntohl(nh) & mask);
    }

    /* IPv6: 掩码位数 dst_mask 最多 128 */
    if (info->ip_family != AF_INET6 || info->dst_mask > 128u)
        return false;
    uint32_t full_bytes = info->dst_mask / 8u;
    uint32_t rem_bits   = info->dst_mask % 8u;

    if (memcmp(info->dst_ip, nexthop, full_bytes) != 0)
        return false;
    if (rem_bits == 0)
        return true;

    uint8_t mask8 = (uint8_t)(0xFFu << (8u - rem_bits));
    return (info->dst_ip[full_bytes] & mask8) == (nexthop[full_bytes] & mask8);
}

bool route_info_check(const route_info* info);
uint32_t get_route_mtu(const route_info* info);

#endif /* ROUTE_ARP_NDP_H */
