#include "if.h"

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/netdev.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ether.h"
#include "log.h"
#include "loopback.h"
#include "netlink.h"
#include "req.h"
#include "route_arp_ndp.h"
#include "worker.h"

typedef struct if_l2_ops {
    int if_type;
    const if_ops* ops;
} if_l2_ops;

static const if_l2_ops g_l2_ops[] = {
    { ARPHRD_ETHER, &ether_ops },
    { ARPHRD_LOOPBACK, &loopback_ops },
};

static list_node g_if_list;
pthread_rwlock_t g_if_rwlock = PTHREAD_RWLOCK_INITIALIZER;

bool if_has_loopback(void)
{
    bool found = false;
    IF_RDLOCK();
    if_info* info;
    FOR_EACH_LIST_OFFSET(&g_if_list, info, if_info, list) {
        if (info->ops == &loopback_ops) {
            found = true;
            break;
        }
    }
    IF_UNLOCK();
    return found;
}

static inline uint32_t if_load_ipv4(const uint8_t* ip)
{
    uint32_t value;
    memcpy(&value, ip, sizeof(value));
    return value;
}

static bool if_addr_equal(const if_addr* addr, sa_family_t family,
                          const uint8_t* ip)
{
    if (addr->ip_family != family)
        return false;
    return family == AF_INET6
        ? memcmp(addr->ipv6, ip, sizeof(addr->ipv6)) == 0
        : addr->ipv4 == if_load_ipv4(ip);
}

/* Derive scope from an IP address (simplified, mirrors kernel logic). */
static uint8_t ip_to_scope(sa_family_t family, const uint8_t* ip)
{
    if (family == AF_INET) {
        uint32_t v4 = if_load_ipv4(ip);
        uint8_t b0 = (uint8_t)(ntohl(v4) >> 24);
        if (b0 == 127)
            return ADDR_SCOPE_HOST;
        if (b0 == 169 && (uint8_t)(ntohl(v4) >> 16) == 254)
            return ADDR_SCOPE_LINK;
        return ADDR_SCOPE_GLOBAL;
    }
    if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80)  /* fe80::/10 */
        return ADDR_SCOPE_LINK;
    static const uint8_t v6_loopback[16] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    };
    if (memcmp(ip, v6_loopback, sizeof(v6_loopback)) == 0)
        return ADDR_SCOPE_HOST;
    return ADDR_SCOPE_GLOBAL;
}

static const if_ops* get_if_ops_by_type(int if_type)
{
    for (uint32_t i = 0; i < sizeof(g_l2_ops) / sizeof(g_l2_ops[0]); ++i) {
        if (g_l2_ops[i].if_type == if_type)
            return g_l2_ops[i].ops;
    }
    return NULL;
}

static inline bool if_is_up(uint32_t flags)
{
    return (flags & IFF_UP) != 0;
}

static bool if_hw_rx_checksum_enabled(const if_info* info)
{
    if (!info->name[0])
        return false;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    struct ethtool_value value = { .cmd = ETHTOOL_GRXCSUM };
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", info->name);
    ifr.ifr_data = (void*)&value;

    bool enabled = ioctl(fd, SIOCETHTOOL, &ifr) == 0 && value.data != 0;
    close(fd);
    return enabled;
}

static void if_update_checksum_features(if_info* info)
{
    uint64_t xsk_features = 0;
    int ret = netlink_get_xsk_features((uint32_t)info->ifindex, &xsk_features);

    info->hw_tx_checksum_enabled =
        ret == 0 && (xsk_features & NETDEV_XSK_FLAGS_TX_CHECKSUM) != 0;
    info->hw_rx_checksum_enabled = if_hw_rx_checksum_enabled(info);

    if (ret < 0)
        WARN_LOG("interface %s: query AF_XDP features failed: %s",
                 info->name, strerror(-ret));
    DEBUG_LOG("interface %s: hw_tx_checksum=%u hw_rx_checksum=%u",
              info->name, info->hw_tx_checksum_enabled,
              info->hw_rx_checksum_enabled);
}

static void clear_addr_list(if_info* info)
{
    if_addr* addr;
    list_node* tmp_node;

    FOR_EACH_LIST_SAFE_OFFSET(&info->addr_list, addr, tmp_node, if_addr, list) {
        remove_list_node(&addr->list);
        free(addr);
    }
}

static bool if_delete_addr(if_info* info, sa_family_t family, const uint8_t* ip)
{
    if_addr* addr;
    list_node* tmp_node;

    IF_WRLOCK();
    FOR_EACH_LIST_SAFE_OFFSET(&info->addr_list, addr, tmp_node, if_addr, list) {
        if (!if_addr_equal(addr, family, ip))
            continue;
        remove_list_node(&addr->list);
        free(addr);
        IF_UNLOCK();
        return true;
    }
    IF_UNLOCK();
    return false;
}

bool if_add_addr(if_info* info, sa_family_t family, const uint8_t* ip,
                 uint32_t prefix_len, uint8_t scope, bool primary)
{
    if_addr* addr;

    IF_WRLOCK();
    FOR_EACH_LIST_OFFSET(&info->addr_list, addr, if_addr, list) {
        if (if_addr_equal(addr, family, ip)) {
            addr->prefix_len = prefix_len;
            addr->scope = scope;
            addr->primary = primary;
            IF_UNLOCK();
            return true;
        }
    }

    addr = calloc(1, sizeof(*addr));
    if (!addr) {
        IF_UNLOCK();
        return false;
    }

    addr->ip_family  = family;
    addr->prefix_len = prefix_len;
    addr->scope      = scope;
    addr->primary    = primary;
    if (family == AF_INET6) {
        memcpy(addr->ipv6, ip, 16);
    } else {
        addr->ipv4 = if_load_ipv4(ip);
    }
    add_list_node(&info->addr_list, &addr->list);
    IF_UNLOCK();
    return true;
}

bool if_has_addr(if_info* info, sa_family_t family, const uint8_t* ip)
{
    bool found = false;
    IF_RDLOCK();
    if_addr* addr;
    FOR_EACH_LIST_OFFSET(&info->addr_list, addr, if_addr, list) {
        if (if_addr_equal(addr, family, ip)) {
            found = true;
            break;
        }
    }
    IF_UNLOCK();
    return found;
}

static bool is_subnet_match_v4(uint32_t sip, uint32_t prefix_len, uint32_t dip)
{
    if (prefix_len == 0)
        return true;
    uint32_t mask = (prefix_len == 32) ? 0xFFFFFFFFu : (~0u << (32 - prefix_len));
    return (ntohl(sip) & mask) == (ntohl(dip) & mask);
}

static bool is_subnet_match_v6(const uint8_t* sip, uint32_t prefix_len, const uint8_t* dip)
{
    if (prefix_len > 128)
        return false;
    if (prefix_len == 0)
        return true;
    uint32_t full_bytes = prefix_len / 8u;
    uint32_t rem_bits   = prefix_len % 8u;
    if (memcmp(sip, dip, full_bytes) != 0)
        return false;
    if (rem_bits == 0)
        return true;
    uint8_t mask8 = (uint8_t)(0xFFu << (8u - rem_bits));
    return (sip[full_bytes] & mask8) == (dip[full_bytes] & mask8);
}

static bool if_addr_better(const if_addr* candidate, const if_addr* current,
                           uint8_t daddr_scope)
{
    if (!current)
        return true;
    if (candidate->primary != current->primary)
        return candidate->primary;

    bool candidate_scope = candidate->scope == daddr_scope;
    bool current_scope = current->scope == daddr_scope;
    if (candidate_scope != current_scope)
        return candidate_scope;
    return candidate->prefix_len > current->prefix_len;
}

static void if_copy_addr(const if_addr* addr, uint8_t* dst)
{
    if (addr->ip_family == AF_INET6)
        memcpy(dst, addr->ipv6, sizeof(addr->ipv6));
    else
        memcpy(dst, &addr->ipv4, sizeof(addr->ipv4));
}

bool if_search_best_saddr_by_daddr(if_info* info, sa_family_t family,
                                   const uint8_t* daddr, uint8_t* saddr)
{
    if_addr* addr;
    if_addr* best = NULL;
    if_addr* best_fallback = NULL;
    uint8_t daddr_scope = ip_to_scope(family, daddr);

    memset(saddr, 0, 16);

    IF_RDLOCK();
    FOR_EACH_LIST_OFFSET(&info->addr_list, addr, if_addr, list) {
        if (addr->ip_family != family)
            continue;

        bool match = false;
        if (family == AF_INET) {
            if (addr->ipv4 == 0 || addr->prefix_len > 32)
                continue;
            match = is_subnet_match_v4(addr->ipv4, addr->prefix_len,
                                       if_load_ipv4(daddr));
        } else {
            match = is_subnet_match_v6(addr->ipv6, addr->prefix_len, daddr);
        }

        if (match && if_addr_better(addr, best, daddr_scope)) {
            best = addr;
            /* host-route match is perfect, stop searching */
            if (addr->prefix_len == (family == AF_INET6 ? 128u : 32u))
                break;
        } else if (!match &&
                   if_addr_better(addr, best_fallback, daddr_scope)) {
            best_fallback = addr;
        }
    }
    const if_addr* selected = best ? best : best_fallback;
    if (selected)
        if_copy_addr(selected, saddr);
    IF_UNLOCK();
    return selected != NULL;
}

static int if_up_cb(void* arg)
{
    if_info* info = (if_info*)arg;
    if (info->ops->up)
        return info->ops->up(info);
    return 0;
}

static int if_down_cb(void* arg)
{
    if_info* info = (if_info*)arg;
    if (info->ops->down)
        return info->ops->down(info);
    return 0;
}

static void notify_if_change(if_info* info, int (*cb)(void*))
{
    worker* cur = get_current_worker();

    for (int i = 0; i < g_worker_num; ++i) {
        worker* w = &g_workers[i];
        if (w == cur)
            continue;
        submit_req_2_worker(w, info, cb, true);
    }
}

static void if_up(if_info* info)
{
    if_update_checksum_features(info);
    if (info->ops->up)
        (void)info->ops->up(info);
    notify_if_change(info, if_up_cb);
}

static void if_down(if_info* info)
{
    notify_if_change(info, if_down_cb);
    if (info->ops->down)
        (void)info->ops->down(info);
}

static if_info* create_if(struct nlmsghdr* nlh)
{
    struct ifinfomsg* ifinfo = (struct ifinfomsg*)NLMSG_DATA(nlh);
    const if_ops* ops = get_if_ops_by_type(ifinfo->ifi_type);
    if_info* info;

    if (!ops)
        return NULL;

    CREATE_REF(if_info, new_info, free);
    info = new_info;
    if (!info)
        return NULL;

    info->ops = ops;
    return info;
}

/* Locking: acquires g_if_rwlock internally.  Interface state transitions are
 * reported to the caller rather than acted on here: starting/stopping XDP can
 * generate netlink events, so it must never run while holding this lock. */
static int if_update(struct nlmsghdr* nlh, if_info** changed_info,
                     bool* bring_up, bool* bring_down)
{
    struct ifinfomsg* ifinfo = (struct ifinfomsg*)NLMSG_DATA(nlh);
    if_info* info;

    *changed_info = NULL;
    *bring_up = false;
    *bring_down = false;

    IF_WRLOCK();
    FOR_EACH_LIST_OFFSET(&g_if_list, info, if_info, list) {
        if (info->ifindex == ifinfo->ifi_index) {
            bool was_up = if_is_up(info->flags);
            info->ops->update(info, nlh);
            if (!was_up && if_is_up(info->flags))
                *bring_up = true;
            else if (was_up && !if_is_up(info->flags))
                *bring_down = true;
            if (*bring_up || *bring_down) {
                INC_REF(info);
                *changed_info = info;
            }
            IF_UNLOCK();
            return 0;
        }
    }

    info = create_if(nlh);
    if (!info) {
        IF_UNLOCK();
        return -1;
    }
    if (info->ops->create(info, nlh) < 0) {
        IF_UNLOCK();
        PUT_REF(info);
        return -1;
    }
    add_list_node(&g_if_list, &info->list);
    if (if_is_up(info->flags)) {
        INC_REF(info);
        *changed_info = info;
        *bring_up = true;
    }
    IF_UNLOCK();
    return 0;
}

/* Locking: acquires g_if_rwlock internally for g_if_list manipulation.
 * The removed list reference is returned to the caller, which performs
 * the potentially re-entrant teardown unlocked. */
static int if_delete(struct nlmsghdr* nlh, if_info** deleted_info,
                     bool* was_up)
{
    struct ifinfomsg* ifinfo = (struct ifinfomsg*)NLMSG_DATA(nlh);
    if_info* info;

    *deleted_info = NULL;
    *was_up = false;

    IF_WRLOCK();
    FOR_EACH_LIST_OFFSET(&g_if_list, info, if_info, list) {
        if (info->ifindex == ifinfo->ifi_index) {
            *was_up = if_is_up(info->flags);
            remove_list_node(&info->list);
            *deleted_info = info;
            clear_addr_list(info);
            IF_UNLOCK();
            return 0;
        }
    }
    IF_UNLOCK();
    return -1;
}

int parse_link_event(struct nlmsghdr* nlh)
{
    int ret = 0;
    if_info* changed_info = NULL;
    bool bring_up = false;
    bool bring_down = false;

    if (nlh->nlmsg_type == RTM_NEWLINK)
        ret = if_update(nlh, &changed_info, &bring_up, &bring_down);
    else if (nlh->nlmsg_type == RTM_DELLINK)
        ret = if_delete(nlh, &changed_info, &bring_down);

    if (changed_info) {
        if (bring_up)
            if_up(changed_info);
        else if (bring_down)
            if_down(changed_info);

        if (nlh->nlmsg_type == RTM_DELLINK &&
            changed_info->ops->destroy)
            changed_info->ops->destroy(changed_info);
        if (nlh->nlmsg_type == RTM_DELLINK)
            DESTROY_REF(changed_info);
        else
            PUT_REF(changed_info);
    }

    return ret;
}

int parse_addr_event(struct nlmsghdr* nlh)
{
    struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nlh);
    struct rtattr* rta;
    int rta_len = IFA_PAYLOAD(nlh);
    if_info* info;
    bool have_local = false, have_addr = false;
    uint32_t ipv4_local = 0, ipv4_addr = 0;
    uint8_t  ipv6_local[16] = {0}, ipv6_addr[16] = {0};
    uint32_t ifa_flags = ifa->ifa_flags;

    if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
        return 0;

    info = search_if_by_index(ifa->ifa_index);
    if (!info)
        return -1;

    for (rta = IFA_RTA(ifa); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (ifa->ifa_family == AF_INET && RTA_PAYLOAD(rta) >= 4) {
            if (rta->rta_type == IFA_LOCAL) {
                memcpy(&ipv4_local, RTA_DATA(rta), 4);
                have_local = true;
            } else if (rta->rta_type == IFA_ADDRESS) {
                memcpy(&ipv4_addr, RTA_DATA(rta), 4);
                have_addr = true;
            }
        } else if (ifa->ifa_family == AF_INET6 && RTA_PAYLOAD(rta) >= 16) {
            if (rta->rta_type == IFA_LOCAL) {
                memcpy(ipv6_local, RTA_DATA(rta), 16);
                have_local = true;
            } else if (rta->rta_type == IFA_ADDRESS) {
                memcpy(ipv6_addr, RTA_DATA(rta), 16);
                have_addr = true;
            }
        }
        if (rta->rta_type == IFA_FLAGS && RTA_PAYLOAD(rta) >= (int)sizeof(uint32_t))
            memcpy(&ifa_flags, RTA_DATA(rta), sizeof(ifa_flags));
    }

    bool primary = !(ifa_flags & IFA_F_SECONDARY);

    if (have_local || have_addr) {
        uint32_t ipv4 = have_local ? ipv4_local : ipv4_addr;
        const uint8_t* ip = ifa->ifa_family == AF_INET6
            ? (have_local ? ipv6_local : ipv6_addr)
            : (const uint8_t*)&ipv4;
        if (nlh->nlmsg_type == RTM_NEWADDR)
            (void)if_add_addr(info, ifa->ifa_family, ip,
                              ifa->ifa_prefixlen, ifa->ifa_scope, primary);
        else if (nlh->nlmsg_type == RTM_DELADDR)
            (void)if_delete_addr(info, ifa->ifa_family, ip);
    }

    PUT_REF(info);
    return 0;
}

if_info* search_if_by_name(const char* name)
{
    if_info* info;

    IF_RDLOCK();
    FOR_EACH_LIST_OFFSET(&g_if_list, info, if_info, list) {
        if (strcmp(info->name, name) == 0) {
            INC_REF(info);
            IF_UNLOCK();
            return info;
        }
    }
    IF_UNLOCK();
    return NULL;
}

if_info* search_if_by_index(uint32_t ifindex)
{
    if_info* info;

    IF_RDLOCK();
    FOR_EACH_LIST_OFFSET(&g_if_list, info, if_info, list) {
        if ((uint32_t)info->ifindex == ifindex) {
            INC_REF(info);
            IF_UNLOCK();
            return info;
        }
    }
    IF_UNLOCK();
    return NULL;
}

bool search_addr_exist(sa_family_t family, const uint8_t* ip, uint32_t ifindex)
{
    if_info* info;
    if_addr* addr;

    IF_RDLOCK();
    FOR_EACH_LIST_OFFSET(&g_if_list, info, if_info, list) {
        if (ifindex && (uint32_t)info->ifindex != ifindex)
            continue;
        FOR_EACH_LIST_OFFSET(&info->addr_list, addr, if_addr, list) {
            if (if_addr_equal(addr, family, ip)) {
                IF_UNLOCK();
                return true;
            }
        }
    }
    IF_UNLOCK();
    return false;
}

if_info* if_create_virtual_loopback(void)
{
    if_info* info;

    CREATE_REF(if_info, lo, free);
    info = lo;
    if (!info)
        return NULL;

    info->ifindex = 0x1234;
    snprintf(info->name, sizeof(info->name), "loopback");
    info->flags = IFF_UP | IFF_RUNNING | IFF_LOOPBACK;
    info->mtu = 65536;
    info->l2_len = 0;   /* loopback has no L2 header */
    info->ops = &loopback_ops;
    add_list_node(&g_if_list, &info->list);
    return info;
}
