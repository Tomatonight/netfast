#ifndef IF_H
#define IF_H
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "list.h"
#include "base.h"

typedef struct skbuff skbuff;
typedef struct if_info if_info;

/* Address scope (mirrors Linux rtnl RT_SCOPE_*). */
#define ADDR_SCOPE_GLOBAL  0
#define ADDR_SCOPE_LINK    253
#define ADDR_SCOPE_HOST    254

typedef struct if_addr {
    list_node   list;
    sa_family_t ip_family;  /* AF_INET / AF_INET6 */
    uint32_t    ipv4;       /* v4 network byte order */
    uint8_t     ipv6[16];   /* v6 address */
    uint32_t    prefix_len; /* v4: 0-32, v6: 0-128 */
    uint8_t     scope;      /* ADDR_SCOPE_* */
    bool        primary;    /* preferred / primary address */
} if_addr;
typedef struct if_ops {
    int (*recv)(if_info* info, skbuff* skb);
    int (*send)(if_info* info, skbuff* skb);
    void (*update)(if_info* info, struct nlmsghdr *nlh);
    int (*create)(if_info* info, struct nlmsghdr *nlh);
    int (*up)(if_info* info);
    int (*down)(if_info* info);
    void (*destroy)(if_info* info);
} if_ops;

typedef struct if_info {
    int32_t ifindex;
    char name[IFNAMSIZ];
    uint8_t* l2_addr;
    uint32_t l2_len;       /* actual L2 header size (e.g. 14 for Ethernet) */
    uint32_t flags;
    uint32_t mtu;
    bool hw_tx_checksum_enabled;
    bool hw_rx_checksum_enabled;
    list_node addr_list;
    const if_ops* ops;
    void* xdp_data[32];
    list_node list;
    ref_info ref;
} if_info;


extern pthread_rwlock_t g_if_rwlock;

#define IF_RDLOCK() do { \
    pthread_rwlock_rdlock(&g_if_rwlock); \
} while (0)

#define IF_WRLOCK() do { \
    pthread_rwlock_wrlock(&g_if_rwlock); \
} while (0)

#define IF_UNLOCK() do { \
    pthread_rwlock_unlock(&g_if_rwlock); \
} while (0)

if_info* search_if_by_name(const char* name);

if_info* search_if_by_index(uint32_t ifindex);

bool if_add_addr(if_info* info, sa_family_t family, const uint8_t* ip,
                 uint32_t prefix_len, uint8_t scope, bool primary);
bool if_has_addr(if_info* info, sa_family_t family, const uint8_t* ip);
bool search_addr_exist(sa_family_t family, const uint8_t* ip, uint32_t ifindex);

int parse_link_event(struct nlmsghdr *nlh);
int parse_addr_event(struct nlmsghdr *nlh);

bool if_search_best_saddr_by_daddr(if_info* info, sa_family_t family,
                                   const uint8_t* daddr, uint8_t* saddr);

if_info* if_create_virtual_loopback(void);

#endif

