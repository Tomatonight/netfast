#ifndef INIT_H
#define INIT_H

#include <stdbool.h>
#include <net/if.h>

#include "base.h"

#ifndef NETFAST_CONFIG_FILE
#define NETFAST_CONFIG_FILE "/usr/local/etc/netfast/netfast_config.json"
#endif

#define NETFAST_LOCAL_CONFIG_FILE "netfast_config.json"

typedef struct if_cfg {
    char name[IFNAMSIZ];
    int queues;
} if_cfg;

typedef struct g_config {
    int thread_num;

    if_cfg *ifs;
    int ifs_count;

    char logfile[256];

    bool ipv4_forward;
    bool ipv6_forward;
} g_config;

int cfg_get_if_queues(const char *ifname);

bool filter_ifname(const char *ifname);
extern g_config g_cfg;
int configure_init(void);

#endif
