#ifndef INIT_H
#define INIT_H

#include <net/if.h>
#include <stdbool.h>

#include "base.h"

#ifndef NETFAST_CONFIG_FILE
#define NETFAST_CONFIG_FILE "/usr/local/etc/netfast/netfast_config.json"
#endif

#define NETFAST_LOCAL_CONFIG_FILE "netfast_config.json"

#define NETFAST_SOURCE_PORT_FIRST_DEFAULT 1024u
#define NETFAST_SOURCE_PORT_LAST_DEFAULT  32767u

typedef struct if_cfg {
    char name[IFNAMSIZ];
    int queues;
} if_cfg;

typedef struct netfast_port_range {
    uint16_t first;
    uint16_t last;
} netfast_port_range;

typedef struct g_config {
    int thread_num;

    if_cfg *ifs;
    int ifs_count;

    char logfile[256];

    netfast_port_range source_port_range;
    bool redirect_fragments;

    bool ipv4_forward;
    bool ipv6_forward;
} g_config;

int config_get_interface_queues(const char *ifname);

bool config_interface_is_filtered(const char *ifname);
extern g_config g_cfg;
int config_load(void);

#endif /* INIT_H */
