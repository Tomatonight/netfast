#ifndef XDP_REDIRECT_CONFIG_H
#define XDP_REDIRECT_CONFIG_H

#include <linux/types.h>

#define NETFAST_XDP_CONFIG_MAP_NAME "netfast_cfg"
#define NETFAST_XDP_CONFIG_KEY 0u

typedef struct netfast_xdp_config {
    __u16 source_port_first;
    __u16 source_port_last;
    __u8 redirect_fragments;
    __u8 reserved[3];
} netfast_xdp_config;

#endif
