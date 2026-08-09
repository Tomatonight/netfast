#ifndef UDP_H
#define UDP_H
#include"socket.h"
#include "skbuff.h"

/* UDP header (RFC 768) */
typedef struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)) udp_hdr;

extern protocol_ops udp_protocol_ops;

int udp_recv(skbuff* skb);

#endif
