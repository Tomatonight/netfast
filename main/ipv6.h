#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <arpa/inet.h>

typedef struct skbuff skbuff;

#define IPV6_HDR_LEN 40

/* 扩展头类型 (RFC 8200) */
#define IPV6_NEXTHDR_HOPOPT   0
#define IPV6_NEXTHDR_ROUTING  43
#define IPV6_NEXTHDR_FRAG     44
#define IPV6_NEXTHDR_AH       51
#define IPV6_NEXTHDR_ESP      50
#define IPV6_NEXTHDR_DSTOPTS  60
#define IPV6_NEXTHDR_NONEXT   59
#define IPV6_NEXTHDR_ICMPV6   58

/* IPv6 fixed header (RFC 8200) */
typedef struct ipv6_hdr {
    uint32_t vtf;          /* version(4) | traffic class(8) | flow label(20) */
    uint16_t payload_len;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
} __attribute__((packed)) ipv6_hdr;

#define IPV6_VERSION(hdr)    ((uint8_t)((ntohl((hdr)->vtf) >> 28) & 0x0F))
#define IPV6_TRAFFIC_CLASS(hdr) ((uint8_t)((ntohl((hdr)->vtf) >> 20) & 0xFF))
#define IPV6_FLOW_LABEL(hdr) ((uint32_t)(ntohl((hdr)->vtf) & 0x000FFFFF))

static inline uint32_t ipv6_make_vtf(uint8_t tc, uint32_t flow_label)
{
    return htonl(((uint32_t)6u << 28) |
                 (((uint32_t)tc & 0xFFu) << 20) |
                 (flow_label & 0x000FFFFFu));
}

int ipv6_init(void);
int ipv6_recv(skbuff* skb);
int ipv6_output(skbuff* skb);
int ipv6_forward(skbuff* skb);

#endif /* IPV6_H */
