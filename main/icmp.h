#ifndef ICMP_H
#define ICMP_H

#include <stdbool.h>
#include <stdint.h>

typedef struct skbuff skbuff;

typedef struct icmp_error_info {
    int family;
    uint8_t protocol;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tcp_seq;
    uint32_t mtu;
    bool has_tcp_seq;
} icmp_error_info;

/* ICMPv4 (RFC 792)
 * Only the minimal header is defined here.
 */

typedef struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t unused;
            uint16_t mtu;
        } frag;
        uint32_t unused32;
    } un;
    /* Followed by data (often: original IP header + 8 bytes) */
} __attribute__((packed)) icmp_hdr;

/* ICMP types */
#define ICMP_ECHOREPLY        0
#define ICMP_DEST_UNREACH     3
#define ICMP_REDIRECT         5
#define ICMP_ECHO             8
#define ICMP_TIME_EXCEEDED    11
#define ICMP_PARAMETERPROB    12

/* ICMP_DEST_UNREACH codes (subset) */
#define ICMP_NET_UNREACH      0
#define ICMP_HOST_UNREACH     1
#define ICMP_PROT_UNREACH     2
#define ICMP_PORT_UNREACH     3

/* ICMPv6 error types and Destination Unreachable codes (RFC 4443). */
#define ICMP6_DEST_UNREACH          1
#define ICMP6_PACKET_TOO_BIG        2
#define ICMP6_TIME_EXCEEDED         3
#define ICMP6_PARAMETER_PROBLEM     4

#define ICMP6_NO_ROUTE              0
#define ICMP6_ADMIN_PROHIBITED      1
#define ICMP6_BEYOND_SCOPE          2
#define ICMP6_ADDR_UNREACH          3
#define ICMP6_PORT_UNREACH          4
#define ICMP6_POLICY_FAIL           5
#define ICMP6_REJECT_ROUTE          6

int icmp_recv(skbuff* skb);
int icmp6_recv(skbuff* skb);
int icmp_send_dest_unreach(skbuff* orig_skb, uint8_t code);

#endif /* ICMP_H */
