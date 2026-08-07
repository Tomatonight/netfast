#ifndef UDP_H
#define UDP_H
#include"socket.h"
#include "skbuff.h"
#include "thread.h"

/* UDP header (RFC 768) */
typedef struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)) udp_hdr;

/* UDP send retry backoff (follows Linux SO_SNDTIMEO / write-space pattern) */
#define UDP_SEND_RETRY_MIN_MS    1       /* initial: 1 ms */
#define UDP_SEND_RETRY_MAX_MS    10      /* maximum backoff: 10 ms */
#define UDP_SEND_RETRY_LIMIT     10      /* max consecutive retries before drop */

typedef struct udp_pcb {
    Socket* sock;
    task* send_task;
    uint32_t send_retry_interval;       /* current retry interval (ms) */
    uint32_t send_retry_count;          /* consecutive send failures */
} udp_pcb;

extern protocol_ops udp_protocol_ops;

int udp_recv(skbuff* skb);

#endif
