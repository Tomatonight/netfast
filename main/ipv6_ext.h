#ifndef IPV6_EXT_H
#define IPV6_EXT_H

#include <stdbool.h>
#include <string.h>

#include "ipv6.h"
#include "list.h"

typedef struct skbuff skbuff;
typedef struct task task;

#define MAX_IP6_HDR_WITH_EXT_LEN 64

#define IPQ6_TIMER_INTERVAL 1000u  /* ms */
#define IPQ6_TIMEOUT        5000u  /* ms */

/* ── Fragment Extension Header (RFC 8200 §4.5) ──────────── */
typedef struct ipv6_frag_hdr {
    uint8_t  next_hdr;
    uint8_t  reserved;
    uint16_t frag_off;   /* offset(13) | res(2) | M(1), network order */
    uint32_t id;         /* 32-bit Identification */
} __attribute__((packed)) ipv6_frag_hdr;

#define IPV6_FRAG_OFFSET_MASK  0xFFF8u
#define IPV6_FRAG_MF_MASK      0x0001u

static inline void ipv6_frag_set(ipv6_frag_hdr* fh, uint16_t offset8, bool mf)
{
    uint16_t v = (offset8 << 3) & IPV6_FRAG_OFFSET_MASK;
    if (mf)
        v |= IPV6_FRAG_MF_MASK;
    v = htons(v);
    memcpy(&fh->frag_off, &v, sizeof(v));
}

/* ── 重组队列 key ──────────────────────────────────────── */
typedef struct ipq6_key {
    uint32_t id;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
} ipq6_key;

/* ── 重组队列 ──────────────────────────────────────────── */
typedef struct ipq6 {
    ipq6_key key;
    uint32_t total_len;        /* payload total length (excluding all headers) */
    uint32_t received_len;     /* received payload bytes */
    uint32_t last_update_time;
    uint16_t unfrag_len;
    uint8_t next_header;
    struct {
        uint32_t last_recved  : 1;
        uint32_t first_recved : 1;
    } flag;
    list_node frag_head;       /* ipq6_frag::node */
} ipq6;

/* ── 分片链节点（挂载在 ipq6::frag_head 上）────────────── */
typedef struct ipq6_frag {
    skbuff*   skb;
    uint32_t  offset;    /* 8-byte units */
    uint32_t  len;       /* payload bytes */
    list_node node;
} ipq6_frag;

/* ── 接口 ──────────────────────────────────────────────── */
bool    ipv6_has_frag(const skbuff* skb);
skbuff* ipv6_defrag(skbuff* skb);
bool    ipv6_frag(skbuff* skb);
void    ipq6_timer(task* tk);

#endif /* IPV6_EXT_H */
