#ifndef IP_FRAG
#define IP_FRAG

#include "ip.h"
#include "hash.h"
#include "list.h"

typedef struct skbuff skbuff;
typedef struct task task;

#define IPQ_TIMER_INTERVAL 1000u /* ms */

#define IPQ_TIMEOUT 5000u /* ms */

typedef struct ipq_key{
    uint16_t id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
}ipq_key;


typedef struct ipq{
    ipq_key key;
    hash_node hash_node;
    uint32_t total_len;       /* payload total length (bytes), not include ip header */
    uint32_t received_len;    /* received payload bytes */
    uint32_t last_update_time;
    struct {
        uint32_t last_recved:1;
        uint32_t first_recved:1;
    } flag;
    list_node frag_head;     /* ipq_frag::node */
}ipq;

bool ipv4_is_frag(const ipv4_hdr* ip);
skbuff* ipv4_defrag(skbuff* skb);
bool ipv4_frag(skbuff* skb);
void ipq_timer(task* tk);
#endif
