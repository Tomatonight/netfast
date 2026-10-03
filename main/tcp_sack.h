#ifndef TCP_SACK_H
#define TCP_SACK_H

#include <stdbool.h>
#include <stdint.h>

#define TCP_OPTION_SACK_PERMITTED 4u
#define TCP_OPTION_SACK           5u
#define TCP_MAX_SACK_BLOCKS       4u

// 1收到乱序报文时更新notify sack //tcp_sack_recv_ooo_skb
// 2收到对方的sack时标记重传树中的skb,并更新peer sack //tcp_sack_process_options
// 3 rcv_nxt前进时更新notify sack,清理掉过期的block,可能加入新的block //tcp_sack_rcv_nxt_advance

// 4



typedef struct tcp_sack_block {
    uint32_t left;
    uint32_t right;
} tcp_sack_block;

enum tcp_sack_state {
    TCP_SACKED_ACKED   = 1u << 0,
    TCP_SACKED_RETRANS = 1u << 1,
    TCP_SACKED_LOST    = 1u << 2,
};

typedef struct tcp_sack{
    tcp_sack_block notify_sacks[TCP_MAX_SACK_BLOCKS];
    uint8_t notify_sack_count;

    tcp_sack_block peer_sacks[TCP_MAX_SACK_BLOCKS];
    uint8_t peer_sack_count;
    uint64_t sacked_bytes;
    uint64_t recovery_bytes;

}tcp_sack;
struct skbuff;
struct tcp_hdr;
struct tcp_pcb;
struct tcp_options;

void tcp_sack_recv_ooo_skb(struct tcp_pcb* pcb,
                              const struct skbuff* skb);
void tcp_sack_rcv_nxt_advance(struct tcp_pcb* pcb);
uint32_t tcp_sack_option_len(const struct tcp_pcb* pcb, uint8_t flags);
void tcp_sack_write_option(struct tcp_pcb* pcb, uint8_t flags,
                           uint8_t* out);
void tcp_sack_process_options(struct tcp_pcb* pcb,
                              const struct tcp_options* options);
uint64_t tcp_sack_acked_bytes(const struct tcp_pcb* pcb);
uint64_t tcp_sack_retransmited_bytes(const struct tcp_pcb* pcb);


void tcp_sack_reset(struct tcp_pcb* pcb);


void tcp_sack_set_state(struct tcp_pcb* pcb, struct skbuff* skb, uint8_t state);


#endif
