#ifndef TCP_SACK_H
#define TCP_SACK_H

#include <stdbool.h>
#include <stdint.h>

#define TCP_OPTION_SACK_PERMITTED 4u
#define TCP_OPTION_SACK           5u
#define TCP_MAX_SACK_BLOCKS       4u

typedef struct tcp_sack_block {
    uint32_t left;
    uint32_t right;
} tcp_sack_block;

enum tcp_sack_state {
    TCP_SACKED_ACKED   = 1u << 0,
    TCP_SACKED_RETRANS = 1u << 1,
    TCP_SACKED_LOST    = 1u << 2,
};

struct skbuff;
struct tcp_hdr;
struct tcp_pcb;

void tcp_sack_receiver_update(struct tcp_pcb* pcb, uint32_t left,
                              uint32_t right);
void tcp_sack_receiver_prune(struct tcp_pcb* pcb);
uint32_t tcp_sack_option_len(const struct tcp_pcb* pcb, uint8_t flags);
uint32_t tcp_sack_write_option(struct tcp_pcb* pcb, uint8_t flags,
                               uint8_t* out, uint32_t capacity);
bool tcp_sack_process_options(struct tcp_pcb* pcb,
                              const struct tcp_hdr* hdr,
                              uint64_t* newly_sacked);
struct skbuff* tcp_sack_next_hole(struct tcp_pcb* pcb);
struct skbuff* tcp_sack_first_unsacked(struct tcp_pcb* pcb);
uint64_t tcp_sack_pipe(const struct tcp_pcb* pcb);
void tcp_sack_mark_retransmitted(struct tcp_pcb* pcb,
                                 struct skbuff* skb);
void tcp_sack_clear_scoreboard(struct tcp_pcb* pcb);
void tcp_sack_clear_skb_state(struct skbuff* skb);
void tcp_sack_reset(struct tcp_pcb* pcb);

#endif
