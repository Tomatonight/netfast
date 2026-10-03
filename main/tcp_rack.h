#ifndef TCP_RACK_H
#define TCP_RACK_H

#include <stdbool.h>
#include <stdint.h>

#include "queue.h"

#define TCP_RACK_REO_WND_MS(rtt_ms) \
    ((uint64_t)(rtt_ms) + (uint64_t)(rtt_ms) / 4u)

struct tcp_pcb;
struct skbuff;

//

typedef struct tcp_rack {
    uint64_t last_send_acked_ms;/*确认的最后发送的数据, 这个时间之前的数据都在rack 判断之内 */
    uint32_t last_send_acked_end_seq;
    
    /* Unacked transmissions ordered by (pkt_send_ms, seq_end).
     * The head determines the earliest RACK loss deadline. */
    queue unacked_queue;
} tcp_rack;

/* 仅在连接初始化时调用；队列节点随原 skb 在释放前摘除。 */
void tcp_rack_init(struct tcp_pcb* pcb);
//更新发送时间
void tcp_rack_skb_sent(struct tcp_pcb* pcb, struct skbuff* skb,
                         uint64_t send_ms);
//从rack queue中移除
void tcp_rack_queue_remove(struct tcp_pcb* pcb, struct skbuff* skb);

void tcp_rack_update_skb(struct tcp_pcb* pcb, struct skbuff* skb);


void tcp_rack_update_last_acked(struct tcp_pcb* pcb,
                                struct skbuff* skb);
bool tcp_rack_skb_lost(struct tcp_pcb* pcb, struct skbuff* skb);

void tcp_rack_retransmit_lost(struct tcp_pcb* pcb);
void tcp_rack_update_timer(struct tcp_pcb* pcb);

//void tcp_rack_tlp_probe_trigger(struct tcp_pcb* pcb);
//void tcp_rack_tlp_probe_timer_update(struct tcp_pcb* pcb);
#endif
