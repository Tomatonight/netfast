#include "tcp_rack.h"

#include "skbuff.h"
#include "tcp.h"

static bool tcp_rack_sent_after(uint64_t time_a, uint32_t end_a,
                                uint64_t time_b, uint32_t end_b)
{
    return time_a > time_b ||
           (time_a == time_b && SEQ_GT(end_a, end_b));
}

void tcp_rack_init(tcp_pcb *pcb)
{
    pcb->rack.last_send_acked_ms = 0;
    pcb->rack.last_send_acked_end_seq = 0;
    init_queue(&pcb->rack.unacked_queue);
}


void tcp_rack_queue_remove(tcp_pcb *pcb, skbuff *skb)
{
    if (!LIST_ATTACHED(&skb->rack_node))
        return;
    remove_list_node(&skb->rack_node);
    pcb->rack.unacked_queue.element_number--;
}

void tcp_rack_skb_sent(tcp_pcb *pcb, skbuff *skb, uint64_t send_ms)
{
    if (skb->l4_private.tcp.pkt_send_ms != send_ms) {
        tcp_rack_queue_remove(pcb, skb);
        skb->l4_private.tcp.pkt_send_ms = send_ms;
    }
    /* Use the common ordered insertion path for both new transmissions and
     * retransmissions.  It walks backward from the queue tail. */
    tcp_rack_update_skb(pcb, skb);
}
//add/remove from rack queue
void tcp_rack_update_skb(tcp_pcb *pcb, skbuff *skb)
{
    queue *q = &pcb->rack.unacked_queue;
    list_node *node = &skb->rack_node;
    uint8_t state = skb->l4_private.tcp.sack_state;
    uint64_t send_ms = skb->l4_private.tcp.pkt_send_ms;

    if (!send_ms) {
        tcp_rack_queue_remove(pcb, skb);
        return;
    }

    if (state & TCP_SACKED_ACKED) {
        tcp_rack_update_last_acked(pcb, skb);
        return;
    }

    if (LIST_ATTACHED(node))
        return;

    /* Detached skbs restored after SACK reneging or splitting retain old
     * timestamps and must be reinserted in (send time, seq_end) order. */
    list_node *prev = q->last.pre;
    while (prev != &q->first) {
        skbuff *queued = SKB_FROM_NODE(prev, rack_node);
        if (!tcp_rack_sent_after(
                queued->l4_private.tcp.pkt_send_ms,
                queued->l4_private.tcp.seq_end,
                send_ms,
                skb->l4_private.tcp.seq_end))
            break;
        prev = prev->pre;
    }
    add_list_node(prev, node);
    q->element_number++;
}

void tcp_rack_update_last_acked(tcp_pcb *pcb, skbuff *skb)
{
    tcp_rack_queue_remove(pcb, skb);
    uint64_t send_ms = skb->l4_private.tcp.pkt_send_ms;
    uint32_t end_seq = skb->l4_private.tcp.seq_end;
    if (send_ms > pcb->rack.last_send_acked_ms ||
        (send_ms == pcb->rack.last_send_acked_ms &&
         SEQ_GT(end_seq, pcb->rack.last_send_acked_end_seq))) {
        pcb->rack.last_send_acked_ms = send_ms;
        pcb->rack.last_send_acked_end_seq = end_seq;
        tcp_rack_update_timer(pcb);
    }
}

bool tcp_rack_skb_lost(tcp_pcb *pcb, skbuff *skb)
{
    uint64_t rtt_ms = ip_metrics_srtt(pcb->metrics);
    if (!tcp_rack_sent_after(pcb->rack.last_send_acked_ms,
                             pcb->rack.last_send_acked_end_seq,
                             skb->l4_private.tcp.pkt_send_ms,
                             skb->l4_private.tcp.seq_end))
        return false;

    uint64_t now_ms = get_current_time_ms();

    return now_ms - skb->l4_private.tcp.pkt_send_ms >=
        TCP_RACK_REO_WND_MS(rtt_ms);
}

void tcp_rack_retransmit_lost(tcp_pcb *pcb)
{
    if (!pcb->tcp_flag.peer_sack_ok)
        return;

    queue *q = &pcb->rack.unacked_queue;

    QUEUE_FOR_EACH_SAFE(q, node, next) {
        skbuff *skb = SKB_FROM_NODE(node, rack_node);
        uint8_t state = skb->l4_private.tcp.sack_state;

        if (!tcp_rack_skb_lost(pcb, skb))
            break;

        state = skb->l4_private.tcp.sack_state;
        if (!(state & TCP_SACKED_RETRANS)) {
            tcp_ca_event(pcb, TCP_CA_EVENT_LOSS);
        }
        tcp_sack_set_state(pcb, skb, state | TCP_SACKED_RETRANS | TCP_SACKED_LOST);
        tcp_retransmit_skb(pcb, skb);

    }
}

void tcp_rack_update_timer(tcp_pcb *pcb) {
    queue *q = &pcb->rack.unacked_queue;
    uint64_t deadline = TCP_TIMER_STOP;

    if (!pcb->tcp_flag.peer_sack_ok) {
        tcp_update_timer(pcb, &pcb->recovery_deadline_ms,
                         TCP_TIMER_STOP, true);
        return;
    }

    if (!q->element_number || !pcb->rack.last_send_acked_ms) {
        tcp_update_timer(pcb, &pcb->recovery_deadline_ms,
                         TCP_TIMER_STOP, true);
        return;
    }

    /* The first unacked skb has the earliest loss deadline.  If it was
     * not sent before the latest acknowledged transmission, no later
     * queue entry is eligible either.  Arm even before the deadline is
     * reached, otherwise a final SACK could leave loss detection idle. */
    skbuff *skb = SKB_FROM_NODE(q->first.next, rack_node);
    if (tcp_rack_sent_after(pcb->rack.last_send_acked_ms,
                            pcb->rack.last_send_acked_end_seq,
                            skb->l4_private.tcp.pkt_send_ms,
                            skb->l4_private.tcp.seq_end)) {
        uint64_t rtt_ms = ip_metrics_srtt(pcb->metrics);
        deadline = tcp_rack_skb_lost(pcb, skb)
            ? get_current_time_ms()
            : skb->l4_private.tcp.pkt_send_ms +
              TCP_RACK_REO_WND_MS(rtt_ms);
    }

    tcp_update_timer(pcb, &pcb->recovery_deadline_ms,
                     deadline, false);
}
/*
void tcp_rack_tlp_probe_trigger(tcp_pcb * pcb)
{
    if (pcb->snd_una == pcb->snd_nxt ||
    pcb->snd_nxt == pcb->rack.last_send_acked_end_seq)
        return;
    if (pcb->sock->send_queue.element_number) {
        tcp_update_timer(pcb,&pcb->nggle,get_current_time_ms(), false);
        return;
    }
    skbuff *last_retrasmit_skb =
    tcp_retransmit_skb(pcb, last_retrasmit_skb);
}

void tcp_rack_tlp_probe_timer_update(tcp_pcb * pcb)
{

}*/
