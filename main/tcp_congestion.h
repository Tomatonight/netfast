#ifndef TCP_CONGESTION_H
#define TCP_CONGESTION_H

#include <stdbool.h>
#include <stdint.h>

struct tcp_pcb;

enum tcp_ca_status {
    TCP_CA_STATUS_OPEN,
    TCP_CA_STATUS_RECOVERY,
    TCP_CA_STATUS_LOST,
};

/*
 * A congestion-control algorithm consumes TCP events through this table.
 * tcp_ca_init/ack_bytes/rto_timeout/recv_repeat_ack are required; the remaining
 * callbacks are optional. An algorithm schedules any recovery work directly.
 */
typedef struct tcp_ca_ops {
    int (*tcp_ca_init)(struct tcp_pcb* pcb);
    void (*release)(struct tcp_pcb* pcb);
    void (*set_state)(struct tcp_pcb* pcb,
                      enum tcp_ca_status new_state);
    void (*mss_changed)(struct tcp_pcb* pcb);
    void (*ack_bytes)(struct tcp_pcb* pcb, uint32_t acked_bytes,
                      bool cwnd_limited);
    void (*rto_timeout)(struct tcp_pcb* pcb);
    void (*recv_repeat_ack)(struct tcp_pcb* pcb, uint32_t repeat_acks);
} tcp_ca_ops;

typedef struct tcp_ca {
    tcp_ca_ops ops;
    void* ca_alg_data;
    uint32_t recovery_seq;
    enum tcp_ca_status status;
} tcp_ca;

/* Install the default algorithm, or inherit only an algorithm from a parent. */
int tcp_ca_init(struct tcp_pcb* pcb);
int tcp_ca_inherit(struct tcp_pcb* child, const struct tcp_pcb* parent);
void tcp_ca_release(struct tcp_pcb* pcb);

/* Rebase packet-sized algorithm state after the effective send MSS changes. */
void tcp_ca_mss_changed(struct tcp_pcb* pcb);

/* Events reported by the TCP core. */
void tcp_ca_ack_bytes(struct tcp_pcb* pcb, uint32_t acked_bytes,
                      bool cwnd_limited);
void tcp_ca_rto_timeout(struct tcp_pcb* pcb);
void tcp_ca_recv_repeat_ack(struct tcp_pcb* pcb, uint32_t repeat_acks);

#endif
