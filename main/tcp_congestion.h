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

enum tcp_ca_event {
    TCP_CA_EVENT_DUP_ACK,
    TCP_CA_EVENT_LOSS,
    TCP_CA_EVENT_ECN,
};

typedef struct tcp_ca_ops {
    int (*tcp_ca_init)(struct tcp_pcb* pcb);
    void (*release)(struct tcp_pcb* pcb);
    void (*set_state)(struct tcp_pcb* pcb,
                      enum tcp_ca_status new_state);
    void (*ack_bytes)(struct tcp_pcb* pcb, uint32_t acked_bytes);
    void (*rto_timeout)(struct tcp_pcb* pcb);
    void (*event)(struct tcp_pcb* pcb, enum tcp_ca_event event);
} tcp_ca_ops;

typedef struct tcp_ca {
    tcp_ca_ops ops;
    void* private;
    uint32_t recovery_seq;
    enum tcp_ca_status status;
} tcp_ca;


int tcp_ca_init(struct tcp_pcb* pcb);
int tcp_ca_inherit(struct tcp_pcb* child, const struct tcp_pcb* parent);
void tcp_ca_release(struct tcp_pcb* pcb);
/* Enter RECOVERY before reducing cwnd so the callback can record Wmax. */
void tcp_ca_set_state(struct tcp_pcb* pcb, enum tcp_ca_status new_state);

/* Events reported by the TCP core. */
void tcp_ca_ack_bytes(struct tcp_pcb* pcb, uint32_t acked_bytes);
void tcp_ca_mss_changed(struct tcp_pcb* pcb);
void tcp_ca_rto_timeout(struct tcp_pcb* pcb);
void tcp_ca_event(struct tcp_pcb* pcb, enum tcp_ca_event event);

#endif
