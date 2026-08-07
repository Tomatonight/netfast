#ifndef TCP_METRICS_H
#define TCP_METRICS_H

#include <stdint.h>

#include "base.h"

/* Retransmission-timeout policy (milliseconds). */
#define TCP_RETRANSMIT_TIMEOUT_MS_MAX 6000u
#define TCP_RTO_MIN_MS                 200u

typedef struct tcp_metrics {
    ref_info ref;
    int family;
    uint8_t dip[16];
    uint32_t ifindex;
    uint32_t rtt;
    uint32_t rttvar;
} tcp_metrics;

int tcp_metrics_init(void);
tcp_metrics* tcp_metrics_get(int family, const uint8_t* dip, uint32_t ifindex);

/* RFC 6298 estimator and all RTO policy helpers. */
uint32_t tcp_metrics_default_rto(void);
uint32_t tcp_metrics_sample(tcp_metrics* metrics, uint32_t measured_rtt);
uint32_t tcp_metrics_rto(const tcp_metrics* metrics);
uint32_t tcp_metrics_backoff(uint32_t rto);

#endif
