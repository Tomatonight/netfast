#ifndef TCP_METRICS_H
#define TCP_METRICS_H

#include <stdint.h>

#include "base.h"
#include "hash.h"

/* Retransmission-timeout policy (milliseconds). */
#define TCP_RETRANSMIT_TIMEOUT_MS_MAX 10000u
#define TCP_RTO_MIN_MS                1000u

/* 共享的按目的地 metrics 以 (目的地 IP, 出口 ifindex) 为 key。
 * IPv4 地址放在 dip 前 4 字节、其余补零，因此 v4/v6 共用同一个
 * 20 字节连续 key 布局（dip[16] + ifindex）。 */
typedef struct tcp_metric_key {
    uint8_t dip[16];
    uint32_t ifindex;
} tcp_metric_key;

typedef struct tcp_metrics {
    ref_info ref;
    hash_node node;
    tcp_metric_key key;
    int family;
    _Atomic uint32_t rtt;
    _Atomic uint32_t last_rtt_ms;
    _Atomic uint32_t rttvar;
} tcp_metrics;

/* 按地址族拆分的共享缓存（由 tcp_metrics_init() 创建）。 */
extern hash* tcp_metrics_hash_v4;
extern hash* tcp_metrics_hash_v6;

int tcp_metrics_init(void);
tcp_metrics* tcp_metrics_get(int family, const uint8_t* dip, uint32_t ifindex);

/* RFC 6298 estimator and all RTO policy helpers. */
uint32_t tcp_metrics_default_rto(void);
/* Return the smoothed RTT, including the conservative initial estimate. */
uint32_t tcp_metrics_srtt(const tcp_metrics* metrics);
uint32_t tcp_metrics_sample(tcp_metrics* metrics, uint32_t measured_rtt);
uint32_t tcp_metrics_rto(const tcp_metrics* metrics);
uint32_t tcp_metrics_backoff(uint32_t rto);

#endif
