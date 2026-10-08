#ifndef IP_METRICS_H
#define IP_METRICS_H

#include <stdbool.h>
#include <stdint.h>

#include "base.h"
#include "hash.h"

/* Retransmission-timeout policy (milliseconds). */
#define IP_METRICS_RTO_MAX_MS 10000u
#define IP_METRICS_RTO_MIN_MS 1000u

/* 共享的按目的地 metrics 以 (目的地 IP, 出口 ifindex) 为 key。
 * IPv4 地址放在 dip 前 4 字节、其余补零，因此 v4/v6 共用同一个
 * 20 字节连续 key 布局（dip[16] + ifindex）。 */
typedef struct ip_metrics_key {
    uint8_t dip[16];
    uint32_t ifindex;
} ip_metrics_key;

typedef struct ip_metrics {
    ref_info ref;
    hash_node node;
    ip_metrics_key key;
    int family;
    _Atomic uint32_t rtt;
    _Atomic uint32_t last_rtt_ms;
    _Atomic uint32_t rttvar;
    _Atomic uint32_t pmtu;
    _Atomic uint64_t pmtu_updated_ms;
} ip_metrics;

/* 按地址族拆分的共享缓存（由 ip_metrics_init() 创建）。 */
extern hash *ip_metrics_hash_v4;
extern hash *ip_metrics_hash_v6;

ip_metrics *ip_metrics_get(int family, const uint8_t *dip, uint32_t ifindex);
bool ip_metrics_update_pmtu(ip_metrics *metrics, uint32_t mtu,
                            uint32_t link_mtu, uint64_t now_ms);
uint32_t ip_metrics_pmtu(const ip_metrics *metrics, uint32_t link_mtu,
                         uint64_t now_ms);

int ip_metrics_init(void);

/* RFC 6298 estimator and all RTO policy helpers. */
uint32_t ip_metrics_default_rto(void);
/* Return the smoothed RTT, including the conservative initial estimate. */
uint32_t ip_metrics_srtt(const ip_metrics *metrics);
uint32_t ip_metrics_sample(ip_metrics *metrics, uint32_t measured_rtt);
uint32_t ip_metrics_rto(const ip_metrics *metrics);
uint32_t ip_metrics_backoff(uint32_t rto);

#endif /* IP_METRICS_H */
