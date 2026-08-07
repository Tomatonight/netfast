#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "tcp_metrics.h"

int tcp_metrics_init(void)
{
    return 0;
}

tcp_metrics* tcp_metrics_get(int family, const uint8_t* dip, uint32_t ifindex)
{
    CREATE_REF(tcp_metrics, metrics, free);
    if (!metrics)
        return NULL;

    metrics->family = family;
    metrics->ifindex = ifindex;
    if (dip)
        memcpy(metrics->dip, dip, family == AF_INET6 ? 16u : 4u);
    return metrics;
}

uint32_t tcp_metrics_default_rto(void)
{
    return TCP_RTO_MIN_MS * 5u;
}

uint32_t tcp_metrics_sample(tcp_metrics* metrics, uint32_t measured_rtt)
{
    /* RFC 6298: alpha=1/8, beta=1/4, clock granularity=1 ms. */
    if (!metrics || measured_rtt == 0)
        return tcp_metrics_rto(metrics);

    if (metrics->rtt == 0) {
        metrics->rtt = measured_rtt;
        metrics->rttvar = measured_rtt / 2u;
    } else {
        uint32_t err = metrics->rtt > measured_rtt
            ? metrics->rtt - measured_rtt : measured_rtt - metrics->rtt;
        metrics->rttvar = (uint32_t)(((uint64_t)3u * metrics->rttvar + err) / 4u);
        metrics->rtt = (uint32_t)(((uint64_t)7u * metrics->rtt + measured_rtt) / 8u);
    }

    return tcp_metrics_rto(metrics);
}

uint32_t tcp_metrics_rto(const tcp_metrics* metrics)
{
    if (!metrics || metrics->rtt == 0)
        return tcp_metrics_default_rto();

    uint64_t rto = (uint64_t)metrics->rtt + 4ull * metrics->rttvar;
    rto = max(rto, (uint64_t)TCP_RTO_MIN_MS);
    return rto > TCP_RETRANSMIT_TIMEOUT_MS_MAX
        ? TCP_RETRANSMIT_TIMEOUT_MS_MAX : (uint32_t)rto;
}

uint32_t tcp_metrics_backoff(uint32_t rto)
{
    if (rto >= TCP_RETRANSMIT_TIMEOUT_MS_MAX / 2u)
        return TCP_RETRANSMIT_TIMEOUT_MS_MAX;
    return rto * 2u;
}
