#include "tcp_metrics.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

hash *tcp_metrics_hash_v4;
hash *tcp_metrics_hash_v6;

/* 最后使用者释放（refcount 归零）时，释放。不可复活：
 * get 用 INC_REF_NOT_ZERO，归零条目不会再被取用，每个条目至多触发
 * 一次本函数。归零后 get 可能已在 INC_REF_NOT_ZERO 失败时把死节点
 * 摘除，因此本函数摘除前需用 node.pprev 判断是否仍链接，避免重复摘除。 */
static void tcp_metrics_free(void *opaque)
{
    tcp_metrics *metrics = (tcp_metrics*)opaque;

    hash *table = metrics->family == AF_INET
        ? tcp_metrics_hash_v4 : tcp_metrics_hash_v6;
    uint32_t index = hash_bucket_index(table, metrics->node.hash);

    HASH_BUCKET_WRLOCK(table, index);
    /* pprev != NULL 表示仍链接在桶中；get 摘除过的死节点这里跳过。 */
    if (metrics->node.pprev)
        hash_unlink_node_locked(&metrics->node);
    HASH_BUCKET_UNLOCK(table, index);
    free(metrics);
}

int tcp_metrics_init(void)
{
    tcp_metrics_hash_v4 = hash_create_safe(
        1024, HASH_KEY_OFFSET(tcp_metrics, node, key),
        sizeof(ip_metric_key));
    tcp_metrics_hash_v6 = hash_create_safe(
        1024, HASH_KEY_OFFSET(tcp_metrics, node, key),
        sizeof(ip_metric_key));
    if (!tcp_metrics_hash_v4 || !tcp_metrics_hash_v6)
        return -1;
    return 0;
}

ip_metrics *ip_metrics_get(int family, const uint8_t *dip, uint32_t ifindex)
{
    /* IPv4 只填 dip 前 4 字节，其余保持为零，保证 key 稳定。 */
    ip_metric_key key = {0};
    key.ifindex = ifindex;
    memcpy(key.dip, dip, family == AF_INET6 ? 16u : 4u);

    hash *table = family == AF_INET6
        ? tcp_metrics_hash_v6 : tcp_metrics_hash_v4;

    uint32_t value = general_hash_algorithm(
        (const uint8_t*)&key, sizeof(key));
    uint32_t index = hash_bucket_index(table, value);

    /* 查找、取引用、新建、链接全部在桶写锁内一次完成。 */
    HASH_BUCKET_WRLOCK(table, index);

    hash_node *node = hash_find_node_locked(table, index, &key, value);
    if (node) {
        tcp_metrics *metrics =
            HASH_CONTAINER_OF(node, tcp_metrics, node);
        if (INC_REF_NOT_ZERO(metrics)) {
            HASH_BUCKET_UNLOCK(table, index);
            return metrics;
        }
        hash_unlink_node_locked(&metrics->node);
    }

    CREATE_REF(tcp_metrics, metrics, tcp_metrics_free);
    if (!metrics) {
        HASH_BUCKET_UNLOCK(table, index);
        return NULL;
    }
    metrics->family = family;
    metrics->key = key;
    /* Use the minimum RTO as the conservative initial RTT. */
    atomic_init(&metrics->rtt, TCP_RTO_MIN_MS);
    atomic_init(&metrics->last_rtt_ms, 0);
    atomic_init(&metrics->rttvar, 0);
    atomic_init(&metrics->pmtu, 0);
    atomic_init(&metrics->pmtu_updated_ms, 0);
    hash_link_node_locked(table, index, &metrics->node, value);
    HASH_BUCKET_UNLOCK(table, index);
    return metrics;
}

bool ip_metrics_update_pmtu(ip_metrics *metrics, uint32_t mtu,
                            uint32_t link_mtu, uint64_t now_ms)
{
    if (!mtu || !link_mtu || mtu >= link_mtu)
        return false;
    if ((metrics->family == AF_INET && mtu < 68u) ||
        (metrics->family == AF_INET6 && mtu < 1280u))
        return false;

    uint32_t old = atomic_load_explicit(&metrics->pmtu,
                                        memory_order_acquire);
    while (old == 0 || mtu < old) {
        if (atomic_compare_exchange_weak_explicit(
                &metrics->pmtu, &old, mtu,
                memory_order_acq_rel, memory_order_acquire)) {
            atomic_store_explicit(&metrics->pmtu_updated_ms, now_ms,
                                  memory_order_release);
            return true;
        }
    }
    return false;
}

uint32_t ip_metrics_pmtu(const ip_metrics *metrics, uint32_t link_mtu,
                         uint64_t now_ms)
{
    if (!link_mtu)
        return link_mtu;
    uint32_t pmtu = atomic_load_explicit(&metrics->pmtu,
                                         memory_order_acquire);
    uint64_t updated = atomic_load_explicit(&metrics->pmtu_updated_ms,
                                            memory_order_acquire);
    /* RFC 1191 recommends probing for increases no more often than every
     * five minutes; use ten minutes as the cache lifetime. */
    if (!pmtu || (uint64_t)now_ms - updated >= 10u * 60u * 1000u)
        return link_mtu;
    return min(pmtu, link_mtu);
}

uint32_t tcp_metrics_default_rto(void)
{
    return TCP_RTO_MIN_MS;
}

uint32_t tcp_metrics_srtt(const tcp_metrics *metrics)
{
    return atomic_load_explicit(&metrics->rtt, memory_order_relaxed);
}

uint32_t tcp_metrics_sample(tcp_metrics *metrics, uint32_t measured_rtt)
{
    /* RFC 6298: alpha=1/8, beta=1/4, clock granularity=1 ms。
     * RTT 字段均为原子字段，多 worker 并发采样/读取无数据竞争；
     * 各字段非同一时刻一致（可能一旧一新），对启发式估计可接受。 */
    if ( measured_rtt == 0)
        return tcp_metrics_rto(metrics);

    uint32_t last_rtt = atomic_load_explicit(&metrics->last_rtt_ms,
                                             memory_order_relaxed);
    uint32_t rtt = atomic_load_explicit(&metrics->rtt, memory_order_relaxed);
    if (!last_rtt) {
        atomic_store_explicit(&metrics->rtt, measured_rtt,
                              memory_order_relaxed);
        atomic_store_explicit(&metrics->rttvar, measured_rtt / 2u,
                              memory_order_relaxed);
    } else {
        uint32_t rttvar = atomic_load_explicit(
            &metrics->rttvar, memory_order_relaxed);
        uint32_t err = rtt > measured_rtt
            ? rtt - measured_rtt : measured_rtt - rtt;
        atomic_store_explicit(&metrics->rttvar,
            (uint32_t)(((uint64_t)3u * rttvar + err) / 4u),
            memory_order_relaxed);
        atomic_store_explicit(&metrics->rtt,
            (uint32_t)(((uint64_t)7u * rtt + measured_rtt) / 8u),
            memory_order_relaxed);
    }
    atomic_store_explicit(&metrics->last_rtt_ms, measured_rtt,
                          memory_order_relaxed);

    return tcp_metrics_rto(metrics);
}

uint32_t tcp_metrics_rto(const tcp_metrics *metrics)
{

    /* 无锁：rtt/rttvar 是原子字段，直接读取即可。 */
    uint32_t rtt = atomic_load_explicit(&metrics->rtt, memory_order_relaxed);
    uint32_t rttvar = atomic_load_explicit(
        &metrics->rttvar, memory_order_relaxed);
    if (rtt == 0)
        return tcp_metrics_default_rto();

    uint64_t rto = (uint64_t)rtt + 4ull * rttvar;
    rto = max(rto, (uint64_t)TCP_RTO_MIN_MS);
    return rto > TCP_RETRANSMIT_TIMEOUT_MS_MAX
        ? TCP_RETRANSMIT_TIMEOUT_MS_MAX : (uint32_t)rto;
}

uint32_t tcp_metrics_backoff(uint32_t rto)
{
    return min(rto * 2u, TCP_RETRANSMIT_TIMEOUT_MS_MAX);
}
