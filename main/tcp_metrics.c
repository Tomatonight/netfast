#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "tcp_metrics.h"
#include "hash.h"

hash* tcp_metrics_hash_v4;
hash* tcp_metrics_hash_v6;

/* 最后使用者释放（refcount 归零）时，释放。不可复活：
 * get 用 INC_REF_NOT_ZERO，归零条目不会再被取用，每个条目至多触发
 * 一次本函数。归零后 get 可能已在 INC_REF_NOT_ZERO 失败时把死节点
 * 摘除，因此本函数摘除前需用 node.pprev 判断是否仍链接，避免重复摘除。 */
static void tcp_metrics_free(void* opaque)
{
    tcp_metrics* metrics = (tcp_metrics*)opaque;

    hash* table = metrics->family == AF_INET
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
        sizeof(tcp_metric_key));
    tcp_metrics_hash_v6 = hash_create_safe(
        1024, HASH_KEY_OFFSET(tcp_metrics, node, key),
        sizeof(tcp_metric_key));
    if (!tcp_metrics_hash_v4 || !tcp_metrics_hash_v6)
        return -1;
    return 0;
}

tcp_metrics* tcp_metrics_get(int family, const uint8_t* dip, uint32_t ifindex)
{
    /* IPv4 只填 dip 前 4 字节，其余保持为零，保证 key 稳定。 */
    tcp_metric_key key = {0};
    key.ifindex = ifindex;
    memcpy(key.dip, dip, family == AF_INET6 ? 16u : 4u);

    hash* table = family == AF_INET6
        ? tcp_metrics_hash_v6 : tcp_metrics_hash_v4;

    uint32_t value = general_hash_algorithm(
        (const uint8_t*)&key, sizeof(key));
    uint32_t index = hash_bucket_index(table, value);

    /* 查找、取引用、新建、链接全部在桶写锁内一次完成。 */
    HASH_BUCKET_WRLOCK(table, index);

    hash_node* node = hash_find_node_locked(table, index, &key, value);
    if (node) {
        tcp_metrics* metrics =
            HASH_CONTAINER_OF(node, tcp_metrics, node);
        /* 不可复活：引用归零表示该条目正被释放（tcp_metrics_free 待
         * 执行）。INC_REF_NOT_ZERO 从 0 递增失败即视为死节点，直接在此
         * 摘除（同一桶 WRLOCK 内），让后续查找可新建同 key 条目；
         * tcp_metrics_free 会通过 node.pprev 判断是否已被摘除。 */
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
    hash_link_node_locked(table, index, &metrics->node, value);
    HASH_BUCKET_UNLOCK(table, index);
    return metrics;
}

uint32_t tcp_metrics_default_rto(void)
{
    return TCP_RTO_MIN_MS * 5u;
}

uint32_t tcp_metrics_sample(tcp_metrics* metrics, uint32_t measured_rtt)
{
    /* RFC 6298: alpha=1/8, beta=1/4, clock granularity=1 ms。
     * rtt/rttvar 为原子字段，多 worker 并发采样/读取无数据竞争；
     * 两字段非同一时刻一致（可能一旧一新），对启发式估计可接受。 */
    if ( measured_rtt == 0)
        return tcp_metrics_rto(metrics);

    uint32_t rtt = atomic_load_explicit(&metrics->rtt, memory_order_relaxed);
    if (rtt == 0) {
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

    return tcp_metrics_rto(metrics);
}

uint32_t tcp_metrics_rto(const tcp_metrics* metrics)
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
