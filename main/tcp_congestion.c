#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tcp_congestion.h"
#include "tcp.h"

#define TCP_INITIAL_CWND         5u
#define TCP_ABC_MAX_SEGMENTS     1u


/* CUBIC-private values are measured in packets; time values are milliseconds. */
typedef struct tcp_cubic {
    uint64_t start_epoch_ms;
    double wmax;
    uint64_t reach_wmax_ms;
    double start_cwnd;
    double w_reno;
    double cwnd_prior; /* Window before the most recent reduction, in packets. */
    double cwnd_fraction; /* Fractional bytes accumulated in the CUBIC region. */

} tcp_cubic;
/* t and reach_wmax_ms (K) are milliseconds relative to start_epoch_ms.
 * Keep fractional packets until converting the target to bytes. */
static inline double tcp_cubic_wt(const tcp_cubic* cubic, uint64_t t)
{
    double offset_ms = t >= cubic->reach_wmax_ms
        ? (double)(t - cubic->reach_wmax_ms)
        : -(double)(cubic->reach_wmax_ms - t);
    double offset_s = offset_ms / 1000.0;
    double wt = 0.4 * offset_s * offset_s * offset_s + cubic->wmax;
    return wt > 0.0 ? wt : 0.0;
}

/* Return the next-RTT target in bytes, bounded by [cwnd, 1.5 * cwnd]. */
static inline uint64_t tcp_cubic_cwnd(const tcp_pcb* pcb,
                                     const tcp_cubic* cubic, uint64_t t)
{
    uint32_t rtt_ms = pcb->metrics ? pcb->metrics->rtt : 0;
    uint64_t next_rtt = t > UINT64_MAX - rtt_ms ? UINT64_MAX : t + rtt_ms;
    double wt_rtt = tcp_cubic_wt(cubic, next_rtt) * pcb->snd_mss;
    uint64_t cwnd = pcb->snd_cwnd;
    uint64_t upper = cwnd > UINT64_MAX - cwnd / 2
        ? UINT64_MAX : cwnd + cwnd / 2;

    if (wt_rtt <= (double)cwnd)
        return cwnd;
    if (wt_rtt >= (double)upper)
        return upper;
    return (uint64_t)wt_rtt;
}
void tcp_ca_set_state(tcp_pcb* pcb, enum tcp_ca_status new_state)
{
    if (pcb->ca.status == new_state)
        return;
    /* The callback observes the old state and, on recovery entry, the
     * window before reduction. The caller reduces the window afterwards. */
    if (pcb->ca.ops.set_state)
        pcb->ca.ops.set_state(pcb, new_state);
    pcb->ca.status = new_state;
}

static int tcp_cubic_init(tcp_pcb* pcb)
{
    pcb->ca.private = calloc(1, sizeof(tcp_cubic));
    return pcb->ca.private ? 0 : -ENOMEM;
}

static void tcp_cubic_release(tcp_pcb* pcb)
{
    free(pcb->ca.private);
    pcb->ca.private = NULL;
}

static void tcp_cubic_set_state(tcp_pcb* pcb,
                                enum tcp_ca_status new_state)
{
    tcp_cubic* cubic = (tcp_cubic*)pcb->ca.private;

    switch (new_state) {
    case TCP_CA_STATUS_RECOVERY:
        if (pcb->ca.status == TCP_CA_STATUS_OPEN && pcb->snd_mss) {
            double cwnd = (double)pcb->snd_cwnd / pcb->snd_mss;
            cubic->cwnd_prior = cwnd;
            /* Fast convergence: reduce the remembered plateau when the
             * current window is already below the previous plateau. */
            cubic->wmax = cubic->wmax > cwnd
                ? cwnd * (1.0 + 0.7) / 2.0 : cwnd;
        }
        break;
    case TCP_CA_STATUS_LOST:
        /* After RTO, ACK processing starts a new curve with K == 0. */
        cubic->wmax = 0;
        cubic->cwnd_prior = 0;
        break;
    case TCP_CA_STATUS_OPEN:
        /* Keep the recovery Wmax; the next ACK initializes a new epoch
         * from the post-recovery window, excluding time spent recovering. */
        break;
    }

    cubic->start_epoch_ms = 0;
    cubic->start_cwnd = 0;
    cubic->reach_wmax_ms = 0;
    cubic->w_reno = 0;
    cubic->cwnd_fraction = 0;
}

static void tcp_cubic_ack_bytes(tcp_pcb* pcb, uint32_t acked_bytes)
{
    tcp_cubic* cubic = (tcp_cubic*)pcb->ca.private;

    bool rto_recovery = pcb->ca.status == TCP_CA_STATUS_LOST;
    if (pcb->ca.status == TCP_CA_STATUS_RECOVERY) {
        if (SEQ_GEQ(pcb->snd_una, pcb->ca.recovery_seq)) {
            tcp_update_sndcwnd(pcb, pcb->snd_ssthresh);
            tcp_ca_set_state(pcb, TCP_CA_STATUS_OPEN);
            pcb->ca.recovery_seq = 0;
        } else if (!pcb->tcp_flag.peer_sack_ok && acked_bytes) {
            /* NewReno partial ACK: remove acknowledged bytes from the
             * inflated window, then credit one segment when appropriate. */
            uint64_t cwnd = pcb->snd_cwnd -
                min(pcb->snd_cwnd, (uint64_t)acked_bytes);
            if (acked_bytes >= pcb->snd_mss)
                cwnd += pcb->snd_mss;
            tcp_update_sndcwnd(pcb, max(cwnd, (uint64_t)pcb->snd_mss));
        }
        /* ACKs covering recovery data do not also earn normal CA growth. */
        return;
    }
    if (pcb->ca.status == TCP_CA_STATUS_LOST &&
        SEQ_GEQ(pcb->snd_una, pcb->ca.recovery_seq)) {
        tcp_ca_set_state(pcb, TCP_CA_STATUS_OPEN);
        pcb->ca.recovery_seq = 0;
    }
    if (!acked_bytes)
        return;

    /* ACK processing has already advanced snd_una. Reconstruct the sent
     * sequence space before this ACK; unsent queued data is not flight. */
    uint64_t flight_before_ack =
        (uint64_t)(uint32_t)(pcb->snd_nxt - pcb->snd_una) + acked_bytes;
    if (flight_before_ack + pcb->snd_mss < pcb->snd_cwnd) {
        cubic->start_cwnd = 0;
        cubic->cwnd_fraction = 0;
        return;
    }
/*
慢启动
当 cwnd < ssthresh：
increase = min(acked_bytes, ssthresh - cwnd);
cwnd += increase;
acked_bytes -= increase;
新确认多少字节，就增加多少字节，最多增长到阈值。如果这次 ACK 还有剩余确认字节，继续用于拥塞避免。


*/
    /* Appropriate Byte Counting: cap one ACK's growth credit so a stretch
     * ACK cannot increase the window by an arbitrary amount. The standards
     * track Reno slow-start behavior uses L=1*SMSS; RFC 3465's L=2*SMSS
     * mode is experimental. */
    uint64_t abc_segments = rto_recovery ? 1u : TCP_ABC_MAX_SEGMENTS;
    uint64_t abc_limit = abc_segments * pcb->snd_mss;
    if ((uint64_t)acked_bytes > abc_limit)
        acked_bytes = abc_limit > UINT32_MAX
            ? UINT32_MAX : (uint32_t)abc_limit;

    if (pcb->snd_cwnd < pcb->snd_ssthresh) {
        uint64_t increase = min((uint64_t)acked_bytes,
                               pcb->snd_ssthresh - pcb->snd_cwnd);
        tcp_update_sndcwnd(pcb, pcb->snd_cwnd + increase);
        acked_bytes -= (uint32_t)increase;
        cubic->start_cwnd = 0;
        cubic->cwnd_fraction = 0;
        if (!acked_bytes)
        {
            return;
        }
    }
/*
初始化本轮曲线
start_cwnd == 0 表示尚未开始本轮 epoch。记录开始时间和窗口，并初始化 w_reno。
如果历史 Wmax 大于当前窗口：

这样曲线满足 W(0) = W_start。
否则使用当前窗口作为 Wmax，令 K=0。这里窗口以 MSS 数计算，保存的 K 为毫秒。
*/
    /* During RTO recovery, ACKs permit slow start up to ssthresh, but
     * congestion avoidance waits until all pre-RTO data is acknowledged. */
    if (pcb->ca.status != TCP_CA_STATUS_OPEN)
        return;
    uint64_t now_ms = get_current_time_ms();
    double cwnd_packets = (double)pcb->snd_cwnd / pcb->snd_mss;
    /* start_cwnd == 0 denotes an uninitialized epoch, including time zero. */
    if (!cubic->start_cwnd) {
        cubic->start_epoch_ms = now_ms;
        cubic->start_cwnd = cwnd_packets;
        cubic->w_reno = cwnd_packets;
        if (!cubic->cwnd_prior)
            cubic->cwnd_prior = cwnd_packets;
        cubic->cwnd_fraction = 0;
        if (cubic->wmax > cwnd_packets) {
            cubic->reach_wmax_ms = (uint64_t)(1000.0 *
                cbrt((cubic->wmax - cwnd_packets) / 0.4));
        } else {
            cubic->wmax = cwnd_packets;
            cubic->reach_wmax_ms = 0;
        }
    }
/*
1. 更新 Reno 友好窗口
   alpha = 3 * (1 - 0.7) / (1 + 0.7); // 约 0.529
   w_reno += alpha * acked_bytes / cwnd;
   w_reno 单位是报文数，acked_bytes / cwnd 是本次 ACK 确认了多少比例的窗口。
   如果当前曲线值 W(t) < w_reno，采用 Reno 估算值乘以 MSS 更新窗口；只允许增大。
2. 否则使用 CUBIC 增长
   先计算一个 RTT 之后的目标：
   target = clamp(W(t + RTT) * MSS, cwnd, 1.5 * cwnd);
   再按本次确认的窗口比例，向目标增长：
   increase = (target - cwnd) * acked_bytes / cwnd;
   例如 cwnd=100000、target=120000、确认 1000 字节，本次增加：
   (120000 - 100000) × 1000 / 100000 = 200 字节
   不足一字节的部分保存在 cwnd_fraction，累计到整数后再更新窗口。
所有实际窗口更新都通过 tcp_update_sndcwnd()，同时更新发送调度。

*/
    uint64_t elapsed_ms = now_ms - cubic->start_epoch_ms;
    double alpha = cubic->w_reno >= cubic->cwnd_prior
        ? 1.0 : 3.0 * (1.0 - 0.7) / (1.0 + 0.7);
    cubic->w_reno += alpha * (double)acked_bytes / pcb->snd_cwnd;

    if (tcp_cubic_wt(cubic, elapsed_ms) < cubic->w_reno) {
        double estimate = cubic->w_reno * pcb->snd_mss;
        uint64_t reno_bytes = estimate >= (double)UINT64_MAX
            ? UINT64_MAX : (uint64_t)estimate;
        if (reno_bytes > pcb->snd_cwnd) {
            cubic->cwnd_fraction = 0;
            tcp_update_sndcwnd(pcb, reno_bytes);
        }
        return;
    }

    uint64_t target = tcp_cubic_cwnd(pcb, cubic, elapsed_ms);
    cubic->cwnd_fraction += (double)(target - pcb->snd_cwnd) *
        acked_bytes / pcb->snd_cwnd;
    uint64_t increase = (uint64_t)cubic->cwnd_fraction;
    cubic->cwnd_fraction -= increase;
    if (increase)
        tcp_update_sndcwnd(pcb, pcb->snd_cwnd +
            min(increase, UINT64_MAX - pcb->snd_cwnd));
}

static void tcp_cubic_rto_timeout(tcp_pcb* pcb)
{
    uint64_t flight_size = tcp_flight_size(pcb);
    uint64_t ssthresh = (flight_size / 10) * 7 +
        (flight_size % 10) * 7 / 10;
    if (pcb->ca.status != TCP_CA_STATUS_LOST)
        pcb->snd_ssthresh = max(ssthresh, 2ull * pcb->snd_mss);
    pcb->ca.recovery_seq = pcb->snd_nxt;
    tcp_ca_set_state(pcb, TCP_CA_STATUS_LOST);
    tcp_update_sndcwnd(pcb, pcb->snd_mss);
}

static void tcp_cubic_event(tcp_pcb* pcb, enum tcp_ca_event event)
{
    switch (event) {
    case TCP_CA_EVENT_LOSS: {
        if (pcb->ca.status != TCP_CA_STATUS_OPEN ||
            pcb->snd_una == pcb->snd_nxt)
            return;

        uint64_t flight_size = tcp_flight_size(pcb);
        pcb->ca.recovery_seq = pcb->snd_nxt;
        tcp_ca_set_state(pcb, TCP_CA_STATUS_RECOVERY);
        uint64_t reduced = (flight_size / 10) * 7 +
            (flight_size % 10) * 7 / 10;
        pcb->snd_ssthresh = max(reduced,
                               2ull * pcb->snd_mss);
        uint64_t cwnd = pcb->snd_ssthresh;
        /* SACK already credits delivered data in the send allowance. */
        if (!pcb->tcp_flag.peer_sack_ok)
            cwnd += 3ull * pcb->snd_mss;
        tcp_update_sndcwnd(pcb, cwnd);
        break;
    }
    case TCP_CA_EVENT_DUP_ACK: {
        if (pcb->ca.status != TCP_CA_STATUS_RECOVERY ||
            pcb->tcp_flag.peer_sack_ok)
            return;

        /* Limit duplicate-ACK inflation to the outstanding sequence space. */
        uint64_t ceiling = pcb->snd_ssthresh +
            (uint32_t)(pcb->snd_nxt - pcb->snd_una);
        if (pcb->snd_cwnd < ceiling)
            tcp_update_sndcwnd(pcb, pcb->snd_cwnd +
                min((uint64_t)pcb->snd_mss, ceiling - pcb->snd_cwnd));
        break;
    }
    case TCP_CA_EVENT_ECN: {
        /* ECN reports congestion without loss, so reduce the CUBIC window
         * but leave retransmission state untouched. */
        if (pcb->ca.status != TCP_CA_STATUS_OPEN ||
            pcb->snd_una == pcb->snd_nxt)
            return;

        uint64_t flight_size = tcp_flight_size(pcb);
        uint64_t reduced = (flight_size / 10) * 7 +
            (flight_size % 10) * 7 / 10;
        pcb->snd_ssthresh = max(reduced, 2ull * pcb->snd_mss);
        pcb->ca.recovery_seq = pcb->snd_nxt;
        tcp_ca_set_state(pcb, TCP_CA_STATUS_RECOVERY);
        tcp_update_sndcwnd(pcb, min(pcb->snd_cwnd, pcb->snd_ssthresh));
        break;
    }
    }
}

static const tcp_ca_ops tcp_cubic_ops = {
    .tcp_ca_init = tcp_cubic_init,
    .release = tcp_cubic_release,
    .set_state = tcp_cubic_set_state,
    .ack_bytes = tcp_cubic_ack_bytes,
    .rto_timeout = tcp_cubic_rto_timeout,
    .event = tcp_cubic_event,
};

static void tcp_ca_reset_common(tcp_pcb* pcb)
{
    uint64_t initial = (uint64_t)TCP_INITIAL_CWND * pcb->snd_mss;
    pcb->snd_cwnd = initial;
    pcb->snd_ssthresh = UINT64_MAX;
    pcb->ca.recovery_seq = 0;
    pcb->ca.status = TCP_CA_STATUS_OPEN;
}



static int tcp_ca_install(tcp_pcb* pcb, const tcp_ca_ops* ops)
{
    tcp_ca_ops selected = *ops;
    tcp_ca_release(pcb);
    pcb->ca.ops = selected;
    tcp_ca_reset_common(pcb);

    int ret = pcb->ca.ops.tcp_ca_init(pcb);
    if (ret < 0) {
        if (pcb->ca.ops.release)
            pcb->ca.ops.release(pcb);
        memset(&pcb->ca, 0, sizeof(pcb->ca));
        return ret;
    }
    return 0;
}

int tcp_ca_init(tcp_pcb* pcb)
{
    return tcp_ca_install(pcb, &tcp_cubic_ops);
}

int tcp_ca_inherit(tcp_pcb* child, const tcp_pcb* parent)
{
    return tcp_ca_install(child, &parent->ca.ops);
}

void tcp_ca_release(tcp_pcb* pcb)
{
    if (pcb->ca.ops.tcp_ca_init && pcb->ca.ops.release)
        pcb->ca.ops.release(pcb);
    memset(&pcb->ca, 0, sizeof(pcb->ca));
}

void tcp_ca_ack_bytes(tcp_pcb* pcb, uint32_t acked_bytes)
{
    if (pcb->ca.ops.ack_bytes)
        pcb->ca.ops.ack_bytes(pcb, acked_bytes);
}

void tcp_ca_mss_changed(tcp_pcb* pcb)
{
    if(pcb->snd_cwnd < (uint64_t)TCP_INITIAL_CWND * pcb->snd_mss)
        tcp_update_sndcwnd(pcb,
                           (uint64_t)TCP_INITIAL_CWND * pcb->snd_mss);
}

void tcp_ca_rto_timeout(tcp_pcb* pcb)
{
    if (pcb->ca.ops.rto_timeout)
        pcb->ca.ops.rto_timeout(pcb);
}

void tcp_ca_event(tcp_pcb* pcb, enum tcp_ca_event event)
{
    if (pcb->ca.ops.event)
        pcb->ca.ops.event(pcb, event);
}
