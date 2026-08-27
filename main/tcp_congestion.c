#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tcp_congestion.h"
#include "tcp.h"

#define TCP_INITIAL_WINDOW         10u

#define CUBIC_BETA                 717u
#define CUBIC_BETA_SCALE           1024u
#define CUBIC_C_NUM                2u
#define CUBIC_C_DEN                5u
#define CUBIC_TCP_FRIEND_SCALE     15u
#define CUBIC_MAX_OFFSET_MS        600000u

/* CUBIC-private values are measured in packets; time values are milliseconds. */
typedef struct tcp_cubic {
    uint64_t epoch_start_ms;
    uint32_t last_max_cwnd;
    uint32_t origin_point;
    uint32_t k_ms;
    uint32_t ack_cnt;
    uint32_t tcp_cwnd;
    uint32_t cnt;
    uint32_t cwnd_cnt;
    uint32_t acked_bytes;
} tcp_cubic;

static tcp_cubic* tcp_cubic_data(tcp_pcb* pcb)
{
    return (tcp_cubic*)pcb->ca.ca_alg_data;
}

static uint32_t tcp_ca_mss(const tcp_pcb* pcb)
{
    return tcp_data_mss(pcb);
}

static void tcp_ca_set_cwnd(tcp_pcb* pcb, uint64_t cwnd)
{
    tcp_update_sndcwnd(pcb, max(cwnd, (uint64_t)tcp_ca_mss(pcb)));
}

static uint32_t tcp_cubic_cwnd_packets(const tcp_pcb* pcb)
{
    uint32_t mss = tcp_ca_mss(pcb);
    uint64_t packets = pcb->snd_cwnd / mss;
    return packets > UINT32_MAX ? UINT32_MAX
                                : max((uint32_t)packets, 1u);
}

static void tcp_cubic_set_cwnd_packets(tcp_pcb* pcb, uint64_t packets)
{
    uint32_t mss = tcp_ca_mss(pcb);
    uint64_t bytes = packets > UINT64_MAX / mss
        ? UINT64_MAX : packets * mss;
    tcp_ca_set_cwnd(pcb, bytes);
}

static uint32_t tcp_cubic_root(uint64_t value)
{
    uint32_t low = 0;
    uint32_t high = 2642245u;

    while (low < high) {
        uint32_t mid = low + (high - low + 1u) / 2u;
        if (mid <= value / mid / mid)
            low = mid;
        else
            high = mid - 1u;
    }
    return low;
}

static void tcp_cubic_reset(tcp_pcb* pcb)
{
    memset(tcp_cubic_data(pcb), 0, sizeof(tcp_cubic));
}

static uint32_t tcp_cubic_take_acked_packets(tcp_pcb* pcb,
                                              uint32_t acked_bytes)
{
    tcp_cubic* cubic = tcp_cubic_data(pcb);
    uint32_t mss = tcp_ca_mss(pcb);
    uint64_t total = (uint64_t)cubic->acked_bytes + acked_bytes;

    cubic->acked_bytes = (uint32_t)(total % mss);
    return (uint32_t)(total / mss);
}

static uint32_t tcp_cubic_slow_start(tcp_pcb* pcb, uint32_t acked)
{
    uint32_t mss = tcp_ca_mss(pcb);
    uint32_t cwnd = tcp_cubic_cwnd_packets(pcb);
    uint64_t ssthresh = pcb->snd_ssthresh / mss;
    if (ssthresh < 2u)
        ssthresh = 2u;

    if (cwnd >= ssthresh)
        return acked;

    uint64_t room = ssthresh - cwnd;
    uint32_t increase = room < acked ? (uint32_t)room : acked;
    tcp_cubic_set_cwnd_packets(pcb, (uint64_t)cwnd + increase);
    return acked - increase;
}

static uint32_t tcp_cubic_k_ms(uint32_t distance)
{
    const uint64_t scale = (uint64_t)CUBIC_C_DEN * 1000000000ull;
    uint64_t value = distance > UINT64_MAX / scale
        ? UINT64_MAX : (uint64_t)distance * scale;
    return tcp_cubic_root(value / CUBIC_C_NUM);
}

static uint32_t tcp_cubic_delta(uint64_t offset_ms)
{
    offset_ms = min(offset_ms, (uint64_t)CUBIC_MAX_OFFSET_MS);
    uint64_t cube = offset_ms * offset_ms * offset_ms;
    return (uint32_t)(CUBIC_C_NUM * cube /
        ((uint64_t)CUBIC_C_DEN * 1000000000ull));
}

static void tcp_cubic_update(tcp_pcb* pcb, uint32_t cwnd, uint32_t acked)
{
    tcp_cubic* cubic = tcp_cubic_data(pcb);
    uint64_t now = get_current_time_ms();
    cubic->ack_cnt = (uint32_t)min(
        (uint64_t)cubic->ack_cnt + acked, (uint64_t)UINT32_MAX);

    if (cubic->epoch_start_ms == 0) {
        cubic->epoch_start_ms = now ? now : 1u;
        cubic->ack_cnt = acked;
        cubic->tcp_cwnd = cwnd;
        if (cubic->last_max_cwnd <= cwnd) {
            cubic->k_ms = 0;
            cubic->origin_point = cwnd;
        } else {
            cubic->k_ms = tcp_cubic_k_ms(cubic->last_max_cwnd - cwnd);
            cubic->origin_point = cubic->last_max_cwnd;
        }
    }

    uint64_t elapsed = now >= cubic->epoch_start_ms
        ? now - cubic->epoch_start_ms : 0;
    uint64_t offset = elapsed > cubic->k_ms
        ? elapsed - cubic->k_ms : cubic->k_ms - elapsed;
    uint32_t delta = tcp_cubic_delta(offset);
    uint32_t target;
    if (elapsed < cubic->k_ms)
        target = delta >= cubic->origin_point
            ? 1u : cubic->origin_point - delta;
    else
        target = (uint32_t)min(
            (uint64_t)cubic->origin_point + delta,
            (uint64_t)UINT32_MAX);

    if (target > cwnd)
        cubic->cnt = max(cwnd / (target - cwnd), 1u);
    else
        cubic->cnt = (uint32_t)min(
            (uint64_t)100u * cwnd, (uint64_t)UINT32_MAX);

    if (cubic->last_max_cwnd == 0 && cubic->cnt > 20u)
        cubic->cnt = 20u;

    uint64_t threshold64 = ((uint64_t)cwnd * CUBIC_TCP_FRIEND_SCALE) >> 3;
    uint32_t threshold = threshold64 > UINT32_MAX
        ? UINT32_MAX : max((uint32_t)threshold64, 1u);
    if (cubic->ack_cnt > threshold) {
        uint32_t steps = (cubic->ack_cnt - 1u) / threshold;
        cubic->ack_cnt -= steps * threshold;
        cubic->tcp_cwnd = (uint32_t)min(
            (uint64_t)cubic->tcp_cwnd + steps,
            (uint64_t)UINT32_MAX);
    }
    if (cubic->tcp_cwnd > cwnd) {
        uint32_t difference = cubic->tcp_cwnd - cwnd;
        cubic->cnt = min(cubic->cnt, max(cwnd / difference, 1u));
    }

    cubic->cnt = max(cubic->cnt, 2u);
}

static void tcp_cubic_cong_avoid(tcp_pcb* pcb, uint32_t acked)
{
    if (pcb->snd_cwnd < pcb->snd_ssthresh) {
        acked = tcp_cubic_slow_start(pcb, acked);
        if (!acked)
            return;
    }

    tcp_cubic* cubic = tcp_cubic_data(pcb);
    uint32_t cwnd = tcp_cubic_cwnd_packets(pcb);
    tcp_cubic_update(pcb, cwnd, acked);

    uint64_t credits = (uint64_t)cubic->cwnd_cnt + acked;
    uint32_t increase = (uint32_t)(credits / cubic->cnt);
    cubic->cwnd_cnt = (uint32_t)(credits % cubic->cnt);
    if (increase)
        tcp_cubic_set_cwnd_packets(pcb, (uint64_t)cwnd + increase);
}

static uint64_t tcp_cubic_recalc_ssthresh(tcp_pcb* pcb)
{
    tcp_cubic* cubic = tcp_cubic_data(pcb);
    uint32_t cwnd = tcp_cubic_cwnd_packets(pcb);
    cubic->epoch_start_ms = 0;
    cubic->cwnd_cnt = 0;

    if (cwnd < cubic->last_max_cwnd) {
        cubic->last_max_cwnd = (uint32_t)(
            (uint64_t)cwnd * (CUBIC_BETA_SCALE + CUBIC_BETA) /
            (2u * CUBIC_BETA_SCALE));
    } else {
        cubic->last_max_cwnd = cwnd;
    }

    uint32_t threshold = (uint32_t)(
        (uint64_t)cwnd * CUBIC_BETA / CUBIC_BETA_SCALE);
    uint64_t bytes = (uint64_t)max(threshold, 2u) * tcp_ca_mss(pcb);
    return bytes;
}

static void tcp_ca_set_state(tcp_pcb* pcb, enum tcp_ca_status new_state)
{
    if (pcb->ca.status == new_state)
        return;
    if (pcb->ca.ops.set_state)
        pcb->ca.ops.set_state(pcb, new_state);
    pcb->ca.status = new_state;
}

static int tcp_cubic_init(tcp_pcb* pcb)
{
    pcb->ca.ca_alg_data = calloc(1, sizeof(tcp_cubic));
    return pcb->ca.ca_alg_data ? 0 : -ENOMEM;
}

static void tcp_cubic_release(tcp_pcb* pcb)
{
    free(pcb->ca.ca_alg_data);
    pcb->ca.ca_alg_data = NULL;
}

static void tcp_cubic_set_state(tcp_pcb* pcb,
                                enum tcp_ca_status new_state)
{
    if (new_state == TCP_CA_STATUS_LOST)
        tcp_cubic_reset(pcb);
}

static void tcp_cubic_mss_changed(tcp_pcb* pcb)
{
    tcp_cubic_reset(pcb);
}

static void tcp_cubic_ack_bytes(tcp_pcb* pcb, uint32_t acked_bytes,
                                bool cwnd_limited)
{
    if (pcb->ca.status != TCP_CA_STATUS_OPEN) {
        if (SEQ_GEQ(pcb->snd_una, pcb->ca.recovery_seq)) {
            tcp_ca_set_cwnd(pcb, pcb->snd_ssthresh);
            tcp_ca_set_state(pcb, TCP_CA_STATUS_OPEN);
            return;
        }

        if (pcb->ca.status == TCP_CA_STATUS_RECOVERY) {
            uint64_t mss = tcp_ca_mss(pcb);
            tcp_ca_set_cwnd(pcb, pcb->snd_ssthresh > UINT64_MAX - mss
                ? UINT64_MAX : pcb->snd_ssthresh + mss);
        }
        tcp_schedule_fast_retransmit(pcb);
        return;
    }

    if (acked_bytes && cwnd_limited) {
        uint32_t acked_pkts =
            tcp_cubic_take_acked_packets(pcb, acked_bytes);
        if (acked_pkts)
            tcp_cubic_cong_avoid(pcb, acked_pkts);
    }
}

static void tcp_cubic_rto_timeout(tcp_pcb* pcb)
{
    if (pcb->ca.status != TCP_CA_STATUS_LOST)
        pcb->ca.recovery_seq = pcb->snd_nxt;
    if (pcb->ca.status == TCP_CA_STATUS_OPEN)
        pcb->snd_ssthresh = tcp_cubic_recalc_ssthresh(pcb);
    tcp_ca_set_state(pcb, TCP_CA_STATUS_LOST);
    tcp_ca_set_cwnd(pcb, tcp_ca_mss(pcb));
}

static void tcp_cubic_recv_repeat_ack(tcp_pcb* pcb,
                                      uint32_t repeat_acks)
{
    if (repeat_acks == 3u && pcb->ca.status == TCP_CA_STATUS_OPEN) {
        pcb->snd_ssthresh = tcp_cubic_recalc_ssthresh(pcb);
        pcb->ca.recovery_seq = pcb->snd_nxt;
        tcp_ca_set_state(pcb, TCP_CA_STATUS_RECOVERY);
        uint64_t inflation = 3ull * tcp_ca_mss(pcb);
        tcp_ca_set_cwnd(pcb,
            pcb->snd_ssthresh > UINT64_MAX - inflation
                ? UINT64_MAX : pcb->snd_ssthresh + inflation);
        tcp_schedule_fast_retransmit(pcb);
        return;
    }

    if (repeat_acks > 3u && pcb->ca.status == TCP_CA_STATUS_RECOVERY) {
        uint32_t mss = tcp_ca_mss(pcb);
        tcp_ca_set_cwnd(pcb, pcb->snd_cwnd > UINT64_MAX - mss
            ? UINT64_MAX : pcb->snd_cwnd + mss);
    }
}

static const tcp_ca_ops tcp_cubic_ops = {
    .tcp_ca_init = tcp_cubic_init,
    .release = tcp_cubic_release,
    .set_state = tcp_cubic_set_state,
    .mss_changed = tcp_cubic_mss_changed,
    .ack_bytes = tcp_cubic_ack_bytes,
    .rto_timeout = tcp_cubic_rto_timeout,
    .recv_repeat_ack = tcp_cubic_recv_repeat_ack,
};

static void tcp_ca_reset_common(tcp_pcb* pcb)
{
    uint64_t initial = (uint64_t)TCP_INITIAL_WINDOW * tcp_ca_mss(pcb);
    pcb->snd_cwnd = initial;
    pcb->snd_ssthresh = UINT64_MAX;
    pcb->ca.recovery_seq = 0;
    pcb->ca.status = TCP_CA_STATUS_OPEN;
}

static bool tcp_ca_ops_valid(const tcp_ca_ops* ops)
{
    return ops && ops->tcp_ca_init && ops->ack_bytes && ops->rto_timeout &&
           ops->recv_repeat_ack;
}

static int tcp_ca_install(tcp_pcb* pcb, const tcp_ca_ops* ops)
{
    if (!tcp_ca_ops_valid(ops))
        return -EINVAL;

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

void tcp_ca_mss_changed(tcp_pcb* pcb)
{
    if (!pcb->ca.ops.tcp_ca_init ||
        (pcb->state != TCP_STATE_CLOSED &&
         pcb->state != TCP_STATE_SYN_SENT &&
         pcb->state != TCP_STATE_SYN_RECEIVED))
        return;

    tcp_ca_reset_common(pcb);
    if (pcb->ca.ops.mss_changed)
        pcb->ca.ops.mss_changed(pcb);
}

void tcp_ca_ack_bytes(tcp_pcb* pcb, uint32_t acked_bytes,
                      bool cwnd_limited)
{
    if (pcb->ca.ops.ack_bytes)
        pcb->ca.ops.ack_bytes(pcb, acked_bytes, cwnd_limited);
}

void tcp_ca_rto_timeout(tcp_pcb* pcb)
{
    if (pcb->ca.ops.rto_timeout)
        pcb->ca.ops.rto_timeout(pcb);
}

void tcp_ca_recv_repeat_ack(tcp_pcb* pcb, uint32_t repeat_acks)
{
    if (pcb->ca.ops.recv_repeat_ack)
        pcb->ca.ops.recv_repeat_ack(pcb, repeat_acks);
}
