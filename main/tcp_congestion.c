#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "tcp.h"

/* Linux tcp_cubic.c defaults.  Window values inside the CUBIC state are in
 * packets; tcp_pcb::snd_cwnd remains in bytes for NetFast's sequence checks. */
#define CUBIC_INITIAL_WINDOW       10u
#define CUBIC_BETA                 717u
#define CUBIC_BETA_SCALE           1024u
#define CUBIC_C_NUM                2u     /* C = 2 / 5 = 0.4 */
#define CUBIC_C_DEN                5u
#define CUBIC_TCP_FRIEND_SCALE     15u
#define CUBIC_MAX_OFFSET_MS        600000u

static uint32_t tcp_ca_mss(const tcp_pcb* pcb)
{
    return pcb->snd_mss ? pcb->snd_mss : 1u;
}

static uint32_t tcp_ca_saturating_add(uint32_t value, uint64_t increment)
{
    uint64_t result = (uint64_t)value + increment;
    return result > UINT32_MAX ? UINT32_MAX : (uint32_t)result;
}

static void tcp_ca_set_cwnd(tcp_pcb* pcb, uint32_t cwnd)
{
    cwnd = max(cwnd, tcp_ca_mss(pcb));
    if (pcb->sock)
        tcp_snd_cwnd_change(pcb, cwnd);
    else
        pcb->snd_cwnd = cwnd;
}

static uint32_t tcp_cubic_cwnd_packets(const tcp_pcb* pcb)
{
    uint32_t mss = tcp_ca_mss(pcb);
    return max(pcb->snd_cwnd / mss, 1u);
}

static void tcp_cubic_set_cwnd_packets(tcp_pcb* pcb, uint64_t packets)
{
    uint64_t bytes = packets * tcp_ca_mss(pcb);
    tcp_ca_set_cwnd(pcb, bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes);
}

static uint32_t tcp_cubic_root(uint64_t value)
{
    uint32_t low = 0;
    uint32_t high = 2642245u; /* floor(cuberoot(UINT64_MAX)) */

    while (low < high) {
        uint32_t mid = low + (high - low + 1u) / 2u;
        bool fits = mid == 0 || mid <= value / mid / mid;
        if (fits)
            low = mid;
        else
            high = mid - 1u;
    }
    return low;
}

static void tcp_cubic_reset(netfast_tcp_cubic* cubic)
{
    memset(cubic, 0, sizeof(*cubic));
}

static uint32_t tcp_cubic_take_acked_packets(tcp_pcb* pcb,
                                              uint32_t acked_bytes)
{
    uint32_t mss = tcp_ca_mss(pcb);
    uint64_t total = (uint64_t)pcb->cubic.acked_bytes + acked_bytes;
    uint64_t packets = total / mss;
    pcb->cubic.acked_bytes = (uint32_t)(total % mss);
    return packets > UINT32_MAX ? UINT32_MAX : (uint32_t)packets;
}

static uint32_t tcp_cubic_slow_start(tcp_pcb* pcb, uint32_t acked)
{
    uint32_t mss = tcp_ca_mss(pcb);
    uint32_t cwnd = tcp_cubic_cwnd_packets(pcb);
    uint32_t ssthresh = max(pcb->snd_ssthresh / mss, 2u);

    if (cwnd >= ssthresh)
        return acked;

    uint32_t increase = min(acked, ssthresh - cwnd);
    tcp_cubic_set_cwnd_packets(pcb, (uint64_t)cwnd + increase);
    return acked - increase;
}

static uint32_t tcp_cubic_k_ms(uint32_t distance)
{
    /* K = cuberoot((Wmax-Wcurrent) / C), converted to milliseconds. */
    const uint64_t scale = (uint64_t)CUBIC_C_DEN * 1000000000ull;
    uint64_t value = distance > UINT64_MAX / scale
        ? UINT64_MAX : (uint64_t)distance * scale;
    value /= CUBIC_C_NUM;
    return tcp_cubic_root(value);
}

static uint32_t tcp_cubic_delta(uint64_t offset_ms)
{
    offset_ms = min(offset_ms, (uint64_t)CUBIC_MAX_OFFSET_MS);
    uint64_t cube = offset_ms * offset_ms * offset_ms;
    uint64_t delta = CUBIC_C_NUM * cube /
                     ((uint64_t)CUBIC_C_DEN * 1000000000ull);
    return delta > UINT32_MAX ? UINT32_MAX : (uint32_t)delta;
}

static void tcp_cubic_update(tcp_pcb* pcb, uint32_t cwnd, uint32_t acked)
{
    netfast_tcp_cubic* cubic = &pcb->cubic;
    uint64_t now = get_current_time_ms();
    cubic->ack_cnt = tcp_ca_saturating_add(cubic->ack_cnt, acked);

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
        target = tcp_ca_saturating_add(cubic->origin_point, delta);

    if (target > cwnd)
        cubic->cnt = max(cwnd / (target - cwnd), 1u);
    else
        cubic->cnt = tcp_ca_saturating_add(0, (uint64_t)100u * cwnd);

    if (cubic->last_max_cwnd == 0 && cubic->cnt > 20u)
        cubic->cnt = 20u;

    /* Linux CUBIC's TCP-friendly region prevents growth below the standard
     * loss-based estimate when the cubic curve is still conservative. */
    uint64_t threshold64 = ((uint64_t)cwnd * CUBIC_TCP_FRIEND_SCALE) >> 3;
    uint32_t threshold = threshold64 > UINT32_MAX
        ? UINT32_MAX : max((uint32_t)threshold64, 1u);
    if (cubic->ack_cnt > threshold) {
        uint32_t steps = (cubic->ack_cnt - 1u) / threshold;
        cubic->ack_cnt -= steps * threshold;
        cubic->tcp_cwnd = tcp_ca_saturating_add(cubic->tcp_cwnd, steps);
    }
    if (cubic->tcp_cwnd > cwnd) {
        uint32_t difference = cubic->tcp_cwnd - cwnd;
        uint32_t friendly_cnt = max(cwnd / difference, 1u);
        cubic->cnt = min(cubic->cnt, friendly_cnt);
    }

    /* Same safety bound as Linux: at most one packet of growth per two ACKs. */
    cubic->cnt = max(cubic->cnt, 2u);
}

static void tcp_cubic_cong_avoid(tcp_pcb* pcb, uint32_t acked)
{
    if (pcb->snd_cwnd < pcb->snd_ssthresh) {
        acked = tcp_cubic_slow_start(pcb, acked);
        if (!acked)
            return;
    }

    uint32_t cwnd = tcp_cubic_cwnd_packets(pcb);
    tcp_cubic_update(pcb, cwnd, acked);

    uint64_t credits = (uint64_t)pcb->cubic.cwnd_cnt + acked;
    uint32_t increase = (uint32_t)(credits / pcb->cubic.cnt);
    pcb->cubic.cwnd_cnt = (uint32_t)(credits % pcb->cubic.cnt);
    if (increase)
        tcp_cubic_set_cwnd_packets(pcb, (uint64_t)cwnd + increase);
}

static uint32_t tcp_cubic_recalc_ssthresh(tcp_pcb* pcb)
{
    netfast_tcp_cubic* cubic = &pcb->cubic;
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
    uint64_t threshold_bytes =
        (uint64_t)max(threshold, 2u) * tcp_ca_mss(pcb);
    return threshold_bytes > UINT32_MAX ? UINT32_MAX
                                        : (uint32_t)threshold_bytes;
}

void tcp_congestion_init(tcp_pcb* pcb)
{
    uint64_t initial = (uint64_t)CUBIC_INITIAL_WINDOW * tcp_ca_mss(pcb);
    pcb->snd_cwnd = initial > UINT32_MAX ? UINT32_MAX : (uint32_t)initial;
    pcb->snd_ssthresh = UINT32_MAX;
    pcb->ca_recovery_seq = 0;
    pcb->ca_prior_cwnd = 0;
    pcb->ca_state = NET_TCP_CA_OPEN;
    tcp_cubic_reset(&pcb->cubic);
}

void tcp_congestion_mss_changed(tcp_pcb* pcb)
{
    if (pcb->state == TCP_STATE_CLOSED || pcb->state == TCP_STATE_SYN_SENT ||
        pcb->state == TCP_STATE_SYN_RECEIVED) {
        tcp_congestion_init(pcb);
    }
}

bool tcp_congestion_on_ack(tcp_pcb* pcb, uint32_t acked_bytes,
                           bool was_cwnd_limited)
{
    if (pcb->ca_state != NET_TCP_CA_OPEN) {
        if (SEQ_GEQ(pcb->snd_una, pcb->ca_recovery_seq)) {
            tcp_ca_set_cwnd(pcb, pcb->snd_ssthresh);
            pcb->ca_state = NET_TCP_CA_OPEN;
            pcb->cubic.cwnd_cnt = 0;
            return false;
        }

        if (pcb->ca_state == NET_TCP_CA_RECOVERY) {
            tcp_ca_set_cwnd(pcb, tcp_ca_saturating_add(
                pcb->snd_ssthresh, tcp_ca_mss(pcb)));
        }
        return true;
    }

    if (was_cwnd_limited && acked_bytes) {
        uint32_t acked = tcp_cubic_take_acked_packets(pcb, acked_bytes);
        if (acked)
            tcp_cubic_cong_avoid(pcb, acked);
    }
    return false;
}

bool tcp_congestion_on_duplicate_ack(tcp_pcb* pcb, uint32_t duplicate_acks)
{
    if (duplicate_acks == 3 && pcb->ca_state == NET_TCP_CA_OPEN) {
        pcb->ca_prior_cwnd = pcb->snd_cwnd;
        pcb->snd_ssthresh = tcp_cubic_recalc_ssthresh(pcb);
        pcb->ca_recovery_seq = pcb->snd_nxt;
        pcb->ca_state = NET_TCP_CA_RECOVERY;
        tcp_ca_set_cwnd(pcb, tcp_ca_saturating_add(
            pcb->snd_ssthresh, 3ull * tcp_ca_mss(pcb)));
        return true;
    }

    if (duplicate_acks > 3 && pcb->ca_state == NET_TCP_CA_RECOVERY) {
        tcp_ca_set_cwnd(pcb, tcp_ca_saturating_add(
            pcb->snd_cwnd, tcp_ca_mss(pcb)));
    }
    return false;
}

void tcp_congestion_on_timeout(tcp_pcb* pcb)
{
    if (pcb->ca_state == NET_TCP_CA_OPEN) {
        pcb->ca_prior_cwnd = pcb->snd_cwnd;
        pcb->snd_ssthresh = tcp_cubic_recalc_ssthresh(pcb);
        pcb->ca_recovery_seq = pcb->snd_nxt;
    }
    pcb->ca_state = NET_TCP_CA_LOSS;
    tcp_ca_set_cwnd(pcb, tcp_ca_mss(pcb));
    tcp_cubic_reset(&pcb->cubic);
}
