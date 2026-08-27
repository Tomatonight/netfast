#ifndef TCP_H
#define TCP_H
#include"socket.h"
#include"thread.h"
#include "tcp_metrics.h"
#include "tcp_congestion.h"
#include <tcp_sack.h>

extern protocol_ops tcp_protocol_ops;

#define MAX_TCP_HDR_LEN 60
#define TCP_RCV_WND_SCALE_DEFAULT 6u

/* RFC 793 flags */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

/* Receive reordering. */
#define TCP_OOO_SKB_MAX 256u

/* SEQ comparison macros (handle uint32 wraparound) */
#define SEQ_LT(a,b)   ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <  0)
#define SEQ_LEQ(a,b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define SEQ_GT(a,b)   ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >  0)
#define SEQ_GEQ(a,b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)

/* TCP timer defaults (ms) */
#define TCP_RETRIES2_DEFAULT                 8      /* established RTO/persist: about 31s */
#define TCP_ORPHAN_RETRIES_DEFAULT           4      /* orphan retransmission: about 15s */
#define TCP_KEEPALIVE_TIMEOUT_MS_DEFAULT    30000u
#define TCP_KEEPALIVE_INTERVAL_MS_DEFAULT    1000u
#define TCP_KEEPALIVE_REPEAT_MAX_DEFAULT       3u
#define TCP_PERSIST_BACKOFF_MS_DEFAULT       1000u
#define TCP_PERSIST_BACKOFF_MS_MAX           4000u
#define TCP_TIMEWAIT_TIMEOUT_MS_DEFAULT      30000u
#define TCP_FINWAIT2_TIMEOUT_MS_DEFAULT      30000u
#define TCP_DELACK_TIMEOUT_MS_DEFAULT       40u
#define TCP_NAGLE_INTERVAL_MS_DEFAULT      10u
#define TCP_OUTPUT_BURST_MAX                64u
#define TCP_KEEPALIVE_RETRY_TIMEOUT_MS_DEFAULT  1000u
#define TCP_CONNECT_TIMEOUT_MS_DEFAULT      1000u
#define TCP_CONNECT_RETRY_MAX               4

#define TCP_TIMER_STOP 0

enum tcp_state {
    TCP_STATE_CLOSED=0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT
};

typedef struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t doff_res_flags;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
    /* Options follow if doff > 5 */
} __attribute__((packed)) tcp_hdr;

typedef struct tcp_option {
    uint8_t kind;
    uint8_t length;
    uint8_t data[0];
} __attribute__((packed)) tcp_option;

typedef struct tcp_pcb{
    Socket* sock;
    tcp_metrics* metrics;
    enum tcp_state state;
    task *timer_task;

    uint64_t fast_retransmit_deadline_ms; /* deferred fast-retransmit task */
    uint64_t retransmit_deadline_ms;
    uint64_t keepalive_deadline_ms;
    uint64_t persist_deadline_ms;
    uint64_t timewait_deadline_ms;
    uint64_t finwait2_deadline_ms;
    uint64_t ack_deadline_ms;
    uint64_t connect_deadline_ms;
    uint64_t nagle_deadline_ms;

    uint32_t retransmit_timeout; // RTO
    uint32_t keepalive_timeout;
    uint32_t keepalive_interval;
    uint32_t keepalive_retry_timeout;
    uint32_t keepalive_repeat_count;
    uint32_t keepalive_repeat_max;
    uint32_t persist_backoff;// 2 4 8 16 32 60 60 ----
    uint32_t retransmits_out;  /* unrecovered data RTO count */
    uint32_t persist_probes_out; /* probes sent in the current persist episode */
    uint32_t retries_max;      /* limit for either counter before abort */
    uint32_t timewait_timeout;
    uint32_t finwait2_timeout;
    uint32_t ack_timeout;
    uint8_t ack_pending_segments; /* data segments since the last ACK */
    uint32_t connect_timeout;
    uint32_t connect_retry_times;
    uint32_t nagle_interval; /* effective Nagle batching delay */

    /* RTT measurement (Karn's algorithm: only on non-retransmitted segments) */
    uint64_t rtt_meas_time;   /* send timestamp of the segment being measured (0 = idle) */
    uint32_t rtt_meas_seq;    /* sequence number of the segment being measured */

    /* listen socket queues */
    list_node syn_list;  /* 半连接队列：SYN_RECV（收到了 SYN，已�?SYN+ACK，等待最�?ACK�?*/
    uint32_t syn_list_num;
    list_node accept_list; /* 全连接队列：ESTABLISHED（完成三次握手，等待 accept 取走�?*/
    uint32_t accept_list_num;
    Socket* parent_sock;

    queue retransmit_queue;
    list_node unordered_skb_list;
    uint16_t unordered_skb_count;

    /* Receiver blocks are kept in RFC 2018 recent-first order. */
    tcp_sack_block recv_sacks[TCP_MAX_SACK_BLOCKS];
    uint8_t recv_sack_count;

    /* Sender scoreboard accounting and diagnostics. */
    uint32_t sack_blocks_sent;
    uint32_t sack_blocks_received;
    uint32_t sack_retransmits;
    uint32_t sack_rto_events;

    uint32_t rcv_nxt;  // next seq expected to receive (下一个按序期望接收序�?
    uint32_t rcv_wnd;  // receiver window advertised (接收窗口大小，将通告给发送方)
    //uint32_t rcv_wnd_max;  // maximum receiver window (最大接收窗�?
    //uint32_t rcv_adv;  // advertised right edge (已通告的右边界=最大可接收序号+1)
    uint32_t rcv_mss; // local MSS advertised to the peer

    uint32_t last_ack;
    uint32_t last_ack_repeat;

    uint32_t snd_wnd; // peer's advertised window (对端通告窗口大小)
    uint32_t snd_una; // oldest unacknowledged seq (最老的未确认序号，左边�?
    uint32_t snd_nxt; // next seq to send (下一个待发送序�?
    uint32_t snd_end; // snd_queue 中最后一个报文段的序�?+ 1（即 snd_queue 中数据的右边界）
    uint64_t snd_cwnd;     /* 拥塞窗口，单位：字节。 */
    uint64_t snd_ssthresh; /* 慢启动阈值，单位：字节。 */

    uint32_t snd_wl1;// seq number of last window update (上次窗口更新的序号，用于判断窗口更新是否过时)
    uint32_t snd_wl2;// 上一次“窗口更新”时记录的对端报�?ACK
    uint32_t peer_mss; // MSS advertised by the peer (or protocol default)
    uint32_t snd_mss; // effective outbound MSS, limited by peer MSS and path MTU
    uint8_t snd_wnd_scale;
    uint8_t rcv_wnd_scale;
    uint32_t backlog;

    uint32_t snd_last_time; // 上次发送数据的时间（ms�?

    uint32_t ts_recent; // 最近一次收到对端时间戳选项中的 tsval（时间戳值）
    uint32_t ts_recent_age_ms;
    uint32_t ts_last_tsecr; // 最近一次收到对端时间戳选项中的 tsecr（时间戳回显应答�?
    struct {
        uint32_t peer_ts_ok : 1;
        uint32_t peer_wnd_scale_ok : 1;
        uint32_t peer_sack_ok : 1; /* peer sent SACK-Permitted in its SYN */
        uint32_t sack_permitted_sent : 1; /* our SYN granted peer permission */
        uint32_t recv_fin : 1; /* an in-order peer FIN has been received */
    } tcp_flag;
    struct {
        uint32_t nodelay : 1;      /* TCP_NODELAY */
    } tcp_options;

    /* Generic state and algorithm-private storage are owned by tcp_ca. */
    tcp_ca ca;

} tcp_pcb;

static inline bool tcp_window_scale_negotiated(const tcp_pcb* pcb)
{
    return pcb->tcp_flag.peer_wnd_scale_ok;
}

/* RFC 7323: an active opener may offer Window Scale in its SYN, while a
 * passive opener may include it in SYN-ACK only when the incoming SYN did. */
static inline bool tcp_should_send_window_scale(const tcp_pcb* pcb,
                                                uint8_t flags)
{
    if (!(flags & TCP_FLAG_SYN))
        return false;
    if (!(flags & TCP_FLAG_ACK))
        return true;
    return pcb->tcp_flag.peer_wnd_scale_ok;
}

/* The Window field in SYN/SYN-ACK is never scaled.  Scaling starts with
 * packets sent after the handshake, and only when both sides exchanged the
 * option. */
static inline uint16_t tcp_encode_window(const tcp_pcb* pcb, uint8_t flags)
{
    uint32_t window = pcb->rcv_wnd;
    if (!(flags & TCP_FLAG_SYN) && tcp_window_scale_negotiated(pcb))
        window >>= pcb->rcv_wnd_scale;
    return (uint16_t)(window > 65535u ? 65535u : window);
}

static inline uint32_t tcp_decode_window(const tcp_pcb* pcb, uint16_t window,
                                         uint8_t flags)
{
    if ((flags & TCP_FLAG_SYN) || !tcp_window_scale_negotiated(pcb))
        return window;
    return (uint32_t)window << pcb->snd_wnd_scale;
}

int tcp_recv(struct skbuff* skb);
void tcp_update_sndcwnd(tcp_pcb* pcb, uint64_t new_cwnd);
void tcp_schedule_fast_retransmit(tcp_pcb* pcb);

/* 每个报文段的有效数据载荷上限（snd_mss 减去 TCP 选项）。 */
uint32_t tcp_data_mss(const tcp_pcb* pcb);

#endif
