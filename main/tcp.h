#ifndef TCP_H
#define TCP_H
#include"socket.h"
#include"thread.h"
#include "tcp_metrics.h"
#include "tcp_congestion.h"
#include "tcp_rack.h"
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

#define TCP_ECN_NOT_ECT 0u
#define TCP_ECN_ECT1    1u
#define TCP_ECN_ECT0    2u
#define TCP_ECN_CE      3u

/* Receive reordering. */
#define TCP_OOO_SKB_MAX 1024u

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

enum tcp_option_flags {
    TCP_OPTION_MSS_SEEN            = 1u << 0,
    TCP_OPTION_WINDOW_SCALE_SEEN   = 1u << 1,
    TCP_OPTION_TIMESTAMP_SEEN      = 1u << 2,
    TCP_OPTION_SACK_PERMITTED_SEEN = 1u << 3,
    TCP_OPTION_SACK_SEEN           = 1u << 4,
};

/* 单个报文的 TCP option 解析结果。解析阶段只写本结构，后续由握手、
 * PAWS 和 ACK/SACK 路径按各自的状态机时机应用。 */
typedef struct tcp_options {
    uint8_t flags;
    uint8_t wnd_scale;
    uint8_t sack_count;
    uint16_t mss;
    uint32_t tsval;
    uint32_t tsecr;
    tcp_sack_block sacks[TCP_MAX_SACK_BLOCKS];
} tcp_options;

typedef struct tcp_skb_tree {
    struct rb_root root;
    uint32_t count;
} tcp_skb_tree;

typedef struct tcp_pcb{
    Socket* sock;
    tcp_metrics* metrics;
    enum tcp_state state;
    task *timer_task;

    uint64_t recovery_deadline_ms; /* 丢包恢复处理的截止时间 */
    uint64_t retransmit_deadline_ms;
    uint64_t keepalive_deadline_ms;
    uint64_t persist_deadline_ms;
    uint64_t timewait_deadline_ms;
    uint64_t finwait2_deadline_ms;
    uint64_t ack_deadline_ms;
    uint64_t nagle_deadline_ms;

    uint32_t retransmit_timeout; // 重传超时（RTO）
    uint32_t keepalive_timeout;
    uint32_t keepalive_interval;
    uint32_t keepalive_retry_timeout;
    uint32_t keepalive_repeat_count;
    uint32_t keepalive_repeat_max;
    uint32_t persist_backoff;// 2 4 8 16 32 60 60 ----
    uint32_t retransmits_out;  /* 未恢复数据的 RTO 重传次数 */
    uint32_t persist_probes_out; /* 当前持续探测阶段已发送的探测次数 */
    uint32_t retries_max;      /* 两类计数到达该值后终止连接 */
    uint32_t timewait_timeout;
    uint32_t finwait2_timeout;
    uint32_t ack_timeout;
    uint8_t ack_pending_segments; /* 自上次 ACK 后收到的数据段数 */
    uint32_t connect_timeout;
    uint32_t connect_retry_times;
    uint32_t nagle_interval; /* 当前生效的 Nagle 聚合延迟 */

    /* RTT 测量（Karn 算法：仅测量未重传报文段）。 */
    uint64_t rtt_meas_time;   /* 被测报文段的发送时间；0 表示未测量 */
    uint32_t rtt_meas_seq;    /* 被测报文段的序列号 */

    /* 监听套接字队列。 */
    list_node syn_list;  /* 半连接队列：已收到 SYN 并发送 SYN+ACK，等待最终 ACK。 */
    uint32_t syn_list_num;
    list_node accept_list; /* 全连接队列：已完成三次握手，等待 accept 取走。 */
    uint32_t accept_list_num;
    Socket* parent_sock;

    tcp_skb_tree retransmit_tree;
    tcp_skb_tree reorder_tree;

    tcp_sack sack;
    tcp_rack rack;
    uint64_t sack_blocks_sent;

    uint32_t rcv_nxt;  // 下一个按序期望接收的序列号
    uint32_t last_ack_sent; // 最近一次实际发送 ACK 报文中的确认号
    uint32_t rcv_wnd;  // 对端可见的本端接收窗口大小
    //uint32_t rcv_wnd_max;  // 最大接收窗口
    //uint32_t rcv_adv;  // 已通告的接收窗口右边界
    uint32_t rcv_mss; // 本端向对端通告的 MSS

    uint32_t last_ack;
    uint32_t last_ack_repeat;

    uint32_t snd_wnd; // 对端通告的发送窗口大小
    uint32_t snd_una; // 最早尚未确认的序列号，即发送窗口左边界
    uint32_t snd_nxt; // 下一个待发送的序列号
    uint32_t snd_end; // 发送队列数据的右边界
    uint64_t snd_cwnd;     /* 拥塞窗口，单位：字节。 */
    uint64_t snd_ssthresh; /* 慢启动阈值，单位：字节。 */

    uint32_t snd_wl1;// 上次窗口更新的报文序列号，用于判断更新是否过时
    uint32_t snd_wl2;// 上次窗口更新时记录的对端 ACK
    uint32_t peer_mss; // 对端通告的 MSS（或协议默认值）
    uint32_t snd_mss; // 实际发送 MSS，受对端 MSS 和路径 MTU 限制
    uint8_t snd_wnd_scale;
    uint8_t rcv_wnd_scale;
    uint32_t backlog;

    uint32_t snd_last_time; // 上次发送数据的时间（毫秒）

    uint32_t ts_recent; // 最近一次收到对端时间戳选项中的 tsval（时间戳值）
    struct {
        uint32_t peer_ts_ok : 1;
        uint32_t peer_wnd_scale_ok : 1;
        uint32_t peer_sack_ok : 1; /* 对端在 SYN 中携带了 SACK-Permitted */
        uint32_t recv_fin : 1; /* 已按序收到对端 FIN */
        uint32_t ecn_ok : 1; /* 双方已在 SYN 握手中协商 ECN */
        uint32_t ecn_echo_pending : 1;
        uint32_t ecn_cwr_pending : 1;
    } tcp_flag;
    /* 通用拥塞控制状态及算法私有数据由 tcp_ca 管理。 */
    tcp_ca ca;

} tcp_pcb;

void tcp_skb_tree_insert(tcp_skb_tree* tree, skbuff* skb,
                         size_t node_offset);
void tcp_skb_tree_remove(tcp_skb_tree* tree, skbuff* skb,
                         size_t node_offset);
skbuff* tcp_skb_tree_lower_bound(const tcp_skb_tree* tree, uint32_t seq,
                                 size_t node_offset);
/* Return the skb with the greatest sequence start strictly below seq. */
skbuff* tcp_skb_tree_prev_lower_bound(const tcp_skb_tree* tree, uint32_t seq,
                                      size_t node_offset);
/* Split a TCP skb at a payload sequence offset, keeping queues, RACK, and
 * SACK byte accounting in sync. */
skbuff* tcp_skb_split(tcp_pcb* pcb, skbuff* skb, uint32_t seq_len);

#define TCP_ADD_RETRASMIT(pcb, skb) \
    tcp_skb_tree_insert(&(pcb)->retransmit_tree, (skb), \
                        offsetof(skbuff, retransmit_node)); \
    tcp_rack_skb_sent((pcb), (skb), (skb)->l4_private.tcp.pkt_send_ms);

#define TCP_REMOVE_RETRASMIT(pcb, skb) do { \
    tcp_skb_tree_remove(&(pcb)->retransmit_tree, (skb), \
                        offsetof(skbuff, retransmit_node)); \
    tcp_sack_set_state((pcb), (skb), 0); \
    tcp_rack_queue_remove((pcb), (skb)); \
} while (0)

#define TCP_TREE_INSERT(pcb, name, skb) \
    tcp_skb_tree_insert(&(pcb)->name##_tree, (skb), \
                        offsetof(skbuff, name##_node))

#define TCP_TREE_FIRST(pcb, name) \
    SKB_FROM_NODE(rb_first(&(pcb)->name##_tree.root), name##_node)
#define TCP_TREE_LAST(pcb, name) \
    SKB_FROM_NODE(rb_last(&(pcb)->name##_tree.root), name##_node)
#define TCP_TREE_NEXT(skb, name) \
    SKB_FROM_NODE(rb_next(&(skb)->name##_node), name##_node)
#define TCP_TREE_PREV(skb, name) \
    SKB_FROM_NODE(rb_prev(&(skb)->name##_node), name##_node)
#define TCP_TREE_LOWER_BOUND(pcb, name, seq) \
    tcp_skb_tree_lower_bound(&(pcb)->name##_tree, (seq), \
                             offsetof(skbuff, name##_node))
#define TCP_TREE_PREV_LOWER_BOUND(pcb, name, seq) \
    tcp_skb_tree_prev_lower_bound(&(pcb)->name##_tree, (seq), \
                                  offsetof(skbuff, name##_node))

/* The Window field in SYN/SYN-ACK is never scaled.  Scaling starts with
 * packets sent after the handshake, and only when both sides exchanged the
 * option. */
static inline uint16_t tcp_encode_window(const tcp_pcb* pcb, uint8_t flags)
{
    uint32_t window = pcb->rcv_wnd;
    if (!(flags & TCP_FLAG_SYN) && pcb->tcp_flag.peer_wnd_scale_ok)
        window >>= pcb->rcv_wnd_scale;
    return (uint16_t)(window > 65535u ? 65535u : window);
}

static inline uint32_t tcp_decode_window(const tcp_pcb* pcb, uint16_t window,
                                         uint8_t flags)
{
    if ((flags & TCP_FLAG_SYN) || !pcb->tcp_flag.peer_wnd_scale_ok)
        return window;
    return (uint32_t)window << pcb->snd_wnd_scale;
}

int tcp_recv(struct skbuff* skb);
/* 重传完整 skb：1 表示上层已消费本次尝试；0 表示预算为零。
 * 下层发送错误按丢包处理，不向 TCP 上层返回负值。 */
void tcp_retransmit_skb(tcp_pcb* pcb, skbuff* skb);
void tcp_update_sndcwnd(tcp_pcb* pcb, uint64_t new_cwnd);
void tcp_update_timer(tcp_pcb* pcb, uint64_t* which,
                      uint64_t deadline_ms, bool override);

static inline uint64_t tcp_flight_size(const tcp_pcb* pcb)
{
    if(pcb->tcp_flag.peer_sack_ok){
        return pcb->snd_nxt - pcb->snd_una - pcb->sack.sacked_bytes;
    }
    return pcb->snd_nxt - pcb->snd_una;
}
/* Split an oversized TCP packet into TCP segments.  Each segment retains the
 * complete TCP header/options and receives its own sequence number/checksum;
 * the IP output path adds the corresponding IP header afterward. */
bool tcp_skb_frag(skbuff* skb, uint32_t mtu);
#endif
