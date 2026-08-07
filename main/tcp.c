#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/tcp.h> 
#include "tcp.h"
#include "tcp_metrics.h"
#include "base.h"
#include "hash.h"
#include "icmp.h"
#include "ip.h"
#include "ipv6.h"
#include "ipv6_ext.h"
#include "log.h"
#include "queue.h"
#include "skbuff.h"
#include "worker.h"
#include "fd_entry.h"
#include "req_socket.h"
#include "xdp.h"
#include "../api/netfast.h"

static void tcp_timer_cb(task* tk);
static void tcp_reset_timer(tcp_pcb* pcb);
static void tcp_update_timer(tcp_pcb* pcb, uint64_t* which, uint64_t deadline_ms, bool override);
static void tcp_destroy_pcb(tcp_pcb *pcb);
static void destroy_tcp_socket(Socket* sock);
static int tcp_send_flag(Socket* sock, uint32_t seq, uint32_t ack, uint8_t flag);
static int tcp_input(Socket *sock, skbuff *skb);
static uint32_t make_tcp_options(tcp_pcb* pcb, skbuff* skb);
static int parse_tcp_options(tcp_pcb* pcb, tcp_hdr* hdr);
static int set_tcp_socket_route(Socket* sock, const uint8_t* dip, uint32_t scope_id);
static skbuff* tcp_retransmit_enqueue(tcp_pcb* pcb, skbuff* skb);
static void tcp_send_fin(tcp_pcb* pcb);

static void tcp_send_window_update(tcp_pcb* pcb,
                                         uint32_t old_limit,
                                         uint32_t new_limit)
{
    if(old_limit == new_limit)
        return;
    Socket* sock = pcb->sock;

    skbuff* retrans_skb = SKB_FROM_QUEUE_NODE(get_queue_first(&pcb->retransmit_queue));
    if (!retrans_skb || !new_limit) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         TCP_TIMER_STOP, true);
    } else if (pcb->retransmit_deadline_ms == TCP_TIMER_STOP) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         get_current_time_ms()+ pcb->retransmit_timeout, false);
    }

    bool was_sendable = sock->send_queue.element_number && old_limit &&
                        SEQ_LT(pcb->snd_nxt, pcb->snd_una + old_limit);
    bool is_sendable = sock->send_queue.element_number && new_limit &&
                       SEQ_LT(pcb->snd_nxt, pcb->snd_una + new_limit);

    if (!is_sendable) {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms, TCP_TIMER_STOP, false);
    } else if (!was_sendable || pcb->nagle_deadline_ms == TCP_TIMER_STOP) {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                         get_current_time_ms(), false);
    }
}

static void tcp_snd_win_change(tcp_pcb* pcb, uint32_t new_wnd){
    uint32_t old_wnd = pcb->snd_wnd;
    uint32_t old_limit = min(pcb->snd_wnd, pcb->snd_cwnd);
    if(old_wnd == new_wnd)
        return;
    if (new_wnd == 0) {
        pcb->retries_out = 0;//retransmit and persist both use retries_out
        //old > 0 new is 0
        tcp_update_timer(pcb, &pcb->persist_deadline_ms, get_current_time_ms() + pcb->persist_backoff, true);
    }
    else if(old_wnd == 0){
        //old win is 0 ,new > 0
        pcb->persist_backoff = TCP_PERSIST_BACKOFF_MS_DEFAULT;
        pcb->retries_out = 0;
        tcp_update_timer(pcb, &pcb->persist_deadline_ms, TCP_TIMER_STOP, true);
    }
    pcb->snd_wnd = new_wnd;
    tcp_send_window_update(pcb, old_limit, min(pcb->snd_wnd, pcb->snd_cwnd));
}

void tcp_snd_cwnd_change(tcp_pcb* pcb, uint32_t new_cwnd)
{
    if (pcb->snd_cwnd == new_cwnd)
        return;

    uint32_t old_limit = min(pcb->snd_wnd, pcb->snd_cwnd);
    pcb->snd_cwnd = new_cwnd;
    tcp_send_window_update(pcb, old_limit, min(pcb->snd_wnd, pcb->snd_cwnd));
}

static skbuff* tcp_retransmit_enqueue(tcp_pcb* pcb, skbuff* skb)
{
    skbuff* last = SKB_FROM_QUEUE_NODE(get_queue_last(&pcb->retransmit_queue));
    uint32_t len = skb_data_len(skb);
    uint32_t seq_len = len
                     + ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1u : 0u)
                     + ((skb->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1u : 0u);
    uint32_t third_mss = pcb->snd_mss / 3u;

    /* Pure ACKs do not consume sequence space and cannot be released by a
     * later cumulative ACK, so they must never enter retransmit_queue. */
    if (seq_len == 0) {
        WARN_LOG("tcp: refusing zero-length retransmit entry");
        PUT_REF(skb);
        return NULL;
    }

    if(last){
#ifndef NDEBUG
        uint32_t last_seq_len = skb_data_len(last)
                              + ((last->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1u : 0u)
                              + ((last->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1u : 0u);
        assert(last->l4_private.tcp.seq + last_seq_len ==
               skb->l4_private.tcp.seq);
#endif
    }
    if (last && skb->l4_private.tcp.flag == TCP_FLAG_ACK &&
        last->l4_private.tcp.flag == TCP_FLAG_ACK && len <= third_mss &&
        skb_data_len(last) + len <= pcb->snd_mss &&
        skb_append_skb(last, skb, true)) {
        return last;
    }

    add_queue(&pcb->retransmit_queue, &skb->queue_node);
    return skb;
}

static inline uint32_t tcp_predict_options_len(const tcp_pcb* pcb, uint8_t flags)
{
    bool is_syn = (flags & TCP_FLAG_SYN) != 0;
    return (is_syn ? 8u : 0u) + (pcb->tcp_flag.peer_ts_ok ? 12u : 0u);
}

static inline bool tcp_deadline_due(tcp_pcb* pcb, uint64_t now_ms, uint64_t *deadline_ms)
{
    if (*deadline_ms == TCP_TIMER_STOP) {
        return false;
    }
    if (now_ms >= *deadline_ms) {
        *deadline_ms = TCP_TIMER_STOP;
        tcp_reset_timer(pcb);
        return true;
    }
    return false;
}

int tcp_pcb_init(Socket* sock){
    tcp_pcb* pcb=calloc(1,sizeof(tcp_pcb));
    if(!pcb){
        goto fail;
    }
    sock->pcb=pcb;
    pcb->sock=sock;
    pcb->state=TCP_STATE_CLOSED;
    init_queue(&pcb->retransmit_queue);

    pcb->timer_task = create_task(TASK_TYPE_TIMER);
    if (!pcb->timer_task)
        goto fail;
    pcb->timer_task->cb_timer = tcp_timer_cb;
    pcb->timer_task->argv = (uint64_t)pcb;

    pcb->keepalive_timeout  = TCP_KEEPALIVE_TIMEOUT_MS_DEFAULT;
    pcb->keepalive_retry_timeout = TCP_KEEPALIVE_RETRY_TIMEOUT_MS_DEFAULT;
    pcb->keepalive_interval = TCP_KEEPALIVE_INTERVAL_MS_DEFAULT;
    pcb->keepalive_repeat_max = TCP_KEEPALIVE_REPEAT_MAX_DEFAULT;
    pcb->persist_backoff    = TCP_PERSIST_BACKOFF_MS_DEFAULT;
    pcb->retries_out = 0;
    pcb->retries_max = TCP_RETRIES2_DEFAULT;
    pcb->timewait_timeout   = TCP_TIMEWAIT_TIMEOUT_MS_DEFAULT;
    pcb->finwait2_timeout   = TCP_FINWAIT2_TIMEOUT_MS_DEFAULT;
    pcb->ack_timeout     = TCP_DELACK_TIMEOUT_MS_DEFAULT;
    pcb->nagle_interval    = TCP_NAGLE_INTERVAL_MS_DEFAULT;
    pcb->connect_timeout = TCP_CONNECT_TIMEOUT_MS_DEFAULT;

    pcb->snd_mss = 512;
    pcb->rcv_mss = 512;
    pcb->rcv_wnd = sock->recv_buffer_len_max;
    pcb->snd_wnd = pcb->rcv_wnd;//tmp set
    tcp_congestion_init(pcb);

    uint32_t iss = get_current_time_ms() % 65535;
    pcb->snd_una = iss;
    pcb->snd_nxt = iss;
    pcb->snd_end = iss;

    pcb->last_ack = iss;

    /* A route is selected later, after the local/remote tuple is known. */
    pcb->retransmit_timeout = tcp_metrics_default_rto();

    return 0;

fail:
    if (pcb)
        PUT_REF(pcb->metrics);
    sock->pcb = NULL;
    free(pcb);
    return -1;
}

static int tcp_seq_cmp(list_node* a, list_node* b)
{
    skbuff* skb_a = (skbuff*)((uint8_t*)a - offsetof(skbuff, tcp_list));
    skbuff* skb_b = (skbuff*)((uint8_t*)b - offsetof(skbuff, tcp_list));
    uint32_t seq_a = skb_a->l4_private.tcp.seq;
    uint32_t seq_b = skb_b->l4_private.tcp.seq;
    /* The receive reorder queue can straddle 2^32.  TCP sequence ordering
     * must therefore use signed modular comparison, not raw uint32 order. */
    if (SEQ_LT(seq_a, seq_b)) return -1;
    return SEQ_GT(seq_a, seq_b);
}

static bool tcp_recv_data(tcp_pcb* pcb, skbuff* skb){
    uint32_t seq = skb->l4_private.tcp.seq;

    uint32_t data_len = skb_data_len(skb);
    if (data_len == 0) {
        return false;
    }

    /* Trim data before rcv_nxt (retransmitted/overlapping prefix) */
    if(SEQ_LT(seq, pcb->rcv_nxt)){
        uint32_t overlap = pcb->rcv_nxt - seq;
        if (overlap >= data_len) {
            return false;
        }
        skb_consume(skb, overlap, false);
        seq = pcb->rcv_nxt;
        data_len = skb_data_len(skb);
    }

    /* Trim data beyond receive window (exceeds rcv_nxt + rcv_wnd) */
    if(SEQ_GT(seq + data_len, pcb->rcv_nxt + pcb->rcv_wnd)){
        uint32_t overlap = (seq + data_len) - (pcb->rcv_nxt + pcb->rcv_wnd);
        if (overlap >= data_len) {
            return false; /* entirely outside window */
        }
        skb_truncate(skb, skb_data_len(skb) - overlap);
    }

    skbuff* queue_skb = skb;
    INC_REF(queue_skb);

    /* Insert into unordered list, ordered by tcp.seq.  Equal sequence
     * numbers are retransmissions already represented in the reorder
     * queue.  add_list_node_compare() leaves the node detached in that
     * case, so drop the extra queue reference instead of leaking the skb
     * (and its XDP frame). */
    if (add_list_node_compare(&pcb->unordered_skb_list,
                              &queue_skb->tcp_list, tcp_seq_cmp) < 0) {
        PUT_REF(queue_skb);
        return false;
    }

    /* Move in-order segments from unordered list to recv queue */
    skbuff* it;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(&pcb->unordered_skb_list, it, tmp, skbuff, tcp_list){
        uint32_t it_seq = it->l4_private.tcp.seq;
        uint32_t it_data_len = skb_data_len(it);

        if(SEQ_GT(it_seq, pcb->rcv_nxt)){
            break; /* gap: not yet in-order */
        }

        if(SEQ_LT(it_seq, pcb->rcv_nxt)){
            /* Overlaps with already received data — trim or discard */
            uint32_t overlap = pcb->rcv_nxt - it_seq;
            if(overlap >= it_data_len){
                /* Entirely duplicate */
                remove_list_node(&it->tcp_list);
                PUT_REF(it);
                continue;
            }
            skb_consume(it, overlap, false);
            it->l4_private.tcp.seq = pcb->rcv_nxt;
            it_data_len = skb_data_len(it);
        }

        remove_list_node(&it->tcp_list);
        add_queue(&pcb->sock->recv_queue, &it->queue_node);
        pcb->sock->recv_buffer_len += it_data_len;
        pcb->rcv_nxt += it_data_len;
    }
    socket_notify_event(pcb->sock, notify_data_read);
    pcb->rcv_wnd = min(SOCKET_USEABLE_RECV_BUFF_SIZE(pcb->sock),
                       pcb->sock->recv_buffer_len_max);
    return true;
}

static void tcp_abort_connect(Socket* sock)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;

    /* Remove the tuple while the concrete addresses are still present. */
    if (sock->flag.is_hash)
        uninstall_tuple(sock, tcp_tuple_hash(sock->family));

    skbuff* skb;
    while ((skb = SKB_FROM_QUEUE_NODE(pop_queue(&pcb->retransmit_queue))))
        PUT_REF(skb);

    pcb->snd_nxt = pcb->snd_una;
    pcb->snd_end = pcb->snd_una;
    memset(sock->dip6, 0, sizeof(sock->dip6));
    sock->dip6_scope_id = 0;
    sock->dport = 0;
    sock->flag.is_connected = 0;
}

static void destroy_tcp_socket(Socket* sock){
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    pcb->state = TCP_STATE_CLOSED;
    
    if(sock->fd_entry){// user hold the socket
        socket_notify_event(sock, notify_err);
        return;
    }

    tcp_destroy_pcb(pcb);
    destroy_socket(sock);
}


static void tcp_update_timer(tcp_pcb* pcb,uint64_t * which, uint64_t deadline_ms, bool override)
{
    if (*which == deadline_ms) {
        return;
    }

    if (*which == TCP_TIMER_STOP || *which > deadline_ms || override) {
        task* tk = pcb->timer_task;
        uint64_t old_deadline_ms = *which;
        *which = deadline_ms;

        if (!tk->registered || old_deadline_ms == tk->timeout) {
            /* task 未安排，或者修改的是当前最早 deadline，需要重新选择。 */
            tcp_reset_timer(pcb);
        } else if (deadline_ms != TCP_TIMER_STOP &&
                (tk->timeout == TCP_TIMER_STOP ||
                    deadline_ms < tk->timeout)) {
            tk->timeout = deadline_ms;
            register_task(pcb->sock->owner->master, tk);
        }
    }
}

static void tcp_reset_timer(tcp_pcb* pcb)
{
    task* tk = pcb->timer_task;
    uint64_t next = 0;
    uint64_t timeouts[] = {
        pcb->keepalive_deadline_ms,
        pcb->retransmit_deadline_ms,
        pcb->persist_deadline_ms,
        pcb->ack_deadline_ms,
        pcb->nagle_deadline_ms,
        pcb->timewait_deadline_ms,
        pcb->finwait2_deadline_ms,
    };
    for (int i = 0; i < (int)(sizeof(timeouts) / sizeof(timeouts[0])); i++) {
        if (timeouts[i] && (next == 0 || timeouts[i] < next)) {
            next = timeouts[i];
        }
    }
    if (next != 0) {
        tk->timeout = next;
        register_task(pcb->sock->owner->master, tk);
    } else {
        unregister_task(tk);
        tk->timeout = 0;
    }
}

static void tcp_timer_cb(task* tk)
{
    tcp_pcb* pcb = (tcp_pcb*)tk->argv;
    Socket* sock = pcb->sock;
    uint64_t now_ms = get_current_time_ms();
    int ret = 0;

    if (tcp_deadline_due(pcb, now_ms, &pcb->nagle_deadline_ms)) {
        if(sock->send_queue.element_number){
            pcb->tcp_flag.nagle_trigger = 1;
            ret = tcp_output(pcb);
        }
    }
    else if (tcp_deadline_due(pcb, now_ms, &pcb->retransmit_deadline_ms)) {
        if(pcb->retransmit_queue.element_number){
            if (pcb->state == TCP_STATE_SYN_SENT || pcb->state == TCP_STATE_SYN_RECEIVED) {
                /* SYN retransmission with exponential backoff */
                if (pcb->connect_retry_times++ >= TCP_CONNECT_RETRY_MAX) {
                    sock->error = ETIMEDOUT;
                    destroy_tcp_socket(sock);
                    return;
                }
                pcb->connect_timeout *= 2;
                tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                                get_current_time_ms() + pcb->connect_timeout, true);
            } else {
                /* Data retransmit: exponential backoff + limit */
                if (pcb->retries_out++ >= pcb->retries_max) {
                    sock->error = ETIMEDOUT;
                    destroy_tcp_socket(sock);
                    return;
                }
                tcp_congestion_on_timeout(pcb);
                pcb->retransmit_timeout =
                    tcp_metrics_backoff(pcb->retransmit_timeout);
                tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                                get_current_time_ms() + pcb->retransmit_timeout, false);
            }
            pcb->tcp_flag.retransmit_trigger = 1;
            ret = tcp_output(pcb);
        }
    }
    else if (tcp_deadline_due(pcb, now_ms, &pcb->ack_deadline_ms)) {
        ret = tcp_send_flag(sock, pcb->snd_nxt, pcb->rcv_nxt, TCP_FLAG_ACK);
    }
    else if (tcp_deadline_due(pcb, now_ms, &pcb->persist_deadline_ms)) {
        if (!pcb->snd_wnd && (pcb->retransmit_queue.element_number || sock->send_queue.element_number)) {
            if (pcb->retries_out++ >= pcb->retries_max) {
                sock->error = ETIMEDOUT;
                destroy_tcp_socket(sock);
                return;
            }
            pcb->persist_backoff = min(pcb->persist_backoff * 2,
                                       TCP_PERSIST_BACKOFF_MS_MAX);
            tcp_update_timer(pcb, &pcb->persist_deadline_ms, get_current_time_ms() + pcb->persist_backoff, true);
            pcb->tcp_flag.persist_trigger = 1;
            ret = tcp_output(pcb);
        }
    }
    else if (tcp_deadline_due(pcb, now_ms, &pcb->timewait_deadline_ms)) {
        destroy_tcp_socket(sock);
        return;
    }
    else if (tcp_deadline_due(pcb, now_ms, &pcb->finwait2_deadline_ms)) {
        if(pcb->state == TCP_STATE_FIN_WAIT_2){
            DEBUG_LOG("TCP FIN_WAIT_2 timeout, closing connection");
            destroy_tcp_socket(sock);
            return;
        }
    }
    else if (tcp_deadline_due(pcb, now_ms, &pcb->keepalive_deadline_ms)) {
        if (!sock->options.keepalive ||
            pcb->state != TCP_STATE_ESTABLISHED) {
            pcb->keepalive_repeat_count = 0;
        } else if(pcb->keepalive_repeat_count++ >= pcb->keepalive_repeat_max){
            sock->error = ETIMEDOUT;
            destroy_tcp_socket(sock);
            return;
        } else {
            /* Keepalive probes use constant retry interval (no backoff), per RFC 1122 */
            tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                             get_current_time_ms() + pcb->keepalive_retry_timeout,
                             false);
            ret = tcp_send_flag(sock, pcb->snd_una - 1, pcb->rcv_nxt,
                                TCP_FLAG_ACK);
        }
    }

    DEBUG_LOG("TCP timer: triggers=0x%x ret=%d", pcb->tcp_flag.triggers, ret);
    (void)ret;
    pcb->tcp_flag.triggers = 0;
}

static void clear_associated_socket(tcp_pcb *pcb){
    if(pcb->parent_sock){
        if(LIST_ATTACHED(&pcb->syn_list)){
            remove_list_node(&pcb->syn_list);
            ((tcp_pcb*)pcb->parent_sock->pcb)->syn_list_num--;
        }
        else if(LIST_ATTACHED(&pcb->accept_list)){
            remove_list_node(&pcb->accept_list);
            tcp_pcb *ppcb = (tcp_pcb*)pcb->parent_sock->pcb;
            ppcb->accept_list_num--;
        }
        pcb->parent_sock = NULL;
        return;
    }

    tcp_pcb* child_pcb;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(&pcb->syn_list, child_pcb, tmp, tcp_pcb, syn_list){
        remove_list_node(&child_pcb->syn_list);
        destroy_tcp_socket(child_pcb->sock);
    }
    pcb->syn_list_num=0;
    FOR_EACH_LIST_SAFE_OFFSET(&pcb->accept_list, child_pcb, tmp, tcp_pcb, accept_list){
        remove_list_node(&child_pcb->accept_list);
        destroy_tcp_socket(child_pcb->sock);
    }
    pcb->accept_list_num=0;
}
static void tcp_destroy_pcb(tcp_pcb *pcb)
{
    destroy_task(pcb->timer_task);
    PUT_REF(pcb->metrics);
    clear_associated_socket(pcb);
    skbuff* skb;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(&pcb->unordered_skb_list, skb, tmp, skbuff, tcp_list){
        remove_list_node(&skb->tcp_list);
        PUT_REF(skb);
    }
    while ((skb = SKB_FROM_QUEUE_NODE(pop_queue(&pcb->retransmit_queue)))) {
        PUT_REF(skb);
    }
    if(pcb->sock)
        pcb->sock->pcb = NULL;
    free(pcb);
}

static Socket *tcp_lookup_socket(uint32_t src_ip, uint16_t src_port,
                                      uint32_t dst_ip, uint16_t dst_port, bool is_syn, worker** aim_worker)
{

    Socket *sock = search_socket_by_tuple(dst_ip, dst_port, src_ip, src_port, g_stack_maps->tcp.tuple_hash4,aim_worker);
    if (sock)
        return sock;
    if (!is_syn)
        return NULL;
    sock = search_socket_by_tuple(dst_ip, dst_port, 0, 0, g_stack_maps->tcp.tuple_hash4,aim_worker);
    if (sock)
        return sock;

    return search_socket_by_tuple(INADDR_ANY, dst_port, 0, 0, g_stack_maps->tcp.tuple_hash4,aim_worker);
}


static bool check_tcp_hdr(skbuff *skb)
{
    tcp_hdr *hdr = skb->tcp_hdr;
    uint32_t hdr_len = (hdr->doff_res_flags >> 4) * 4;

    /* TCP header length: 5..15 (20..60 bytes), 32-bit aligned */
    if (hdr_len < sizeof(tcp_hdr) || hdr_len > MAX_TCP_HDR_OPT_LEN ||
        hdr_len > skb_data0_len(skb))
    {
        DEBUG_LOG("Invalid TCP header length %u", hdr_len);
        return false;
    }

    /* Verify checksum (pseudo header + tcp header + payload). */
    if (skb->flag.is_hw_rcv_checksum)
        return true;
    uint32_t seg_len = skb_data_len(skb);
    uint16_t csum = (skb->family == AF_INET6)
        ? skb_checksum_protocol6(skb, seg_len,
                                 skb->ipv6_hdr->saddr, skb->ipv6_hdr->daddr, IPPROTO_TCP)
        : skb_checksum_protocol(skb, seg_len,
                                skb->ipv4_hdr->saddr, skb->ipv4_hdr->daddr, IPPROTO_TCP);
    if (csum != 0)
    {
        DEBUG_LOG("Invalid TCP checksum csum=0x%04x seg_len=%u", ntohs(csum), seg_len);
        return false;
    }

    return true;
}
static int tcp_reply_rst(Socket* sock, skbuff* recv_skb)
{
    tcp_hdr* tcp=recv_skb->tcp_hdr;
    uint32_t seg_len = skb_data_len(recv_skb)
                     + ((tcp->flags & TCP_FLAG_SYN) ? 1u : 0u)
                     + ((tcp->flags & TCP_FLAG_FIN) ? 1u : 0u);
    if(tcp->flags & TCP_FLAG_RST)
        return 0;
    if(!(tcp->flags & TCP_FLAG_ACK))
        return tcp_send_flag(sock, 0, ntohl(tcp->seq) + seg_len, TCP_FLAG_RST | TCP_FLAG_ACK);
    return tcp_send_flag(sock, ntohl(tcp->ack_seq), 0, TCP_FLAG_RST);
}

static Socket *tcp_lookup_socket6(const uint8_t src_ip[16], uint16_t src_port,
                                   const uint8_t dst_ip[16], uint16_t dst_port,
                                   bool is_syn, worker** aim_worker)
{
    static const uint8_t zero[16];
    Socket *sock = search_socket_by_tuple6(dst_ip, dst_port, src_ip, src_port,
                                            g_stack_maps->tcp.tuple_hash6, aim_worker);
    if (sock) return sock;
    if (!is_syn) return NULL;
    sock = search_socket_by_tuple6(dst_ip, dst_port, zero, 0,
                                   g_stack_maps->tcp.tuple_hash6, aim_worker);
    if (sock) return sock;
    return search_socket_by_tuple6(zero, dst_port, zero, 0,
                                   g_stack_maps->tcp.tuple_hash6, aim_worker);
}

int tcp_recv(struct skbuff *skb)
{
    tcp_hdr *tcp = NULL;
    bool is_v6 = (skb->family == AF_INET6);

    if(skb->process == tcp_recv) {
        tcp = skb->tcp_hdr;
        goto find_socket;
    }
    if (skb_data0_len(skb) < sizeof(tcp_hdr))
        return -1;
    tcp = (tcp_hdr *)skb_start(skb);
    skb->tcp_hdr = tcp;
    if (!check_tcp_hdr(skb))
        return -1;
    skb->l4_private.tcp.seq = ntohl(tcp->seq);
    skb->l4_private.tcp.flag = tcp->flags;
    uint32_t tcp_hdr_len = (tcp->doff_res_flags >> 4) * 4;
    if (skb_consume(skb, tcp_hdr_len, true) != tcp_hdr_len) {
        DEBUG_LOG("tcp_recv: failed to consume TCP header len=%u", tcp_hdr_len);
        return -1;
    }

find_socket:
    bool is_syn = (tcp->flags & TCP_FLAG_SYN) && !(tcp->flags & TCP_FLAG_ACK);
    worker* aim_worker;
    Socket *sock;
    if (is_v6) {
        ipv6_hdr* ip6 = skb->ipv6_hdr;
        sock = tcp_lookup_socket6(ip6->saddr, tcp->sport, ip6->daddr, tcp->dport, is_syn, &aim_worker);
    } else {
        ipv4_hdr* ip = skb->ipv4_hdr;
        sock = tcp_lookup_socket(ip->saddr, tcp->sport, ip->daddr, tcp->dport, is_syn, &aim_worker);
    }
    if (!sock)
    {
        if (tcp->flags & TCP_FLAG_RST)
            return 0;
        static __thread Socket sock_tmp;
        if (is_v6) {
            ipv6_hdr* ip6 = skb->ipv6_hdr;
            memcpy(sock_tmp.sip6, ip6->daddr, 16);
            sock_tmp.sport = tcp->dport;
            memcpy(sock_tmp.dip6, ip6->saddr, 16);
            sock_tmp.dport = tcp->sport;
            sock_tmp.family = AF_INET6;
        } else {
            ipv4_hdr* ip = skb->ipv4_hdr;
            sock_tmp.sip = ip->daddr;
            sock_tmp.sport = tcp->dport;
            sock_tmp.dip = ip->saddr;
            sock_tmp.dport = tcp->sport;
            sock_tmp.family = AF_INET;
        }
        sock_tmp.protocol = IPPROTO_TCP;
        tcp_reply_rst(&sock_tmp, skb);
        return 0;
    }
    if(aim_worker != get_current_worker()){
        transmit_skb_2_worker(aim_worker, skb, tcp_recv);
        return 0;
    }
    if(sock->tuple_node.next) {
        if (is_v6) {
            uint32_t h = tcp->sport;
            for (uint32_t i = 0; i < 16; ++i)
                h = h * 33u + skb->ipv6_hdr->saddr[i];
            sock = socket_select(sock, h);
        } else {
            sock = socket_select(sock, (uint32_t)(tcp->sport ^ skb->ipv4_hdr->saddr));
        }
    }
    return tcp_input(sock, skb);
}
static void tcp_update_retransmit_queue(tcp_pcb* pcb){
    uint32_t ack = pcb->snd_una;
    bool acked = false;
    while(1){
        skbuff* skb = SKB_FROM_QUEUE_NODE(get_queue_first(&pcb->retransmit_queue));
        if(!skb)
            break;

        /* SYN and FIN each consume 1 byte of sequence space beyond data_len */
        uint32_t seg_len = skb_data_len(skb)
                         + ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1u : 0u)
                         + ((skb->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1u : 0u);

        if(SEQ_GT(ack, skb->l4_private.tcp.seq)){
            acked = true;
            if(SEQ_GEQ(ack, skb->l4_private.tcp.seq + seg_len)){
                uint32_t data_len = skb_data_len(skb);
                pop_queue(&pcb->retransmit_queue);
                pcb->sock->send_buffer_len -= data_len;
                PUT_REF(skb);
            }
            else{
                uint32_t consumed = ack - skb->l4_private.tcp.seq;
                if ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) && consumed > 0) {
                    skb->l4_private.tcp.flag &= ~TCP_FLAG_SYN;
                    consumed--;
                }

                if (consumed > 0) {
                    skb_consume(skb, consumed, false);
                    pcb->sock->send_buffer_len -= consumed;
                }
                skb->l4_private.tcp.seq = ack;
                break;
            }
        }
        else
            break;
    }

    if (acked) {
        pcb->retries_out = 0;
        pcb->retransmit_timeout = tcp_metrics_rto(pcb->metrics);
        socket_notify_event(pcb->sock, notify_data_write);

        if (pcb->sock->send_queue.element_number &&
            min(pcb->snd_wnd, pcb->snd_cwnd) &&
            SEQ_LT(pcb->snd_nxt,
                   pcb->snd_una + min(pcb->snd_wnd, pcb->snd_cwnd))) {
            tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                             get_current_time_ms(), false);
        }
    }

    if (pcb->retransmit_queue.element_number == 0) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms, TCP_TIMER_STOP, true);
        pcb->last_ack_repeat = 0;
    } else if (acked) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         get_current_time_ms() + pcb->retransmit_timeout,
                         true);
    }
}

static void tcp_retransmit_now(tcp_pcb* pcb)
{
    if (!pcb->retransmit_queue.element_number)
        return;

    pcb->tcp_flag.retransmit_trigger = 1;
    (void)tcp_output(pcb);
    pcb->tcp_flag.retransmit_trigger = 0;
    tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                     get_current_time_ms() + pcb->retransmit_timeout, true);
}

static int tcp_send_flag(Socket* sock, uint32_t seq, uint32_t ack, uint8_t flag)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    /* Control-only segment: allocate enough headroom for link/ip/tcp(+opts). */
    uint32_t ip_hdr_len = sock->family == AF_INET6
        ? MAX_IP6_HDR_WITH_EXT_LEN : MAX_IP_HDR_WITH_OPT_LEN;
    uint32_t l2_len = sock->route->if_info->l2_len;
    uint32_t total_hdr_len = MAX_TCP_HDR_OPT_LEN + ip_hdr_len + l2_len;
    skbuff* skb = skb_alloc(total_hdr_len);
    if (!skb) {
        return -ENOMEM;
    }
    skb_reserve(skb, total_hdr_len);

    skb->l4_private.tcp.seq = seq;
    skb->l4_private.tcp.flag = flag;

    set_skb_by_socket(skb, sock);

    skbuff* send_skb = skb;
    if (flag & TCP_FLAG_SYN) {
        INC_REF(skb);
        add_queue(&pcb->retransmit_queue, &skb->queue_node);

        send_skb = skb_clone(skb);
        if (!send_skb) {
            skbuff* queued_skb = SKB_FROM_QUEUE_NODE(pop_queue_last(&pcb->retransmit_queue));
            PUT_REF(queued_skb);
            PUT_REF(skb);
            return -ENOMEM;
        }

        pcb->snd_nxt++;
        pcb->snd_end++;
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
            get_current_time_ms() + pcb->retransmit_timeout, false);
    }

    uint32_t opt_len = 0;
    if (pcb) {
        opt_len = make_tcp_options(pcb, send_skb);
    }

    tcp_hdr* hdr = (tcp_hdr*)skb_data_push(send_skb, sizeof(tcp_hdr));
    memset(hdr, 0, sizeof(*hdr));

    hdr->sport = sock->sport;
    hdr->dport = sock->dport;
    hdr->seq = htonl(seq);
    hdr->ack_seq = htonl(ack);
    hdr->flags = flag;

    hdr->doff_res_flags = (uint8_t)(((sizeof(tcp_hdr) + opt_len) / 4) << 4);

    /* Advertise current receive window if PCB is available */
    uint16_t wnd = 0;
    //rst tmp socket has no pcb
    if (pcb) {
        wnd = (uint16_t)min(pcb->rcv_wnd >> pcb->rcv_wnd_scale, 65535u);
    }
    hdr->window = htons(wnd);

    /* NOTE: URG not supported yet. */
    hdr->urg_ptr = 0;
    hdr->check = 0;
    hdr->check = sock->family == AF_INET6
        ? skb_checksum_protocol6(send_skb, skb_data_len(send_skb),
                                 sock->sip6, sock->dip6, IPPROTO_TCP)
        : skb_checksum_protocol(send_skb, skb_data_len(send_skb),
                                sock->sip, sock->dip, IPPROTO_TCP);

    int ret = sock->family == AF_INET6 ? ipv6_output(send_skb)
                                       : ipv4_output(send_skb);
    if (ret >= 0 && pcb && (flag & TCP_FLAG_ACK)) {
        pcb->ack_pending_segments = 0;
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, TCP_TIMER_STOP, true);
    }
    PUT_REF(send_skb);
    if (send_skb != skb)
        PUT_REF(skb);
    return ret;
}

static int tcp_process_syn_sent(Socket* sock, skbuff* skb){
    tcp_pcb *pcb=sock->pcb;
    tcp_hdr *hdr = skb->tcp_hdr;

    uint8_t flags = hdr->flags;

    uint32_t seq = ntohl(hdr->seq);
    uint32_t ack = ntohl(hdr->ack_seq);
    uint16_t window = ntohs(hdr->window);


    if(flags & TCP_FLAG_ACK){
         if(SEQ_LEQ(ack, pcb->snd_una) || SEQ_GT(ack, pcb->snd_nxt)){
            if(!(flags & TCP_FLAG_RST)){
                tcp_send_flag(pcb->sock, ack, 0, TCP_FLAG_RST);
            }
            return 0;
        }
    }

    if(flags & TCP_FLAG_RST){
        pcb->sock->error = ECONNREFUSED;
        destroy_tcp_socket(pcb->sock);
    }

    //to do security/compartment

    if (parse_tcp_options(pcb, hdr) < 0)
        return 0;

    if (flags & TCP_FLAG_SYN) {
        pcb->rcv_nxt = seq + 1;
        if (flags & TCP_FLAG_ACK) {
            pcb->snd_una = ack;
            pcb->last_ack = ack;
            pcb->last_ack_repeat = 0;
            pcb->state = TCP_STATE_ESTABLISHED;
            tcp_update_retransmit_queue(pcb);
            if (sock->options.keepalive) {
                pcb->keepalive_repeat_count = 0;
                tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                                 get_current_time_ms() + pcb->keepalive_timeout,
                                 true);
            }

            socket_notify_event(sock, notify_data_write);
            //to do urg
        }
        else {
            pcb->state = TCP_STATE_SYN_RECEIVED;
        }
        tcp_snd_win_change(pcb, window << pcb->snd_wnd_scale);
        pcb->snd_wl1 = seq;
        pcb->snd_wl2 = ack;
        tcp_update_timer(pcb,&pcb->ack_deadline_ms, get_current_time_ms(), false);
        //to do TFO
    }
    return 0;
}

static int tcp_process_listen(Socket *sock, skbuff *skb)
{
    tcp_pcb *pcb = (tcp_pcb*)sock->pcb;
    tcp_hdr *hdr = skb->tcp_hdr;
    bool is_v6 = (skb->family == AF_INET6);
    uint8_t flags = hdr->flags;
    uint32_t seq = ntohl(hdr->seq);
    uint32_t ack = ntohl(hdr->ack_seq);
    uint16_t window = ntohs(hdr->window);
    tcp_pcb* child_pcb;

    if (flags & TCP_FLAG_RST)
        return 0;

    if (flags & TCP_FLAG_ACK) {
        tcp_send_flag(sock, ack, 0, TCP_FLAG_RST);
        return 0;
    }

    if (!(flags & TCP_FLAG_SYN))
        return 0;

    FOR_EACH_LIST_OFFSET(&pcb->syn_list, child_pcb, tcp_pcb, syn_list) {
        if (is_v6 ? (memcmp(child_pcb->sock->sip6, skb->ipv6_hdr->daddr, 16) == 0)
                  : (child_pcb->sock->sip == skb->ipv4_hdr->daddr)) {
            if (child_pcb->sock->sport == hdr->dport
                && (is_v6 ? (memcmp(child_pcb->sock->dip6, skb->ipv6_hdr->saddr, 16) == 0)
                          : (child_pcb->sock->dip == skb->ipv4_hdr->saddr))
                && child_pcb->sock->dport == hdr->sport) {
                return 0;
            }
        }
    }

    /* Backlog limit: drop SYN if queues are full */
    if (pcb->backlog > 0 && (pcb->syn_list_num + pcb->accept_list_num) >= pcb->backlog) {
        return 0;  /* silent drop, client will retransmit SYN */
    }

    Socket *new_sock = create_socket(sock->family, sock->type, sock->protocol);
    if (!new_sock) {
        ERR_LOG("tcp_process_listen: failed to create new socket");
        return -1;
    }

    child_pcb = (tcp_pcb*)new_sock->pcb;
    child_pcb->rcv_wnd = new_sock->recv_buffer_len_max;
    new_sock->options.reuseport = true;//for bind
    new_sock->options.keepalive = sock->options.keepalive;

    //bind saddr
    addr_key saddr = {
        .port = hdr->dport,
        .family = is_v6 ? AF_INET6 : AF_INET
    };
    if (is_v6)
        memcpy(saddr.addr6, skb->ipv6_hdr->daddr, 16);
    else
        saddr.addr = skb->ipv4_hdr->daddr;
    if (!bind_saddr(new_sock, &saddr, tcp_bound_table(new_sock->family))) {
        ERR_LOG("tcp_process_listen: failed to bind new socket");
        destroy_tcp_socket(new_sock);
        return -1;
    }
    //assign daddr
    if (is_v6) {
        memcpy(new_sock->dip6, skb->ipv6_hdr->saddr, 16);
    } else {
        new_sock->dip = skb->ipv4_hdr->saddr;
    }
    new_sock->dport = hdr->sport;
    new_sock->flag.is_connected = true;

    //set route
    if (set_tcp_socket_route(new_sock,
                             is_v6 ? new_sock->dip6 : (const uint8_t*)&new_sock->dip,
                             is_v6 ? new_sock->dip6_scope_id : 0) < 0) {
        ERR_LOG("tcp_process_listen: failed to set route for new socket");
        destroy_tcp_socket(new_sock);
        return -1;
    }

    //install tuple
    if (!install_tuple(new_sock, tcp_tuple_hash(new_sock->family))) {
        ERR_LOG("tcp_process_listen: failed to install tuple for new socket");
        destroy_tcp_socket(new_sock);
        return -1;
    }

    //add to parent sock
    child_pcb->state = TCP_STATE_SYN_RECEIVED;
    child_pcb->parent_sock = pcb->sock;
    add_list_node(&pcb->syn_list, &child_pcb->syn_list);
    pcb->syn_list_num++;
    set_socket_worker(new_sock, get_current_worker());

    if (parse_tcp_options(child_pcb, hdr) < 0)
        return 0;
    child_pcb->rcv_nxt = seq + 1;
    tcp_snd_win_change(child_pcb, window << child_pcb->snd_wnd_scale);
    return tcp_send_flag(new_sock, child_pcb->snd_una, child_pcb->rcv_nxt, TCP_FLAG_SYN | TCP_FLAG_ACK);
}

static int tcp_input(Socket *sock, skbuff *skb)
{

    tcp_pcb *pcb = (tcp_pcb *)sock->pcb;
    tcp_hdr *hdr = skb->tcp_hdr;
    uint8_t flags = hdr->flags;
    uint32_t seq = ntohl(hdr->seq);
    uint32_t ack = ntohl(hdr->ack_seq);
    uint16_t window = ntohs(hdr->window);

    uint32_t data_len = skb_data_len(skb);
    uint32_t seg_len = data_len + ((flags & TCP_FLAG_SYN) ? 1u : 0u) + ((flags & TCP_FLAG_FIN) ? 1u : 0u);

    if (pcb->state == TCP_STATE_CLOSED) {
        if (flags & TCP_FLAG_RST)
            return 0;
        if (!(flags & TCP_FLAG_ACK))
            return tcp_send_flag(pcb->sock, 0, seq + seg_len, TCP_FLAG_RST | TCP_FLAG_ACK);
        return tcp_send_flag(pcb->sock, ack, 0, TCP_FLAG_RST);
    }
    if (pcb->state == TCP_STATE_LISTEN) {
        return tcp_process_listen(sock, skb);
    }
    if(pcb->state == TCP_STATE_SYN_SENT){
        return tcp_process_syn_sent(sock, skb);
    }

    if (parse_tcp_options(pcb, hdr) < 0)
        return 0;  /* PAWS: old duplicate — silently drop */

    /*
3.10.7.4. Other States 其他状态
否则
第一步，校验序列号：
SYN-RECEIVED STATE
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
分段按顺序处理。到达时的初始测试用于丢弃旧的重复项，但以SEG.SEQ的顺序进行进一
步的处理。如果段的内容跨越新旧之间的边界，则仅处理新的部分。
通常，必须实现对接收段的处理，以尽可能聚合ACK段（MUST-58）。例如，如果TCP端点正在处理一系列排队的段，则它必须在发送任何ACK段之前处理所有这些段（MUST59）。
传入段的可接受性测试有四种情况：
Segment Length	Receive Window	Test
0	    0	    SEG.SEQ = RCV.NXT
0	    >0	    RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND
>0	    0	    not acceptable
>0	    >0	    RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND or RCV.NXT <= SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
在实现此处所述的序列号验证时，请参见附录A.2
如果RCV.WND是0，不接受任何段，但应特别考虑接受有效的ACK、URG和RST。
如果传入段不可接受，则应发送应答确认（除非设置了RST位，否则删除段并返回）：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
发送确认后，丢弃不可接受的段并返回。
注意，对于TIME-WAIT状态，[40]中描述了一种改进的算法，用于处理利用时间戳而不是依
赖于这里描述的序列号检查的传入SYN段。当实现改进的算法时，上述逻辑不适用于在
TIME-WAIT状态下的连接上接收的具有时间戳选项的传入SYN段。当实现改进的算法时，上述逻辑不适用于在TIME-WAIT状态下的连接上接收的具有时间戳选项的传入SYN段。
在下文中，假设段是从RCV.NXT开始的理想段，不超过窗口大小。可以通过修剪位于窗口
之外的任何部分（包括SYN和FIN）来定制实际段以适应该假设，并且如果段随后从
RCV.NXT开始，则仅进一步处理。具有较高起始序列号的段应保留以供以后处理（SHLD31）。
*/
    bool seg_allow = false;

    if(!seg_len){
        if(pcb->rcv_wnd == 0){
            if(pcb->rcv_nxt==seq){
                seg_allow = true;
            }
        }else{
            if(SEQ_LEQ(pcb->rcv_nxt, seq) && SEQ_LT(seq, pcb->rcv_nxt + pcb->rcv_wnd)){
                seg_allow = true;
            }
        }
    }
    else if(pcb->rcv_wnd != 0){
        if ((SEQ_LEQ(pcb->rcv_nxt, seq) &&
             SEQ_LT(seq, pcb->rcv_nxt + pcb->rcv_wnd)) ||
            (SEQ_LEQ(pcb->rcv_nxt, seq + seg_len - 1) &&
             SEQ_LT(seq + seg_len - 1, pcb->rcv_nxt + pcb->rcv_wnd))) {
            seg_allow = true;
        }
    }

    /* A FIN retransmitted in TIME_WAIT is immediately before RCV.NXT and
     * therefore fails the normal receive-window test.  Let it reach the
     * FIN state-machine below, which will acknowledge it and restart the
     * TIME_WAIT timer without consuming sequence space again. */
    if (!seg_allow && pcb->state == TCP_STATE_TIME_WAIT &&
        (flags & (TCP_FLAG_ACK | TCP_FLAG_FIN)) ==
            (TCP_FLAG_ACK | TCP_FLAG_FIN) &&
        !(flags & (TCP_FLAG_RST | TCP_FLAG_SYN)) &&
        seq + data_len + 1u == pcb->rcv_nxt) {
        seg_allow = true;
    }

    if(!seg_allow && !(flags & TCP_FLAG_RST)){
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
        return 0;
    }

/*
第二步，校验RST位：
RFC5961[9]的第3节描述了潜在的盲重置攻击和可选的缓解方法。这不提供加密保护（例如，在
IPsec或TCP-AO中），但可以适用于RFC5961中描述的情况。对于实现RFC5961中描述的保护的堆
栈，下面的三个检查适用；否则，下面进一步指示对这些状态的处理。
1. 如果设置了RST位，并且序列号在当前接收窗口之外，则静默丢弃该段。
2. 如果设置了RST位，并且序列号与下一个期望的序列号（RCV.NXT）完全匹配，则TCP端点必
须根据连接状态，以下面规定的方式重置连接。
3. 如果设置了RST位，并且序列号不完全匹配下一个期望的序列值，但仍然在当前接收窗口内，
则TCP端点必须发送确认（challenge ACK）：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
在发送challenge ACK后，TCP端点必须丢弃不可接受的段，并停止进一步处理传入数据包。请
注意，RFC5961和勘误表ID4772[99]包含实现中ACK调节的其他注意事项。
SYN-RECEIVED STATE
如果设置了RST位，
如果该连接是通过被动OPEN（即来自LISTEN状态）初始化的，则将该连接返回到LISTEN状态
并返回。无需通知用户。如果此连接是通过主动OPEN（即来自SYN-SENT状态）初始化的，则
拒绝连接；向用户发出“connection refused”的信号。在任何一种情况下，都应该刷新重传队
列。在主动OPEN情况下，进入CLOSED状态并删除TCB，然后返回。
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
如果设置了RST位，则任何未完成的RECEIVE和SEND都应接收“重置”的响应。应刷新所有段队
列。用户还应收到未被要求的常规“connection reset”信号。进入CLOSED（关闭）状态，删除
TCB，返回。
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
如果设置了RST位，则进入关闭状态，删除TCB，返回。
*/
    if(flags & TCP_FLAG_RST){
        if(seq != pcb->rcv_nxt){
            //challenge ACK
            tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
            return 0;
        }
        switch(pcb->state){
            case TCP_STATE_SYN_RECEIVED:
            if(pcb->parent_sock){
                destroy_tcp_socket(pcb->sock);
                return 0;
            }else {
                pcb->sock->error = ECONNREFUSED;
                destroy_tcp_socket(pcb->sock);
                return 0;
            }
            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_FIN_WAIT_1:
            case TCP_STATE_FIN_WAIT_2:
            case TCP_STATE_CLOSE_WAIT:
            {
                pcb->sock->error = ECONNRESET;
                destroy_tcp_socket(pcb->sock);
                return 0;
            }
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
            case TCP_STATE_TIME_WAIT:
                destroy_tcp_socket(pcb->sock);
                return 0;
            default:
                return 0;
        }
    }
    /*

第三步，校验安全：
SYN-RECEIVED STATE
如果段中的security/compartment没有完全匹配TCB中的security/compartment，则发送一个重置并返回。
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
如果段中的security/compartment没有完全匹配TCB中的security/compartment，则发送一个重
置；任何未完成的RECEIVE和SEND都应收到“reset’”响应。应刷新所有段队列。用户还应收到
未被要求的常规“connection reset”信号。进入CLOSED状态，删除TCB，返回。
请注意，此检查放在序列检查之后，以防止来自这些具有不同安全性的端口号之间的旧连接的段导
致当前连接中止。
*/
// to do security/compartment

/*
第四步，校验SYN位：
SYN-RECEIVED STATE
如果连接是通过被动OPEN初始化的，则将该连接返回到LISTEN状态并返回。否则，请按照以
下同步状态的说明进行处理。
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
如果在这些同步状态下设置SYN位，则它可能是合法的新连接尝试（例如，在TIME-WAIT
的情况下）、应重置连接的错误或攻击尝试的结果，如RFC5961[9]中所述。对于TIMEWAIT状态，
如果使用时间戳选项并满足预期，则可以接受新连接（根据[40]）。对于所有
其他情况，RFC5961提供了适用于某些情况的缓解措施，尽管也有提供加密保护的替代方
案（见第7节）。RFC5961推荐，在这些同步状态下，如果设置了SYN位，则无论序列号如
何，TCP端点都必须向远程端发送“challenge ACK”：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
发送确认后，TCP实现必须丢弃不可接受的段并停止进一步的处理。请注意，RFC5961和
勘误表ID4772[99]包含用于实现的额外ACK调节的说明。
对于不遵循RFC5961的实现，本段中遵循RFC793中描述的原始行为。如果SYN在窗口
中，则它是一个错误：发送重置，任何未完成的RECEIVE和SEND应接收“reset”响应，应
刷新所有段队列，用户还应收到未被要求的常规“connection reset”信号，进入CLOSED状
态，删除TCB，返回。
如果SYN不在窗口中，则不会到达该步骤，并且会在第一步中发送ACK（序列号检查）。
*/
    if(flags & TCP_FLAG_SYN){
        switch(pcb->state){
            case TCP_STATE_SYN_RECEIVED:
                if(pcb->parent_sock){
                    destroy_tcp_socket(pcb->sock);
                    return 0;
                }
                /* Active-open SYN_RECEIVED follows the synchronized-state path. */
                __attribute__((fallthrough));
            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_FIN_WAIT_1:
            case TCP_STATE_FIN_WAIT_2:
            case TCP_STATE_CLOSE_WAIT:
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
            case TCP_STATE_TIME_WAIT:
                tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
                return 0;
            default:
                return 0;
        }


    }

/*
第五步，校验ACK字段
如果ACK位关闭，则丢弃段并返回。
如果设置了ACK位，
RFC5961[9]的第5节描述了潜在的盲数据注入攻击，以及实现可以选择包括的缓解（MAY-12）。实
现RFC5961的TCP堆栈必须添加输入检查，以确保只有在ACK值在（((SND.UNA - MAX.SND.WND)
=< SEG.ACK =< SND.NXT)的范围内时，ACK值才可接受。必须丢弃ACK值不满足上述条件的所有
传入段，并发回ACK。新的状态变量MAX.SND.WND被定义为本地发送方从其对端接收到的最大
窗口（受窗口缩放影响），或者可以硬编码为最大允许窗口值。当ACK值可接受时，适用于以下各
个状态处理：
SYN-RECEIVED STATE
如果SND.UNA < SEG.ACK =< SND.NXT，则进入ESTABLISHED状态，并继续处理，设
置以下的变量：
SND.WND <- SEG.WND
SND.WL1 <- SEG.SEQ
SND.WL2 <- SEG.ACK
如果该段的确认不可接受，形成一个重置段
<SEQ=SEG.ACK><CTL=RST>
并发送它。
ESTABLISHED STATE
如果SND.UNA < SEG.ACK =< SND.NXT，那么设置SND.UNA <- SEG.ACK。因此已完全
确认的重传队列上的任何段都被删除。用户应收到已发送和完全确认的缓冲区的肯定确认
（即，SEND缓冲区应返回“ok”响应）。如果ACK是重复的（SEG.ACK=<SND.UNA），则
可以忽略它。如果ACK确认尚未发送的内容（SEG.ACK>SND.NXT），则发送ACK，丢弃
该段，返回。
如果SND.UNA =< SEG.ACK =< SND.NXT，发送窗口应该更新。如果 (SND.WL1 <
SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK))，设置SND.WND <-
SEG.WND，设置SND.WL1 <- SEG.SEQ，并设置SND.WL2 <- SEG.ACK，
请注意SND.WND是来自SND.UNA的偏移量。那个SND.WL1记录用于更新SND.WND的最
后一个段的序列号，SND.WL2记录用于更新SND.WND的最后一个段的确认号。此处的校
验防止使用旧段更新窗口。
FIN-WAIT-1 STATE
除了ESTABLISHED状态的处理外，如果FIN段现在被确认，则进入FIN-WAIT-2并在该状态下继
续处理。
FIN-WAIT-2 STATE
除了ESTABLISHED状态的处理外，如果重传队列为空，则可以确认用户的CLOSE（“ok”），但
不要删除TCB。
CLOSE-WAIT STATE
执行与ESTABLISHED状态相同的处理。
CLOSING STATE
除了ESTABLISHED状态的处理外，如果ACK确认我们的FIN，则进入TIME-WAIT状态；否则，
忽略该段。
LAST-ACK STATE
在这种状态下，唯一可以到达的是对我们的FIN的确认。如果我们的FIN现在已被确认，则删除
TCB，进入CLOSED状态，并返回。
TIME-WAIT STATE
唯一可以达到这种状态的是远程FIN的重传。确认它，并重新启动2 MSL超时。
*/
    if(!(flags & TCP_FLAG_ACK)){
        return 0;
    }
    if(SEQ_LT(ack,pcb->snd_una - pcb->snd_wnd) ||
       SEQ_GT(ack, pcb->snd_nxt)){
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
        return 0;
    }
    switch(pcb->state){
        case TCP_STATE_SYN_RECEIVED:
            if(SEQ_LT(pcb->snd_una, ack) && SEQ_LEQ(ack, pcb->snd_nxt)){
                pcb->state = TCP_STATE_ESTABLISHED;
                pcb->snd_una = ack;
                pcb->last_ack = ack;
                pcb->last_ack_repeat = 0;

                tcp_update_retransmit_queue(pcb);
                tcp_snd_win_change(pcb, window << pcb->snd_wnd_scale);
                pcb->snd_wl1 = seq;
                pcb->snd_wl2 = ack;

                if (sock->options.keepalive) {
                    pcb->keepalive_repeat_count = 0;
                    tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                                     get_current_time_ms() + pcb->keepalive_timeout,
                                     true);
                }

                if(pcb->parent_sock){
                    tcp_pcb* parent_pcb = (tcp_pcb*)pcb->parent_sock->pcb;
                    remove_list_node(&pcb->syn_list);
                    parent_pcb->syn_list_num--;
                    add_list_node(&parent_pcb->accept_list, &pcb->accept_list);
                    parent_pcb->accept_list_num++;
                    socket_notify_event(pcb->parent_sock, notify_new_connection);
                }
            }
            else if(SEQ_LEQ(ack, pcb->snd_una)){
                tcp_send_flag(sock, ack, 0, TCP_FLAG_RST);
                return 0;
            }
            break;
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
            if(SEQ_LT(pcb->snd_una, ack)){
                //ack new data
                uint32_t prior_una = pcb->snd_una;
                uint32_t prior_flight = pcb->snd_nxt - prior_una;
                uint32_t acked_bytes = ack - prior_una;
                bool was_cwnd_limited =
                    (uint64_t)prior_flight + pcb->snd_mss >= pcb->snd_cwnd;
                pcb->snd_una = ack;
                tcp_update_retransmit_queue(pcb);
                pcb->last_ack = ack;
                pcb->last_ack_repeat = 0;

                /* RTT measurement (RFC 6298).
                 * Prefer timestamp-based (TSecr) when available — it is
                 * immune to retransmission ambiguity.
                 * Fall back to sequence-based measurement otherwise. */
                {
                    uint32_t sample = 0;

                    if (pcb->tcp_flag.peer_ts_ok && pcb->ts_last_tsecr) {
                        /* Timestamp echo: how long ago the peer received
                         * our TSval = ts_last_tsecr. */
                        uint64_t now = get_current_time_ms();
                        if (now > pcb->ts_last_tsecr)
                            sample = (uint32_t)(now - pcb->ts_last_tsecr);
                        pcb->ts_last_tsecr = 0;  /* consume once */
                    } else if (pcb->rtt_meas_time &&
                               SEQ_LEQ(pcb->rtt_meas_seq, pcb->snd_una)) {
                        /* Sequence-based fallback (Karn: only non-retransmit). */
                        uint64_t now = get_current_time_ms();
                        sample = (uint32_t)(now - pcb->rtt_meas_time);
                    }

                    if (sample && pcb->metrics) {
                        pcb->retransmit_timeout =
                            tcp_metrics_sample(pcb->metrics, sample);
                    }
                    pcb->rtt_meas_time = 0;
                }

                if(SEQ_LT(pcb->snd_wl1, seq) || (pcb->snd_wl1 == seq && SEQ_LEQ(pcb->snd_wl2, ack))){
                    // update snd win
                    tcp_snd_win_change(pcb, window << pcb->snd_wnd_scale);
                    pcb->snd_wl1 = seq;
                    pcb->snd_wl2 = ack;
                }
                if (tcp_congestion_on_ack(pcb, acked_bytes,
                                          was_cwnd_limited)) {
                    tcp_retransmit_now(pcb);
                }
            }else{
                //ack is repeat (duplicate ACK) — fast retransmit detection
                uint32_t new_wnd = window << pcb->snd_wnd_scale;
                bool window_changed = false;
                if (SEQ_LT(pcb->snd_wl1, seq) ||
                    (pcb->snd_wl1 == seq && SEQ_LEQ(pcb->snd_wl2, ack))) {
                    window_changed = pcb->snd_wnd != new_wnd;
                    tcp_snd_win_change(pcb, new_wnd);
                    pcb->snd_wl1 = seq;
                    pcb->snd_wl2 = ack;
                }
                if (!window_changed && ack == pcb->last_ack && seg_len == 0 && SEQ_GT(pcb->snd_nxt, pcb->snd_una)) {
                    pcb->last_ack_repeat++;
                    if (tcp_congestion_on_duplicate_ack(
                            pcb, pcb->last_ack_repeat)) {
                        tcp_retransmit_now(pcb);
                        DEBUG_LOG("TCP fast retransmit triggered, dupack=%u",
                                 pcb->last_ack_repeat);
                    }
                } else if (ack != pcb->last_ack) {
                    pcb->last_ack = ack;
                    pcb->last_ack_repeat = 0;
                }

                break;
            }
            if(pcb->state == TCP_STATE_FIN_WAIT_1 && pcb->snd_una == pcb->snd_end){
                pcb->state = TCP_STATE_FIN_WAIT_2;
                if(!pcb->sock->fd_entry)
                tcp_update_timer(pcb, &pcb->finwait2_deadline_ms,
                    get_current_time_ms() + pcb->finwait2_timeout, true);
            }
            else if(pcb->state == TCP_STATE_CLOSING){
                if(pcb->snd_una == pcb->snd_end){
                    pcb->state = TCP_STATE_TIME_WAIT;
                    tcp_update_timer(pcb, &pcb->timewait_deadline_ms, get_current_time_ms() + pcb->timewait_timeout, true);
                }
            }
            else if(pcb->state == TCP_STATE_LAST_ACK &&
                    pcb->snd_una == pcb->snd_end){
                destroy_tcp_socket(pcb->sock);
                return 0;
            }

            break;
        case TCP_STATE_TIME_WAIT:
        default:
            break;
    }

/*第六步，校验URG位：
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
如果设置了URG位，那么设置RCV.UP <- max(RCV.UP,SEG.UP)，并且如果紧急指针
（RCV.UP）在消耗的数据之前，则向用户发送信号，告知远程侧具有紧急数据。如果用户已经
收到此连续紧急数据序列的信号（或仍处于“紧急模式”），则不要再次向用户发出信号。
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
这不应该发生，因为已经从远程端接收到FIN。忽略URG。
*/
//to do
/*
第七步，处理段的文本：
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
一旦处于ESTABLISHED状态，就可以将段数据传递到用户RECEIVE缓冲区。来自段的数
据可以移动到缓冲区中，直到缓冲区已满或段为空。如果段清空并带有PUSH标志，则当返
回缓冲区时，通知用户已收到PUSH。
当TCP端点负责将数据交付给用户时，它还必须确认数据的接收。
一旦TCP端点对数据负责，它就会提高RCV.NXT超过接受的数据，并调整RCV.WND适用
于当前可用缓冲区。RCV.NXT与RCV.WND的和不应降低。
当一个有效段到达时，该段位于窗口中，但不在窗口左侧边缘，TCP实现可以发送确认
RCV.NXT的ACK段（MAY-13）。
请注意第3.8节中的窗口管理建议。
发送一个该格式的确认：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
如果可能，该确认应捎带（piggybacked ）在正在传输的段上，而不会引起过度的延迟。
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
这不应该发生，因为已经从远程端接收到FIN。忽略段文本。
*/
switch(pcb->state){
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
        if(data_len > 0){
            if (tcp_recv_data(pcb, skb)) {
                if (++pcb->ack_pending_segments >= 3) {
                    tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                                     get_current_time_ms(), true);
                } else {
                    tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                                     get_current_time_ms() + pcb->ack_timeout,
                                     false);
                }
            }
        }
        break;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_TIME_WAIT:
    default:
        break;
}
/*
第八步，校验FIN位：
如果由于SEG.SEQ无法验证导致状态为CLOSED、LISTEN或SYN-SENT，则不要处理FIN；丢弃段
并返回。
如果设置了FIN位，则向用户发出“connection closing”信号，并以相同消息返回任何即将发送的
RECEIVE，基于FIN提高RCV.NXT，并发送FIN的确认。请注意，FIN表示对任何段文本的PUSH都
尚未传递给用户。
SYN-RECEIVED STATE
ESTABLISHED STATE
进入CLOSE-WAIT状态
FIN-WAIT-1 STATE
如果我们的FIN已被确认（可能在该段中），则进入TIME-WAIT，启动时间等待计时器，关闭其
他计时器；否则，进入CLOSING状态。
FIN-WAIT-2 STATE
进入TIME-WAIT状态。启动时间等待计时器，关闭其他计时器。
CLOSE-WAIT STATE
Remain in the CLOSE-WAIT state.
保持在CLOSE-WAIT状态。
CLOSING STATE
保持在CLOSING状态。
LAST-ACK STATE
保持在LAST-ACK状态。
TIME-WAIT STATE
保持在TIME-WAIT状态。重启2 MSL时间等待超时。
并返回。
    */
    if(pcb->state == TCP_STATE_CLOSED || pcb->state == TCP_STATE_SYN_SENT) {
        return 0;
    }
    if ((flags & TCP_FLAG_FIN) && pcb->state == TCP_STATE_TIME_WAIT &&
        seq + data_len + 1u == pcb->rcv_nxt) {
        uint64_t now_ms = get_current_time_ms();
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, now_ms, true);
        tcp_update_timer(pcb, &pcb->timewait_deadline_ms,
                         now_ms + pcb->timewait_timeout, true);
        return 0;
    }

    if((flags & TCP_FLAG_FIN) && (seq + data_len == pcb->rcv_nxt)) {
        pcb->rcv_nxt++;

        pcb->tcp_flag.recv_fin = 1;
        socket_notify_event(sock, notify_recv_fin);
        pcb->keepalive_repeat_count = 0;
        tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                         TCP_TIMER_STOP, true);

        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
        switch(pcb->state) {
            case TCP_STATE_SYN_RECEIVED:
            case TCP_STATE_ESTABLISHED:
                pcb->state = TCP_STATE_CLOSE_WAIT;
                break;
            case TCP_STATE_FIN_WAIT_1:
                if(pcb->snd_una == pcb->snd_end){
                    pcb->state = TCP_STATE_TIME_WAIT;
                    tcp_update_timer(pcb, &pcb->timewait_deadline_ms, get_current_time_ms() + pcb->timewait_timeout, false);
                }else {
                    pcb->state = TCP_STATE_CLOSING;
                }
                break;
            case TCP_STATE_FIN_WAIT_2:
                pcb->state = TCP_STATE_TIME_WAIT;
                tcp_update_timer(pcb, &pcb->finwait2_deadline_ms, TCP_TIMER_STOP, true);
                tcp_update_timer(pcb, &pcb->timewait_deadline_ms, get_current_time_ms() + pcb->timewait_timeout, false);
                break;
            case TCP_STATE_CLOSE_WAIT:
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
                break;
            case TCP_STATE_TIME_WAIT:
                tcp_update_timer(pcb, &pcb->timewait_deadline_ms, get_current_time_ms() + pcb->timewait_timeout, true);
                break;
            default:
                break;
        }
    }

    if (sock->options.keepalive && pcb->state == TCP_STATE_ESTABLISHED) {
        pcb->keepalive_repeat_count = 0;
        tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                         get_current_time_ms() + pcb->keepalive_timeout, true);
    }
    return 0;
}
static void make_tcp_hdr(tcp_pcb* pcb, skbuff* skb){
    uint8_t flags = skb->l4_private.tcp.flag;
    uint32_t opt_len = make_tcp_options(pcb, skb);

    tcp_hdr* hdr = (tcp_hdr*)skb_data_push(skb, sizeof(tcp_hdr));
    memset(hdr, 0, sizeof(tcp_hdr));

    hdr->sport = pcb->sock->sport;
    hdr->dport = pcb->sock->dport;

    hdr->seq = htonl(skb->l4_private.tcp.seq);
    hdr->ack_seq = htonl(pcb->rcv_nxt);

    hdr->flags = flags;
    hdr->doff_res_flags = (uint8_t)(((sizeof(tcp_hdr) + opt_len) / 4) << 4);

    hdr->window = htons((uint16_t)min(pcb->rcv_wnd >> pcb->rcv_wnd_scale,
                                      65535u));
    hdr->urg_ptr = 0;

    hdr->check = 0;
    if (pcb->sock->family == AF_INET6)
        hdr->check = skb_checksum_protocol6(skb, skb_data_len(skb),
                                       pcb->sock->sip6, pcb->sock->dip6, IPPROTO_TCP);
    else
        hdr->check = skb_checksum_protocol(skb, skb_data_len(skb),
                                       pcb->sock->sip, pcb->sock->dip, IPPROTO_TCP);
}

int tcp_output(tcp_pcb* pcb){
    uint32_t sent_count = 0;
output_next:
    Socket* sock=pcb->sock;
    uint32_t win_min = min(pcb->snd_wnd, pcb->snd_cwnd);
    skbuff* skb=NULL;
    skbuff* send_skb = NULL;
    bool add_retransmit = false;
    uint32_t seg_limit = 0;


    if(pcb->tcp_flag.retransmit_trigger){
        skb = SKB_FROM_QUEUE_NODE(get_queue_first(&pcb->retransmit_queue));
        if(!skb) {
            return 0;
        }
    }
    else if(pcb->tcp_flag.nagle_trigger){
        skb = SKB_FROM_QUEUE_NODE(get_queue_first(&sock->send_queue));
        if(!skb)
            return 0;
        add_retransmit = true;
    }else if(pcb->tcp_flag.persist_trigger){
        if(pcb->retransmit_queue.element_number){
            skb = SKB_FROM_QUEUE_NODE(get_queue_first(&pcb->retransmit_queue));
            if (!skb)
                return 0;
        }else if(sock->send_queue.element_number){
            skb = SKB_FROM_QUEUE_NODE(get_queue_first(&sock->send_queue));
            if(!skb)
                return 0;
            add_retransmit = true;
        }else{
            return 0;
        }
    }else{
        return 0;
    }
    uint32_t seg_len = skb_data_len(skb) + ((skb->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1 : 0) + ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1 : 0);

    //win limit
    if(!pcb->tcp_flag.persist_trigger){
        uint32_t window_end = pcb->snd_una + win_min;

        if (!win_min || SEQ_GEQ(skb->l4_private.tcp.seq, window_end))
            return 0;

        if(SEQ_GT(skb->l4_private.tcp.seq + seg_len, window_end)){
            seg_limit = window_end - skb->l4_private.tcp.seq;
        }
    }else if(seg_len > 1){
        seg_limit = 1;
    }
    send_skb = skb_clone(skb);
    if(!send_skb){
        return -1;
    }
    uint8_t original_flags = skb->l4_private.tcp.flag;
    uint32_t original_data_len = skb_data_len(skb);
    uint32_t syn_seq_len = (original_flags & TCP_FLAG_SYN) ? 1u : 0u;
    uint32_t send_data_len = original_data_len;
    bool send_fin = (original_flags & TCP_FLAG_FIN) != 0;

    if(seg_limit){
        uint32_t payload_budget = seg_limit > syn_seq_len
            ? seg_limit - syn_seq_len : 0u;
        send_data_len = min(original_data_len, payload_budget);
        send_fin = (original_flags & TCP_FLAG_FIN) &&
                   seg_limit > syn_seq_len + original_data_len;

        skb_truncate(send_skb, send_data_len);
        if (!send_fin)
            send_skb->l4_private.tcp.flag &= ~TCP_FLAG_FIN;

        seg_len = syn_seq_len + send_data_len + (send_fin ? 1u : 0u);
    }
    if(set_tcp_socket_route(sock, sock->family == AF_INET6 ? sock->dip6 : (const uint8_t*)&sock->dip,
                            sock->family == AF_INET6 ? sock->dip6_scope_id : 0) < 0){
        PUT_REF(send_skb);
        sock->error = EHOSTUNREACH;
        socket_notify_event(sock, notify_err);
        return -1;
    }
    set_skb_by_socket(send_skb, sock);

    if(add_retransmit && !seg_limit && skb_data_len(send_skb) &&
       sock->send_queue.element_number == 1){
        send_skb->l4_private.tcp.flag |= TCP_FLAG_PSH;
    }

    make_tcp_hdr(pcb, send_skb);
    int ret = (sock->family == AF_INET6)
        ? ipv6_output(send_skb) : ipv4_output(send_skb);
    if (ret < 0) {
        PUT_REF(send_skb);

        /* The packet was not accepted by the output queue.  New data must
         * remain on send_queue and snd_nxt must not move past an unsent
         * segment.  Retry it after a short delay instead of waiting for an
         * RTO for data that never left this host. */
        if (add_retransmit) {
            tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                             get_current_time_ms() + pcb->nagle_interval,
                             false);
        }
        return ret;
    }

    tcp_update_timer(pcb, &pcb->ack_deadline_ms, TCP_TIMER_STOP, false);
    if(add_retransmit){
        pcb->snd_nxt += seg_len;
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
            get_current_time_ms() + pcb->retransmit_timeout, false);
        if(send_skb->l4_private.tcp.flag & TCP_FLAG_FIN){
            switch(pcb->state){
                case TCP_STATE_SYN_RECEIVED:
                case TCP_STATE_ESTABLISHED:
                    pcb->state = TCP_STATE_FIN_WAIT_1;
                    break;
                case TCP_STATE_CLOSE_WAIT:
                    pcb->state = TCP_STATE_LAST_ACK;
                    break;
                default:
                    break;
            }
        }

        if (!pcb->rtt_meas_time ) {
            pcb->rtt_meas_time = get_current_time_ms();
            pcb->rtt_meas_seq  = skb->l4_private.tcp.seq ;
        }

        if(seg_limit){
            bool tail_has_data = send_data_len < original_data_len;
            bool tail_has_fin = (original_flags & TCP_FLAG_FIN) && !send_fin;
            skbuff* tail_skb = NULL;

            if (tail_has_data) {
                tail_skb = skb_split(skb, send_data_len);
            } else if (tail_has_fin) {
                uint32_t fin_l2_len = sock->route->if_info->l2_len;
                uint32_t fin_hdr_len = MAX_TCP_HDR_OPT_LEN +
                    (sock->family == AF_INET6 ? MAX_IP6_HDR_WITH_EXT_LEN
                                              : MAX_IP_HDR_WITH_OPT_LEN) +
                    fin_l2_len;
                tail_skb = skb_alloc(fin_hdr_len);
                if (tail_skb) {
                    skb_reserve(tail_skb, fin_hdr_len);
                    tail_skb->l4_private = skb->l4_private;
                }
            }

            if ((tail_has_data || tail_has_fin) && !tail_skb) {
                PUT_REF(send_skb);
                return -ENOMEM;
            }

            (void)pop_queue(&sock->send_queue);
            if (tail_skb) {
                tail_skb->l4_private.tcp.flag =
                    original_flags & (uint8_t)~TCP_FLAG_SYN;
                tail_skb->l4_private.tcp.seq =
                    skb->l4_private.tcp.seq + seg_len;
                add_queue_first(&sock->send_queue, &tail_skb->queue_node);
            }

            if (!send_fin)
                skb->l4_private.tcp.flag &= ~TCP_FLAG_FIN;
            (void)tcp_retransmit_enqueue(pcb, skb);
        }else{
            skbuff* queued_skb =
                SKB_FROM_QUEUE_NODE(pop_queue(&sock->send_queue));
            if (queued_skb)
                (void)tcp_retransmit_enqueue(pcb, queued_skb);
        }
    }
    PUT_REF(send_skb);
    sent_count++;
    if (pcb->tcp_flag.nagle_trigger && sock->send_queue.element_number) {
        if (sent_count >= TCP_OUTPUT_BURST_MAX) {
            tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                             get_current_time_ms(), false);
            return ret;
        }
        goto output_next;
    }
    return ret;
}
static int tcp_connect(Socket *sock, req* req, const sockaddr_in *addr, socklen_t addrlen)
{
    int ret = 0;
    bool is_v6 = sock->family == AF_INET6;
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)addr;
    tcp_pcb* pcb = sock->pcb;
    socklen_t required = is_v6 ? sizeof(*addr6) : sizeof(*addr);

    if (req->status == REQ_WAITING_CONNECT)
        goto retry;
    if (!addr) {
        req->saved_errno = EFAULT;
        return -1;
    }
    if (addrlen < required) {
        req->saved_errno = EINVAL;
        return -1;
    }
    if (addr->sin_family != sock->family) {
        req->saved_errno = EAFNOSUPPORT;
        return -1;
    }
    if (pcb->state == TCP_STATE_SYN_SENT || pcb->state == TCP_STATE_SYN_RECEIVED) {
        req->saved_errno = EALREADY;
        return -1;
    }
    if (sock->flag.is_connected)
    {
        req->saved_errno = EISCONN;
        return -1;
    }
    if (pcb->state != TCP_STATE_CLOSED)
    {
        DEBUG_LOG("TCP Socket in invalid state %d for connect", pcb->state);
        req->saved_errno = EINVAL;
        return -1;
    }
    if(set_tcp_socket_route(sock,
        is_v6 ? (const uint8_t*)&addr6->sin6_addr : (const uint8_t*)&addr->sin_addr.s_addr,
        is_v6 ? addr6->sin6_scope_id : 0) < 0){
        req->saved_errno = EHOSTUNREACH;
        ret = -1;
        goto exit;
    }

    if (!sock->flag.is_bound)
    {
        if(socket_auto_bind(sock, tcp_bound_table(sock->family),
            is_v6 ? (const uint8_t*)&addr6->sin6_addr : (const uint8_t*)&addr->sin_addr.s_addr,
            is_v6 ? addr6->sin6_port : addr->sin_port,
            is_v6 ? addr6->sin6_scope_id : 0) < 0)
        {
            req->saved_errno = EADDRNOTAVAIL;
            ret = -1;
            goto exit;
        }
    }
    else if ((is_v6 && IN6_IS_ADDR_UNSPECIFIED(
                           (const struct in6_addr*)sock->sip6)) ||
             (!is_v6 && sock->sip == INADDR_ANY))
    {
        /* Socket bound to any-address: pick a concrete source IP for this destination. */
        route_key key = { .ip_family = is_v6 ? AF_INET6 : AF_INET };
        if (is_v6) {
            key.ifindex = addr6->sin6_scope_id;
            memcpy(key.dip, &addr6->sin6_addr, 16);
        } else {
            memcpy(key.dip, &addr->sin_addr.s_addr, 4);
        }
        route_key answer;
        if (!search_best_saddr_by_daddr(&key, &answer))
        {
            req->saved_errno = EADDRNOTAVAIL;
            ret = -1;
            goto exit;
        }

        uint16_t bound_port = sock->sport;
        uint32_t original_scope_id = sock->sip6_scope_id;
        addr_key old_key = { .port = bound_port,
                             .family = is_v6 ? AF_INET6 : AF_INET,
                             .scope_id = original_scope_id };
        if (is_v6) {
            static const uint8_t zero6[16];
            memcpy(old_key.addr6, zero6, 16);
        } else {
            old_key.addr = INADDR_ANY;
        }
        unbind_saddr(sock, tcp_bound_table(sock->family));

        addr_key new_key = { .port = bound_port,
                             .family = is_v6 ? AF_INET6 : AF_INET };
        if (is_v6) {
            memcpy(new_key.addr6, answer.dip, 16);
        } else {
            memcpy(&new_key.addr, answer.dip, 4);
        }
        if (!bind_saddr(sock, &new_key, tcp_bound_table(sock->family)))
        {
            WARN_LOG("Failed to re-bind TCP Socket on connect");
            bind_saddr(sock, &old_key, tcp_bound_table(sock->family));
            req->saved_errno = EADDRNOTAVAIL;
            ret = -1;
            goto exit;
        }
        if (is_v6)
            memcpy(sock->sip6, answer.dip, 16);
        else
            memcpy(&sock->sip, answer.dip, 4);
    }
    if (is_v6) {
        memcpy(sock->dip6, &addr6->sin6_addr, 16);
        sock->dip6_scope_id = addr6->sin6_scope_id;
        sock->dport = addr6->sin6_port;
    } else {
        sock->dip = addr->sin_addr.s_addr;
        sock->dport = addr->sin_port;
    }

    /* Ensure the final (sip, sport, dip, dport) tuple maps to this worker. */
    {
        uint16_t dest_port = is_v6 ? addr6->sin6_port : addr->sin_port;
        worker* tuple_worker = select_worker_by_tuple(sock->family,
            is_v6 ? sock->sip6 : (const uint8_t*)&sock->sip,
            is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip,
            sock->sport, dest_port);
        if (tuple_worker != get_current_worker()) {
            set_socket_worker(sock, tuple_worker);
            change_req_worker(req, tuple_worker);
            return REQ_PENDING;
        }
    }

    if (!install_tuple(sock, tcp_tuple_hash(sock->family)))
    {
        req->saved_errno = EADDRINUSE;
        ret = -1;
        goto exit;
    }

    pcb->state = TCP_STATE_SYN_SENT;
    ret = tcp_send_flag(sock, pcb->snd_nxt, 0, TCP_FLAG_SYN);
    if (ret < 0) {
        req->saved_errno = ret == -ENOMEM ? ENOMEM : ENETUNREACH;
        pcb->state = TCP_STATE_CLOSED;
        goto exit;
    }

    sock->flag.is_connected = true;

    if(pcb->state != TCP_STATE_SYN_SENT){
        //send to self
        goto retry;
    }
    if (sock->file_flags & O_NONBLOCK) {
        req->saved_errno = EINPROGRESS;
        return -1;
    }
    if(sock->options.send_timeout){
        wait_until(sock, req, REQ_WAITING_CONNECT, get_current_time_ms() + get_time(&sock->send_timeout));
        return REQ_PENDING;
    }
    wait(sock, req, REQ_WAITING_CONNECT);
    return REQ_PENDING;
retry:
    if (sock->error) {
        req->saved_errno = sock->error;
        sock->error = 0;
        ret = -1;
        goto exit;
    }
    bool is_expired = false;
    if(req->timeout_task && req->timeout_task->timeout <= get_current_time_ms())
        is_expired = true;
    if(pcb->state==TCP_STATE_ESTABLISHED || pcb->state==TCP_STATE_CLOSE_WAIT){
        ret=0;
    }else if(pcb->state==TCP_STATE_SYN_SENT || pcb->state==TCP_STATE_SYN_RECEIVED){
        if(is_expired){
            req->saved_errno = ETIMEDOUT;
            ret=-1;
        }else{
            ret = REQ_PENDING;
        }
    }else {
        req->saved_errno = ECONNREFUSED;
        DEBUG_LOG("TCP connect failed with state %d", pcb->state);
        ret = -1;
    }
    
exit:
    if (ret < 0) {
        pcb->state = TCP_STATE_CLOSED;
        tcp_abort_connect(sock);
    }
    return ret;
}
static int tcp_bind(Socket *sock, req* r, const sockaddr_in *addr, socklen_t addrlen)
{
    int ret = 0;
    bool is_v6 = sock->family == AF_INET6;
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)addr;
    socklen_t required = is_v6 ? sizeof(*addr6) : sizeof(*addr);
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    if (!addr) {
        r->saved_errno = EFAULT;
        ret = -1;
        goto exit;
    }
    if (addrlen < required) {
        r->saved_errno = EINVAL;
        ret = -1;
        goto exit;
    }
    if (addr->sin_family != sock->family) {
        r->saved_errno = EAFNOSUPPORT;
        ret = -1;
        goto exit;
    }
    uint16_t port = is_v6 ? addr6->sin6_port : addr->sin_port;
    if (!port)
    {
        r->saved_errno = EINVAL;
        ret = -1;
        goto exit;
    }
    if (sock->flag.is_bound)
    {
        r->saved_errno = EADDRINUSE;
        ret = -1;
        goto exit;
    }
    if(pcb->state != TCP_STATE_CLOSED){
        DEBUG_LOG("TCP Socket in invalid state %d for bind", pcb->state);
        r->saved_errno = EINVAL;
        ret = -1;
        goto exit;
    }
    static const uint8_t zero6[16];
    const uint8_t* ip = is_v6 ? (const uint8_t*)&addr6->sin6_addr
                              : (const uint8_t*)&addr->sin_addr.s_addr;
    bool any = is_v6 ? memcmp(ip, zero6, 16) == 0
                     : addr->sin_addr.s_addr == INADDR_ANY;
    if (is_v6 && IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && !addr6->sin6_scope_id) {
        r->saved_errno = EINVAL;
        DEBUG_LOG("IPv6 link-local bind requires a scope ID (e.g. fe80::1%%eth0)");
        ret = -1;
        goto exit;
    }
    if (!any && !search_addr_exist(sock->family, ip,
            is_v6 ? addr6->sin6_scope_id : 0))
    {
        DEBUG_LOG("IP address is not available for family=%d", sock->family);
        r->saved_errno = EADDRNOTAVAIL;
        ret = -1;
        goto exit;
    }

    addr_key key = {
        .port = port,
        .family = is_v6 ? AF_INET6 : AF_INET,
        .scope_id = is_v6 ? addr6->sin6_scope_id : 0
    };
    if (is_v6)
        memcpy(key.addr6, ip, 16);
    else
        memcpy(&key.addr, ip, 4);
    if (!bind_saddr(sock, &key, tcp_bound_table(sock->family)))
    {
        r->saved_errno = EADDRINUSE;
        ret = -1;
        goto exit;
    }
    if (is_v6)
        sock->sip6_scope_id = addr6->sin6_scope_id;
exit:
    return ret;
}

static int tcp_write(Socket* sock, req* req, const void *buf, uint32_t len)
{
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    uint32_t send_len = 0;
    if (sock->error) {
        req->saved_errno = sock->error;
        sock->error = 0;
        return -1;
    }
    if (!len) {
        return 0;
	}
	if (sock->flag.close_send) {
		req->saved_errno = EPIPE;
		return -1;
	}

    if(!buf){
        req->saved_errno = EFAULT;
        ret = -1;
        goto exit;
    }
    if(!sock->flag.is_connected || !sock->flag.is_bound){
        req->saved_errno = ENOTCONN;
        ret = -1;
        goto exit;
    }
    switch(pcb->state){
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:
            /* Established sockets can send immediately; data queued during
             * the handshake is sent once the connection is established. */
            break;
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
            req->saved_errno = EPIPE;
            ret = -1;
            goto exit;
        case TCP_STATE_LISTEN:
        case TCP_STATE_CLOSED:
            DEBUG_LOG("TCP Socket in invalid state %d for write", pcb->state);
            req->saved_errno = ENOTCONN;
            ret = -1;
            goto exit;
    }
    /* Check send buffer space (blocking/non-blocking). */
    if(sock->send_buffer_len >= sock->send_buffer_len_max){
        if(sock->file_flags & O_NONBLOCK){
            req->saved_errno = EAGAIN;
            ret=-1;
            goto exit;
        }
        if (req->status == REQ_WAITING_WRITE && req->timeout_task &&
            req->timeout_task->timeout <= get_current_time_ms()) {
            req->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        if(sock->options.send_timeout){
            wait_until(sock,req,REQ_WAITING_WRITE, get_current_time_ms() + get_time(&sock->send_timeout));
        } else {
            wait(sock,req,REQ_WAITING_WRITE);
        }
        return REQ_PENDING;
    }
    if(set_tcp_socket_route(sock, sock->family == AF_INET6 ? sock->dip6 : (const uint8_t*)&sock->dip,
                            sock->family == AF_INET6 ? sock->dip6_scope_id : 0) < 0){
        req->saved_errno = EHOSTUNREACH;
        ret = -1;
        goto exit;
    }

    /* Cap total bytes to available send buffer space. */
    uint32_t space = sock->send_buffer_len_max - sock->send_buffer_len;
    if (len > space) {
        DEBUG_LOG("TCP send buffer only has %u bytes, truncating write from %u", space, len);
        len = space;
    }

    /* Effective per-segment data limit = MSS minus current TCP options. */
    uint32_t seg_limit = pcb->snd_mss;
    if (pcb->tcp_flag.peer_ts_ok)
        seg_limit -= 12u;  /* Timestamps */

    /* Loop: append data across one or more skbs. */
    while (send_len < len) {
        uint32_t chunk = (len - send_len);
        if (chunk > seg_limit)
            chunk = seg_limit;

        skbuff* skb = SKB_FROM_QUEUE_NODE(get_queue_last(&sock->send_queue));

        /* Need a new skb if the last one is full or doesn't exist. */
        if (!skb || skb_data_len(skb) + chunk > seg_limit) {
            uint32_t send_l2_len = sock->route->if_info->l2_len ;
            uint32_t tcp_hdr_len = MAX_TCP_HDR_OPT_LEN +
                (sock->family == AF_INET6 ? MAX_IP6_HDR_WITH_EXT_LEN
                                          : MAX_IP_HDR_WITH_OPT_LEN) +
                send_l2_len;
            skb = skb_alloc(tcp_hdr_len + chunk);
            if (!skb) {
                ERR_LOG("Failed to allocate skb for TCP write");
                break;
            }
            skb_reserve(skb, tcp_hdr_len);
            skb->l4_private.tcp.seq = pcb->snd_end;
            skb->l4_private.tcp.flag = TCP_FLAG_ACK;
            add_queue(&sock->send_queue, &skb->queue_node);
        }

        if (!skb_data_append(skb, (uint8_t*)buf + send_len, chunk, 0, seg_limit)) {
            ERR_LOG("Failed to append data to skb for TCP write");
            break;
        }

        pcb->snd_end += chunk;
        sock->send_buffer_len += chunk;
        send_len += chunk;
    }

    if (send_len == 0) {
        req->saved_errno = ENOMEM;
        ret = -1;
        goto exit;
    }

    skbuff* first_skb = SKB_FROM_QUEUE_NODE(get_queue_first(&sock->send_queue));
    if (pcb->tcp_options.nodelay
        || (first_skb && skb_data_len(first_skb) >= seg_limit)
        || sock->send_queue.element_number > 1) {
        pcb->tcp_flag.nagle_trigger = 1;
        (void)tcp_output(pcb);
        pcb->tcp_flag.nagle_trigger = 0;
    } else {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                         get_current_time_ms() + pcb->nagle_interval, false);
    }

    ret = (int)send_len;
exit:
    return ret < 0 ? -1 : ret;
}
static int tcp_read(Socket* sock,req* req,void *buf,uint32_t len)
{
    int ret = 0;
    tcp_pcb* pcb = sock->pcb;
    if (sock->error) {
        req->saved_errno = sock->error;
        sock->error = 0;
        return -1;
    }
    if (sock->flag.close_recv)
        return 0;
    if (!sock->recv_queue.element_number && pcb->tcp_flag.recv_fin)
        return 0;

    switch (pcb->state) {
        case TCP_STATE_CLOSED:
            if (pcb->tcp_flag.recv_fin &&
                sock->recv_queue.element_number)
                break;
            req->saved_errno = ENOTCONN;
            ret = -1;
            goto exit;
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
            break;
        default:
            req->saved_errno = ENOTCONN;
            ret = -1;
            goto exit;
    }
    /* If recv queue is empty, either return EOF or wait */
    if (!sock->recv_queue.element_number) {
        if (sock->file_flags & O_NONBLOCK) {
            req->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        if (req->status == REQ_WAITING_READ && req->timeout_task &&
            req->timeout_task->timeout <= get_current_time_ms()) {
            req->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        if (sock->options.recv_timeout) {
            wait_until(sock, req, REQ_WAITING_READ, get_current_time_ms() + get_time(&sock->recv_timeout));
            return REQ_PENDING;
        }
        wait(sock, req, REQ_WAITING_READ);
        return REQ_PENDING;
    }

    uint32_t copied = 0;
    while (copied < len) {
        skbuff* skb = SKB_FROM_QUEUE_NODE(get_queue_first(&sock->recv_queue));
        if (!skb) break;

        uint32_t avail = skb_data_len(skb);
        if (avail == 0) {
            pop_queue(&sock->recv_queue);
            PUT_REF(skb);
            continue;
        }

        uint32_t n = (avail <= (len - copied)) ? avail : (len - copied);

        /* 使用 skb_copy_bits 正确处理 scatter-gather 多缓冲区 */
        if (!skb_copy_bits(skb, 0, (uint8_t*)buf + copied, n)) {
            ERR_LOG("tcp_read: skb_copy_bits failed");
            if (!copied) {
                req->saved_errno = EIO;
                ret = -1;
                goto exit;
            }
            break;
        }
        copied += n;

        sock->recv_buffer_len -= n;

        if (n < avail) {
            /* 没读完：consume 截断开头（跨 fragment 安全），skb 留在队首 */
            skb_consume(skb, n, false);
            break;
        }

        /* 完全读完：出队释放 */
        pop_queue(&sock->recv_queue);
        PUT_REF(skb);
    }
    uint32_t old_wnd = pcb->rcv_wnd;
    pcb->rcv_wnd = min(SOCKET_USEABLE_RECV_BUFF_SIZE(pcb->sock),
                       pcb->sock->recv_buffer_len_max);
    if (pcb->rcv_wnd > old_wnd) {
        /* A blocked peer needs a prompt window update after userspace drains
         * the receive queue; otherwise it can wait for a persist probe. */
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
    }

    ret = (int)copied;

exit:
    return ret;
}
static int tcp_accept(Socket* sock,req* r, sockaddr_in *addr, socklen_t *addrlen){
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    tcp_pcb* child_pcb;
    if(pcb->state!=TCP_STATE_LISTEN){
        //WARN_LOG("TCP Socket in invalid state %d for accept", pcb->state);
        r->saved_errno = EINVAL;
        ret = -1;
        goto exit;
    }
    if(!pcb->accept_list_num){
        if(sock->file_flags & O_NONBLOCK){
            r->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        if (r->status == REQ_WAITING_ACCEPT && r->timeout_task &&
            r->timeout_task->timeout <= get_current_time_ms()) {
            r->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        if (sock->options.recv_timeout)
            wait_until(sock, r, REQ_WAITING_ACCEPT,
                       get_current_time_ms() + get_time(&sock->recv_timeout));
        else
            wait(sock, r, REQ_WAITING_ACCEPT);
        return REQ_PENDING;
    }
    child_pcb = (tcp_pcb*)((uint8_t*)pcb->accept_list.next - offsetof(tcp_pcb, accept_list));
    Socket* child_sock = child_pcb->sock;

    if (addr && !addrlen) {
        r->saved_errno = EFAULT;
        ret = -1;
        goto exit;
    }

    /* Fill peer address with the same bounded-copy semantics as accept(2). */
    if (addr) {
        bool is_v6_accept = (sock->family == AF_INET6);
        socklen_t required_len = is_v6_accept ? sizeof(struct sockaddr_in6) : sizeof(sockaddr_in);
        struct sockaddr_storage out;
        memset(&out, 0, sizeof(out));
        if (is_v6_accept) {
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&out;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port   = child_sock->dport;
            memcpy(&addr6->sin6_addr, child_sock->dip6, 16);
            addr6->sin6_scope_id = child_sock->dip6_scope_id;
        } else {
            struct sockaddr_in* addr4 = (struct sockaddr_in*)&out;
            addr4->sin_family      = AF_INET;
            addr4->sin_addr.s_addr = child_sock->dip;
            addr4->sin_port        = child_sock->dport;
        }
        socklen_t capacity = *addrlen < required_len ? *addrlen : required_len;
        if (capacity)
            memcpy(addr, &out, capacity);
        *addrlen = required_len;
    }

    worker* child_worker = select_worker_by_tuple(child_sock->family,
        child_sock->dip6, child_sock->sip6,
        child_sock->dport, child_sock->sport);
    fd_entry* entry = alloc_fd_entry_with_worker(child_sock, &socket_fd_ops,
                                                 child_worker);
    if(!entry){
        ERR_LOG("Failed to allocate fd entry for child socket");
        r->saved_errno = EMFILE;
        ret = -1;
        goto exit;
    }
    child_sock->fd_entry = entry;
    remove_list_node(&child_pcb->accept_list);
    child_pcb->parent_sock = NULL;
    pcb->accept_list_num--;
    ret = entry->fd;
    set_socket_worker(child_sock, child_worker);
exit:
    return ret;
}
static int tcp_listen(Socket* sock,req* req,int backlog){
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    if(!sock->flag.is_bound){
        req->saved_errno = EINVAL;
        ret = -1;
        goto exit;
    }
    if(pcb->state != TCP_STATE_CLOSED){
        DEBUG_LOG("TCP Socket in invalid state %d for listen", pcb->state);
        req->saved_errno = EINVAL;
        ret = -1;
        goto exit;
    }
    if(!install_tuple(sock, tcp_tuple_hash(sock->family))){
        req->saved_errno = EADDRINUSE; 
        ret = -1;
        goto exit;
    }

    pcb->state=TCP_STATE_LISTEN;
    pcb->backlog = max(backlog, 1);

exit:
    return ret;
}
static int tcp_release(Socket* sock, req* req){
    (void)req;
    tcp_pcb* pcb=sock->pcb;
    switch(pcb->state){
        case TCP_STATE_CLOSED:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_LISTEN:
            pcb->state=TCP_STATE_CLOSED;
            destroy_tcp_socket(sock);
            break;
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
            if (!sock->flag.close_send) {
                sock->flag.close_send = 1;
                tcp_send_fin(pcb);
            }
            break;
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
            /* Already sent FIN — socket is now orphan.
             * Reduce persist retries so a dead peer doesn't
             * keep the socket alive forever.  (Linux tcp_orphan_retries) */
            pcb->retries_max = TCP_ORPHAN_RETRIES_DEFAULT;
            break;
        case TCP_STATE_FIN_WAIT_2:
            pcb->retries_max = TCP_ORPHAN_RETRIES_DEFAULT;
            tcp_update_timer(pcb, &pcb->finwait2_deadline_ms,
                get_current_time_ms() + pcb->finwait2_timeout, true);
            break;
        case TCP_STATE_TIME_WAIT:
            /* The peer FIN has already been acknowledged.  Keep the PCB
             * alive until the existing TIME-WAIT timer expires so duplicate
             * segments can still be answered; closing the user fd needs no
             * further TCP action. */
            break;
        default:
            ERR_LOG("tcp_release: unexpected TCP state %d on release", pcb->state);
            break;
    }
    return 0;
}
static int tcp_setsockopt(Socket* sock,req* req,int level,int optname,const void* optval,socklen_t optlen){
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    (void)req;
    switch(level){
        case SOL_SOCKET:
            ret = socket_setsockopt(sock, level, optname, optval, optlen);
            if (ret < 0 && req->saved_errno == 0) {
                req->saved_errno = ENOPROTOOPT;
            } else if (ret == 0 && optname == SO_KEEPALIVE) {
                pcb->keepalive_repeat_count = 0;
                if (sock->options.keepalive &&
                    pcb->state == TCP_STATE_ESTABLISHED) {
                    tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                                     get_current_time_ms() + pcb->keepalive_timeout,
                                     true);
                } else {
                    tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                                     TCP_TIMER_STOP, true);
                }
            }
            break;
        case IPPROTO_TCP:
            switch (optname)
            {
            case TCP_NODELAY:
                if (optlen >= sizeof(int))
                {
                    pcb->tcp_options.nodelay = (*(int*)optval != 0);
                }
                else
                {
                    req->saved_errno = EINVAL;
                    ret = -1;
                }
                break;
            case TCP_CORK:
                if (optlen >= sizeof(int))
                {
                    pcb->tcp_options.cork = (*(int*)optval != 0);
                }
                else
                {
                    req->saved_errno = EINVAL;
                    ret = -1;
                }
                break;
            case TCP_QUICKACK:
                if (optlen >= sizeof(int))
                {
                    pcb->tcp_options.quickack = (*(int*)optval != 0);
                }
                else
                {
                    req->saved_errno = EINVAL;
                    ret = -1;
                }
                break;
            default:
                req->saved_errno = ENOPROTOOPT;
                ret = -1;
                break;
            }
            break;
        default:
            DEBUG_LOG("tcp_setsockopt: unsupported level=%d optname=%d",
                      level, optname);
            req->saved_errno = ENOPROTOOPT;
            ret = -1;
            break;
    }

    
    return ret;
}
static int tcp_getsockopt(Socket* sock,req* req,int level,int optname,void* optval,socklen_t* optlen){
    int ret = 0;

    tcp_pcb* pcb=sock->pcb;
    switch(level){
        case SOL_SOCKET:
            /* 复用通用 SOL_SOCKET 选项处理：SO_REUSEADDR/RCVBUF/RCVTIMEO/... */
            ret = socket_getsockopt(sock, level, optname, optval, optlen);
            if (ret < 0 && req->saved_errno == 0)
                req->saved_errno = ENOPROTOOPT;
            break;
        case IPPROTO_TCP:
            switch (optname)
            {
            case TCP_NODELAY:
                if (*optlen >= sizeof(int))
                {
                    *(int*)optval = pcb->tcp_options.nodelay;
                    *optlen = sizeof(int);
                }
                else
                {
                    req->saved_errno = EINVAL;
                    ret = -1;
                }
                break;
            case TCP_CORK:
                if (*optlen >= sizeof(int))
                {
                    *(int*)optval = pcb->tcp_options.cork;
                    *optlen = sizeof(int);
                }
                else
                {
                    req->saved_errno = EINVAL;
                    ret = -1;
                }
                break;
            case TCP_QUICKACK:
                if (*optlen >= sizeof(int))
                {
                    *(int*)optval = pcb->tcp_options.quickack;
                    *optlen = sizeof(int);
                }
                else
                {
                    req->saved_errno = EINVAL;
                    ret = -1;
                }
                break;
            default:
                req->saved_errno = ENOPROTOOPT;
                ret = -1;
                break;
            }
            break;
        default:
            DEBUG_LOG("tcp_getsockopt: unsupported level=%d optname=%d",
                      level, optname);
            req->saved_errno = ENOPROTOOPT;
            ret = -1;
            break;
    }

    return ret;
}

static uint32_t tcp_poll(struct Socket* sock)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    uint32_t mask = 0;

    if (sock->error)
        mask |= EPOLLERR;

    switch (pcb->state) {
    case TCP_STATE_LISTEN:
        if (pcb->accept_list_num > 0)
            mask |= EPOLLIN;
        break;

    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_CLOSE_WAIT:
        if (sock->recv_buffer_len > 0)
            mask |= EPOLLIN;
        if (!sock->flag.close_send &&
            SOCKET_USEABLE_SEND_BUFF_SIZE(sock) > 0)
            mask |= EPOLLOUT;
        break;

    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
        /* Still readable for remaining data */
        if (sock->recv_buffer_len > 0)
            mask |= EPOLLIN;
        break;

    case TCP_STATE_SYN_SENT:
    case TCP_STATE_SYN_RECEIVED:
        /* Handshaking — no events until state change */
        break;

    case TCP_STATE_TIME_WAIT:
    case TCP_STATE_CLOSED:
        if (sock->recv_buffer_len > 0)
            mask |= EPOLLIN;
        mask |= EPOLLHUP;
        break;
    }

    if (sock->flag.close_recv)
        mask |= EPOLLIN;
    if (pcb->tcp_flag.recv_fin)
        mask |= EPOLLIN | EPOLLRDHUP;
    if (sock->flag.close_send &&
        (sock->flag.close_recv || pcb->tcp_flag.recv_fin))
        mask |= EPOLLHUP;

    return mask;
}

static int tcp_getsockname(Socket* sock,req* r,sockaddr_in* addr,socklen_t* addrlen){
    if (!addr || !addrlen) {
        r->saved_errno = EFAULT;
        return -1;
    }
    struct sockaddr_storage out;
    socklen_t required;
    memset(&out, 0, sizeof(out));
    if (sock->family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&out;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = sock->sport;
        memcpy(&addr6->sin6_addr, sock->sip6, 16);
        addr6->sin6_scope_id = sock->sip6_scope_id;
        required = sizeof(*addr6);
    } else {
        struct sockaddr_in *addr4 = (struct sockaddr_in*)&out;
        addr4->sin_family = AF_INET;
        addr4->sin_port = sock->sport;
        addr4->sin_addr.s_addr = sock->sip;
        required = sizeof(*addr4);
    }
    socklen_t capacity = *addrlen < required ? *addrlen : required;
    if (capacity)
        memcpy(addr, &out, capacity);
    *addrlen = required;
    return 0;
}
static int tcp_getpeername(Socket* sock,req* r,sockaddr_in* addr,socklen_t* addrlen){
    if (!addr || !addrlen) {
        r->saved_errno = EFAULT;
        return -1;
    }
    if(!sock->flag.is_connected){
        r->saved_errno = ENOTCONN;
        return -1;
    }
    struct sockaddr_storage out;
    socklen_t required;
    memset(&out, 0, sizeof(out));
    if (sock->family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&out;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = sock->dport;
        memcpy(&addr6->sin6_addr, sock->dip6, 16);
        addr6->sin6_scope_id = sock->dip6_scope_id;
        required = sizeof(*addr6);
    } else {
        struct sockaddr_in *addr4 = (struct sockaddr_in*)&out;
        addr4->sin_family = AF_INET;
        addr4->sin_port = sock->dport;
        addr4->sin_addr.s_addr = sock->dip;
        required = sizeof(*addr4);
    }
    socklen_t capacity = *addrlen < required ? *addrlen : required;
    if (capacity)
        memcpy(addr, &out, capacity);
    *addrlen = required;
    return 0;
}

static uint32_t make_tcp_options(tcp_pcb* pcb, skbuff* skb)
{
    uint8_t flags = skb->l4_private.tcp.flag;
    bool is_syn = (flags & TCP_FLAG_SYN) != 0;

    uint32_t opt_len = tcp_predict_options_len(pcb, flags);
    if (opt_len == 0)
        return 0;

    /* Push options bytes at current skb front (before existing payload).
     * make_tcp_hdr will later push the basic header before these. */
    uint8_t* opt_ptr = skb_data_push(skb, opt_len);

    memset(opt_ptr, 0, opt_len);

    uint32_t pos = 0;

    /* MSS / Window Scale：只在握手阶段产生（SYN 或 SYN+ACK） */
    if (is_syn) {
        /* MSS */
        opt_ptr[pos++] = 2; /* Kind: MSS */
        opt_ptr[pos++] = 4; /* Length */
        uint16_t mss_n = htons((uint16_t)pcb->snd_mss);
        memcpy(opt_ptr + pos, &mss_n, sizeof(mss_n));
        pos += sizeof(mss_n);

        pcb->rcv_wnd_scale = TCP_RCV_WND_SCALE_DEFAULT;
        opt_ptr[pos++] = 1; /* NOP for alignment */
        opt_ptr[pos++] = 3; /* Kind: Window Scale */
        opt_ptr[pos++] = 3; /* Length */
        opt_ptr[pos++] = TCP_RCV_WND_SCALE_DEFAULT;
    }

    /* Timestamps（RFC 7323）：协商成功后尽量所有段都带 */
    if (pcb->tcp_flag.peer_ts_ok) {
        /* TS 选项需要 4 字节对齐，前面用 NOP 补齐 */
        while ((pos % 4) != 0) {
            opt_ptr[pos++] = 1; /* NOP */
        }

        opt_ptr[pos++] = 8;  /* Kind: Timestamps */
        opt_ptr[pos++] = 10; /* Length */

        uint32_t tsval = (uint32_t)get_current_time_ms();
        uint32_t tsecr = pcb->ts_recent;

        uint32_t tsval_n = htonl(tsval);
        uint32_t tsecr_n = htonl(tsecr);
        memcpy(opt_ptr + pos, &tsval_n, sizeof(tsval_n));
        pos += sizeof(tsval_n);
        memcpy(opt_ptr + pos, &tsecr_n, sizeof(tsecr_n));
        pos += sizeof(tsecr_n);
    }

    /* 最终填充到 4 字节对齐 */
    while (((sizeof(tcp_hdr) + pos) % 4) != 0) {
        opt_ptr[pos++] = 1; /* NOP */
    }

    return opt_len;
}
static int parse_tcp_options(tcp_pcb* pcb,tcp_hdr* hdr){

    uint32_t hdr_len = (uint32_t)((hdr->doff_res_flags >> 4) & 0x0Fu) * 4u;

    int options_len = (int)hdr_len - (int)sizeof(tcp_hdr);

    /* Only validate/negotiate options during handshake (SYN or SYN+ACK).
     * For established connections, just extract TS values. */
    bool is_handshake = (hdr->flags & TCP_FLAG_SYN) != 0;
    uint32_t old_mss = pcb->snd_mss;

    const uint8_t *opt = (const uint8_t *)((const uint8_t *)hdr + sizeof(tcp_hdr));
    int i = 0;
    while (i < options_len) {
        uint8_t kind = opt[i];
        if (kind == 0) /* EOL */
            break;
        if (kind == 1) { /* NOP */
            i += 1;
            continue;
        }
        if (i + 1 >= options_len)
            break;
        uint8_t len = opt[i + 1];
        if (len < 2 || i + len > options_len)
            break;

        if (kind == 2 && len == 4 && is_handshake) { /* MSS */
            uint16_t mss_n;
            memcpy(&mss_n, &opt[i + 2], sizeof(mss_n));
            uint16_t mss = ntohs(mss_n);

            /* RFC 1122: MSS must be at least 64, at most link MTU - headers */
            uint32_t ip_hdr_len = pcb->sock->family == AF_INET6
                ? IPV6_HDR_LEN : sizeof(ipv4_hdr);
            uint32_t mtu = get_route_mtu(pcb->sock->route);
            uint32_t link_mss = mtu > ip_hdr_len + sizeof(tcp_hdr)
                ? mtu - ip_hdr_len - sizeof(tcp_hdr) : 0;
            if (mss < 64) {
                DEBUG_LOG("TCP: peer MSS %u too small (< 64), ignoring", mss);
                i += len;
                continue;
            }
            pcb->snd_mss = mss;
            if (link_mss && link_mss < mss)
                pcb->snd_mss = link_mss;
            pcb->tcp_flag.peer_mss_ok = 1;
        }
        else if (kind == 3 && len == 3 && is_handshake) { /* Window Scale */
            /* RFC 7323: shift count 0..14 */
            uint8_t ws = opt[i + 2];
            if (ws > 14) {
                DEBUG_LOG("TCP: peer window scale %u > 14, clamping to 14", ws);
                ws = 14;
            }
            pcb->snd_wnd_scale = ws;
        }
        else if (kind == 8 && len == 10) { /* Timestamps (RFC 7323) */
            /* 格式：kind(1)=8, len(1)=10, TSval(4), TSecr(4) */
            uint32_t tsval_n = 0;
            uint32_t tsecr_n = 0;
            memcpy(&tsval_n, &opt[i + 2], sizeof(tsval_n));
            memcpy(&tsecr_n, &opt[i + 6], sizeof(tsecr_n));
            uint32_t tsval = ntohl(tsval_n);
            uint32_t tsecr = ntohl(tsecr_n);

            /* ── PAWS (RFC 7323 §5) ──────────────────────────
             * If timestamps were already negotiated (peer_ts_ok),
             * reject old segments: TSval < ts_recent means this
             * segment predates the last one we accepted. */
            if (pcb->tcp_flag.peer_ts_ok && tsval < pcb->ts_recent) {
                return -1;  /* old duplicate — silently drop */
            }

            /* SYN 阶段出现时间戳选项，表示对端支持 Timestamps */
            if (hdr->flags & TCP_FLAG_SYN)
                pcb->tcp_flag.peer_ts_ok = 1;
            pcb->ts_recent = tsval;
            pcb->ts_recent_age_ms = get_current_time_ms();
            pcb->ts_last_tsecr = tsecr; 
        }

        i += len;
    }

    if (is_handshake && pcb->snd_mss != old_mss)
        tcp_congestion_mss_changed(pcb);

    return 0;
}
static int set_tcp_socket_route(Socket* sock, const uint8_t* dip, uint32_t scope_id){
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    if(set_socket_route(sock, dip, scope_id) < 0){
        return -1;
    }
    if(sock->family != AF_INET6 &&
       (route_is_broadcast(sock->route) || route_is_multicast(sock->route))){
        route_info* route = sock->route;
        sock->route = NULL;
        PUT_REF(route);
        return -1;
    }

    if (pcb->metrics && pcb->metrics->ifindex != sock->route->ifindex) {
        PUT_REF(pcb->metrics);
        pcb->metrics = NULL;
    }
    if (!pcb->metrics) {
        pcb->metrics = tcp_metrics_get(sock->family, dip, sock->route->ifindex);
        pcb->retransmit_timeout = tcp_metrics_rto(pcb->metrics);
    }

    uint32_t ip_hdr_len = sock->family == AF_INET6 ? IPV6_HDR_LEN : sizeof(ipv4_hdr);
    uint32_t mtu = get_route_mtu(sock->route);

    uint32_t route_mss = mtu - sizeof(tcp_hdr) - ip_hdr_len;
    pcb->snd_mss = min(pcb->snd_mss, route_mss);
    pcb->rcv_mss = route_mss;

    return 0;
}
static int tcp_icmp_process(Socket* sock, const icmp_error_info* info, int err)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;

    if (!sock->flag.is_bound || !sock->flag.is_connected) {
        return 0;
    }

    /* Ignore errors quoting a TCP segment outside the current send window. */
    if (info && info->has_tcp_seq &&
        !(SEQ_LEQ(pcb->snd_una, info->tcp_seq) &&
          SEQ_LT(info->tcp_seq, pcb->snd_nxt)))
        return 0;

    sock->error = err;

    /* 根据当前状态决定处理方式 */
    switch (pcb->state) {
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:
            /* 握手阶段：ICMP 错误意味着连接失败，销毁 socket */
            destroy_tcp_socket(sock);
            break;

        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
            /* 已建立/半关闭：只标记错误，不销毁连接。
             * 单次 ICMP 错误不等同于连接断开（路由可能瞬间恢复），
             * 让重传超时机制自然地处理连接故障。
             * 参照 Linux：标记 sk_err，通知 EPOLLERR，但不销毁 socket。 */
            socket_notify_event(sock, notify_err);
            break;

        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
            /* 已在关闭流程中：直接销毁 */
            destroy_tcp_socket(sock);
            break;

        default:
            break;
    }

    return 0;
}

static int tcp_shutdown(struct Socket* sock, req* req, int how)
{
    int ret = 0;

    if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR) {
        req->saved_errno = EINVAL;
        return -1;
    }
    tcp_pcb *pcb = (tcp_pcb*)sock->pcb;
    if (!sock->flag.is_connected ||
        (pcb->state != TCP_STATE_ESTABLISHED &&
         pcb->state != TCP_STATE_CLOSE_WAIT &&
         pcb->state != TCP_STATE_FIN_WAIT_1 &&
         pcb->state != TCP_STATE_FIN_WAIT_2)) {
        req->saved_errno = ENOTCONN;
        return -1;
    }

    if ((how == SHUT_RD || how == SHUT_RDWR) &&
        !sock->flag.close_recv) {
        sock->flag.close_recv = 1;
        socket_notify_event(sock, notify_data_read);
    }

    if ((how == SHUT_WR || how == SHUT_RDWR) && !sock->flag.close_send) {
        sock->flag.close_send = 1;
        tcp_send_fin(pcb);
        ret = 0;
    }

    return ret;
}
static void tcp_send_fin(tcp_pcb* pcb){
    Socket* sock = pcb->sock;
    skbuff* last_send_skb = SKB_FROM_QUEUE_NODE(get_queue_last(&sock->send_queue));
    if(!last_send_skb){
        uint32_t ip_hdr_len = sock->family == AF_INET6
            ? MAX_IP6_HDR_WITH_EXT_LEN : MAX_IP_HDR_WITH_OPT_LEN;
        uint32_t alloc_len = MAX_TCP_HDR_OPT_LEN + ip_hdr_len
                           + sock->route->if_info->l2_len;
        last_send_skb = skb_alloc(alloc_len);
        if(!last_send_skb){
            ERR_LOG("Failed to allocate skb for sending FIN");
            return;
        }
        skb_reserve(last_send_skb, alloc_len);
        last_send_skb->l4_private.tcp.seq = pcb->snd_end;
        last_send_skb->l4_private.tcp.flag = TCP_FLAG_ACK;
        add_queue(&sock->send_queue, &last_send_skb->queue_node);
    }
    last_send_skb->l4_private.tcp.flag |= TCP_FLAG_FIN;
    pcb->snd_end++;
    if (SEQ_LT(pcb->snd_nxt, pcb->snd_una +
               min(pcb->snd_wnd, pcb->snd_cwnd))) {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                         get_current_time_ms(), false);
    }
}

protocol_ops tcp_protocol_ops = {
    .protocol = IPPROTO_TCP,
    .pcb_init = tcp_pcb_init,
    .icmp_process = tcp_icmp_process,
    .read = tcp_read,
    .write = tcp_write,
    .recvfrom = NULL,
    .sendto = NULL,
    .release = tcp_release,
    .connect = tcp_connect,
    .bind = tcp_bind,
    .listen = tcp_listen,
    .accept = tcp_accept,
    .getsockname = tcp_getsockname,
    .getpeername = tcp_getpeername,
    .setsockopt = tcp_setsockopt,
    .getsockopt = tcp_getsockopt,
    .poll = tcp_poll,
    .shutdown = tcp_shutdown,
};
