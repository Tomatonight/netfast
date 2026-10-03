#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/time.h>

#include "base.h"
#include "fd_entry.h"
#include "hash.h"
#include "icmp.h"
#include "ip.h"
#include "ipv6.h"
#include "ipv6_ext.h"
#include "log.h"
#include "netfast.h"
#include "queue.h"
#include "req_socket.h"
#include "rss.h"
#include "skbuff.h"
#include "stack.h"
#include "tcp.h"
#include "tcp_metrics.h"
#include "worker.h"
#include "xdp.h"

#define TCP_IPV4_MIN_MSS 512
#define TCP_IPV6_MIN_MSS 512
#define TCP_SKB_CAPACITY_MSS 1u

#define TCP_XMIT_FLAG_NEW_TRANSMIT (1u << 0)
#define TCP_XMIT_FLAG_RETRANSMIT   (1u << 1)
#define TCP_OUTPUT_BURST_MAX                (254u)

static void tcp_destroy_pcb(tcp_pcb* pcb);
static void tcp_destroy_socket(Socket* sock);
static void tcp_timer_cb(task* tk);
static void tcp_reset_timer(tcp_pcb* pcb);


static int tcp_input(Socket* sock, skbuff* skb);

static int tcp_send_new_flag(Socket* sock, uint32_t seq, uint32_t ack, uint8_t flag);
static int tcp_send_new_syn(Socket* sock);
static int tcp_send_new(tcp_pcb* pcb);
static void tcp_commit_fin_send(tcp_pcb* pcb);
static void tcp_fast_retransmit(tcp_pcb* pcb);
static void tcp_retransmit_first(tcp_pcb* pcb);
static uint32_t tcp_skb_budget(tcp_pcb* pcb, skbuff* skb);
static int tcp_xmit_skb(tcp_pcb* pcb, skbuff* skb, uint32_t ack,
                        uint32_t xmit_flags);

static inline uint8_t tcp_ecn_tx_flags(tcp_pcb* pcb, uint8_t flags)
{
    if (pcb->tcp_flag.ecn_echo_pending)
        flags |= TCP_FLAG_ECE;
    if (pcb->tcp_flag.ecn_cwr_pending) {
        flags |= TCP_FLAG_CWR;
        pcb->tcp_flag.ecn_cwr_pending = 0;
    }
    return flags;
}

static inline bool tcp_duplicate_ack(tcp_pcb* pcb, skbuff* skb)
{
    tcp_hdr* hdr = skb->tcp_hdr;
    uint8_t flags = skb->l4_private.tcp.flag;
    uint32_t ack = ntohl(hdr->ack_seq);

    if (!(flags & TCP_FLAG_ACK))
        return false;
    return
        !(flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) &&
        skb_data_len(skb) == 0 &&
        ack == pcb->last_ack &&
        SEQ_GT(pcb->snd_nxt, pcb->snd_una) &&
        tcp_decode_window(pcb, ntohs(hdr->window), flags) == pcb->snd_wnd;
}

static inline void tcp_skb_update_seq_end(skbuff* skb)
{
    skb->l4_private.tcp.seq_end = skb->l4_private.tcp.seq +
        skb_data_len(skb) +
        ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1u : 0u) +
        ((skb->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1u : 0u);
}

static inline uint32_t tcp_skb_seq_len(const skbuff* skb)
{
    return skb->l4_private.tcp.seq_end - skb->l4_private.tcp.seq;
}
static inline void tcp_update_mss(tcp_pcb* pcb){
    /* Bound send MSS by the current route MTU and the peer's MSS. */
    uint32_t route_mss = pcb->rcv_mss;
    if (pcb->sock && pcb->sock->route) {
        uint32_t ip_hdr_len = pcb->sock->family == AF_INET6
            ? IPV6_HDR_LEN : (uint32_t)sizeof(ipv4_hdr);
        uint32_t header_len = ip_hdr_len + (uint32_t)sizeof(tcp_hdr);
        uint32_t mtu = get_route_mtu(pcb->sock->route);
        route_mss = mtu > header_len ? mtu - header_len : 0;
        pcb->rcv_mss = route_mss;
    }

    uint32_t mss = min(pcb->peer_mss, route_mss);

    if (TCP_SKB_CAPACITY_MSS == 1) {
        uint32_t tcp_option_len = MAX_TCP_HDR_LEN - sizeof(tcp_hdr);
        uint32_t ip_option_len = pcb->sock->family == AF_INET6
            ? MAX_IP6_HDR_WITH_EXT_LEN - IPV6_HDR_LEN
            : MAX_IP_HDR_WITH_OPT_LEN - sizeof(ipv4_hdr);
        uint32_t option_len = tcp_option_len + ip_option_len;
        mss = mss - option_len;
    }
    pcb->snd_mss = mss;
}

static bool tcp_build_frag_header(skbuff* skb, const uint8_t* header,
                                     uint32_t header_len, uint32_t seq,
                                     uint8_t flags)
{
    Socket* sock = skb->sock;
    uint32_t lower_header_len = 0;
    route_info* route = skb->route ;
    lower_header_len = route->if_info->l2_len;
    lower_header_len += sock->family == AF_INET6
        ? IPV6_HDR_LEN : (uint32_t)sizeof(ipv4_hdr);

    tcp_hdr* tcp = (tcp_hdr*)skb_data_push(
        skb, header_len, header_len + lower_header_len);
    if (!tcp)
        return false;
    memcpy(tcp, header, header_len);
    tcp->seq = htonl(seq);
    tcp->flags = flags;
    tcp->check = 0;
    skb->tcp_hdr = tcp;
    skb->tx_checksum_offset = 0;

    if (skb->route->if_info->hw_tx_checksum_enabled) {
        tcp->check = skb->family == AF_INET6
            ? skb_checksum_protocol6(NULL, skb_data_len(skb),
                                     sock->sip6, sock->dip6, IPPROTO_TCP)
            : skb_checksum_protocol(NULL, skb_data_len(skb),
                                    sock->sip, sock->dip, IPPROTO_TCP);
        skb->tx_checksum_offset = offsetof(tcp_hdr, check);
    } else {
        tcp->check = skb->family == AF_INET6
            ? skb_checksum_protocol6(skb, skb_data_len(skb),
                                     sock->sip6, sock->dip6, IPPROTO_TCP)
            : skb_checksum_protocol(skb, skb_data_len(skb),
                                    sock->sip, sock->dip, IPPROTO_TCP);
    }
    return true;
}

bool tcp_skb_frag(skbuff* skb, uint32_t mtu)
{
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return false;

    uint32_t ip_hdr_len = skb->family == AF_INET6
        ? IPV6_HDR_LEN : (uint32_t)sizeof(ipv4_hdr);
    uint32_t tcp_hdr_len =
        (uint32_t)(skb->tcp_hdr->doff_res_flags >> 4) * 4u;
    uint32_t total_len = skb_data_len(skb);

    uint32_t payload_limit = mtu - ip_hdr_len - tcp_hdr_len;
    uint32_t payload_len = total_len - tcp_hdr_len;
    if (payload_len <= payload_limit)
        return true;

    uint8_t header[MAX_TCP_HDR_LEN];
    if (!skb_copy_bits(skb, 0, header, tcp_hdr_len)) {
        ERR_LOG("tcp_skb_frag header copy failed total=%u hdr=%u",
                total_len, tcp_hdr_len);
        return false;
    }
    uint32_t base_seq = skb->l4_private.tcp.seq;
    uint8_t original_flags = skb->l4_private.tcp.flag;

    if (!skb_consume(skb, tcp_hdr_len, false)) {
        return false;
    }
    if (!skb_frag(skb, payload_limit)) {
        skb_free_frag_list(skb);
        return false;
    }

    uint32_t data_offset = 0;
    uint32_t syn_len = (original_flags & TCP_FLAG_SYN) ? 1u : 0u;
    skbuff* frag;
    bool has_tail = skb->frag_list.next != NULL;
    uint8_t first_flags = original_flags;
    if (has_tail)
        first_flags &= (uint8_t)~(TCP_FLAG_FIN | TCP_FLAG_PSH);
    if (!tcp_build_frag_header(skb, header, tcp_hdr_len, base_seq,
                                  first_flags))
        goto fail;
    skb->l4_private.tcp.seq = base_seq;
    skb->l4_private.tcp.flag = first_flags;
    skb->l4_private.tcp.seq_end = base_seq + skb_data_len(skb) - tcp_hdr_len +
        ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1u : 0u) +
        ((skb->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1u : 0u);
    data_offset += skb_data_len(skb) - tcp_hdr_len;

    FOR_EACH_LIST_OFFSET(&skb->frag_list, frag, skbuff, frag_list) {
        bool last = frag->frag_list.next == NULL;
        uint8_t flags = original_flags;
        if (data_offset != 0)
            flags &= (uint8_t)~TCP_FLAG_SYN;
        if (!last)
            flags &= (uint8_t)~(TCP_FLAG_FIN | TCP_FLAG_PSH);
        uint32_t seq = base_seq + syn_len + data_offset;
        uint32_t frag_payload_len = skb_data_len(frag);
        if (!tcp_build_frag_header(frag, header, tcp_hdr_len, seq, flags))
            goto fail;
        frag->l4_private.tcp.seq = seq;
        frag->l4_private.tcp.flag = flags;
        frag->l4_private.tcp.seq_end = seq + frag_payload_len +
            ((flags & TCP_FLAG_SYN) ? 1u : 0u) +
            ((flags & TCP_FLAG_FIN) ? 1u : 0u);
        data_offset += frag_payload_len;
    }
    return true;

fail:
    skb_free_frag_list(skb);
    return false;
}

static inline uint32_t tcp_hdr_reserve_len(const Socket* sock)
{
    uint32_t ip_hdr_len = sock->family == AF_INET6
        ? MAX_IP6_HDR_WITH_EXT_LEN : sizeof(ipv4_hdr);
    uint32_t l2_len = sock->route->if_info->l2_len;
    return l2_len + ip_hdr_len + MAX_TCP_HDR_LEN;
}

static inline uint32_t tcp_skb_capacity(const tcp_pcb* pcb)
{
    return pcb->snd_mss * TCP_SKB_CAPACITY_MSS;
}

static inline uint64_t tcp_cwnd_limit(tcp_pcb* pcb)
{
    if(pcb->tcp_flag.peer_sack_ok) {
        uint64_t acked_bytes = tcp_sack_acked_bytes(pcb);
        return pcb->snd_cwnd + acked_bytes;
    }
    return (pcb->snd_cwnd);
}
static inline uint64_t tcp_win_limit(tcp_pcb* pcb)
{
    return min(pcb->snd_wnd, tcp_cwnd_limit(pcb));
}
static void tcp_update_persist_timer(tcp_pcb* pcb)
{
    bool pending = pcb->retransmit_tree.count ||
                   pcb->sock->send_queue.element_number;
    if (!pcb->snd_wnd && pending) {
        if (pcb->persist_deadline_ms == TCP_TIMER_STOP){
            pcb->persist_backoff = TCP_PERSIST_BACKOFF_MS_DEFAULT;
            pcb->persist_probes_out = 0;
            tcp_update_timer(pcb, &pcb->persist_deadline_ms,
                             get_current_time_ms() + pcb->persist_backoff,
                             false);

        }
    } else {
        if (pcb->persist_deadline_ms != TCP_TIMER_STOP)
            tcp_update_timer(pcb, &pcb->persist_deadline_ms,
                             TCP_TIMER_STOP, false);
    }
}

static void tcp_update_transmit_timer(tcp_pcb* pcb)
{
    Socket* sock = pcb->sock;
    /*
    if (!pcb->retransmit_tree.count || !pcb->snd_wnd) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         TCP_TIMER_STOP, true);
    } else if (pcb->retransmit_deadline_ms == TCP_TIMER_STOP) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         get_current_time_ms()+ pcb->retransmit_timeout, false);
    }
    */
    bool sendable = sock->send_queue.element_number &&
                    tcp_win_limit(pcb) >
                        (uint32_t)(pcb->snd_nxt - pcb->snd_una);

    if (!sendable) {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms, TCP_TIMER_STOP, false);
    } else if(pcb->nagle_deadline_ms == TCP_TIMER_STOP){
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                         get_current_time_ms() , false);
    }
}

static void tcp_update_sndwin(tcp_pcb* pcb, uint32_t new_wnd){
    new_wnd = new_wnd - new_wnd % pcb->snd_mss;
    if (pcb->snd_wnd == new_wnd)
        return;
    pcb->snd_wnd = new_wnd;
    tcp_update_persist_timer(pcb);
    tcp_update_transmit_timer(pcb);

}

void tcp_update_sndcwnd(tcp_pcb* pcb, uint64_t new_cwnd)
{

    if (pcb->snd_cwnd == new_cwnd)
        return;

    pcb->snd_cwnd = new_cwnd;
    tcp_update_transmit_timer(pcb);
}


void tcp_skb_tree_insert(tcp_skb_tree* tree, skbuff* skb,
                         size_t node_offset)
{
    struct rb_node** link = &tree->root.rb_node;
    struct rb_node* parent = NULL;
    struct rb_node* skb_node = (struct rb_node*)((uint8_t*)skb + node_offset);
    uint32_t seq = skb->l4_private.tcp.seq;
    uint32_t seq_end = skb->l4_private.tcp.seq_end;

    while (*link) {
        skbuff* queued = skb_from_node(*link, node_offset);
        parent = *link;
        if (SEQ_LT(seq, queued->l4_private.tcp.seq) ||
            (seq == queued->l4_private.tcp.seq &&
             SEQ_LT(seq_end, queued->l4_private.tcp.seq_end)))
            link = &(*link)->rb_left;
        else
            link = &(*link)->rb_right;
    }

    rb_link_node(skb_node, parent, link);
    rb_insert_color(skb_node, &tree->root);
    tree->count++;
}

void tcp_skb_tree_remove(tcp_skb_tree* tree, skbuff* skb,
                         size_t node_offset)
{
    struct rb_node* node = (struct rb_node*)((uint8_t*)skb + node_offset);
    rb_erase(node, &tree->root);
    rb_init_node(node);
    tree->count--;
}

skbuff* tcp_skb_tree_lower_bound(const tcp_skb_tree* tree, uint32_t seq,
                                 size_t node_offset)
{
    struct rb_node* node = tree->root.rb_node;
    skbuff* result = NULL;

    while (node) {
        skbuff* skb = skb_from_node(node, node_offset);
        if (SEQ_GEQ(skb->l4_private.tcp.seq, seq)) {
            result = skb;
            node = node->rb_left;
        } else {
            node = node->rb_right;
        }
    }
    return result;
}

skbuff* tcp_skb_tree_prev_lower_bound(const tcp_skb_tree* tree, uint32_t seq,
                                      size_t node_offset)
{
    struct rb_node* node = tree->root.rb_node;
    skbuff* result = NULL;

    while (node) {
        skbuff* skb = skb_from_node(node, node_offset);
        if (SEQ_LT(skb->l4_private.tcp.seq, seq)) {
            result = skb;
            node = node->rb_right;
        } else {
            node = node->rb_left;
        }
    }
    return result;
}


static inline bool tcp_deadline_due(uint64_t now_ms, uint64_t *deadline_ms)
{
    if (*deadline_ms == TCP_TIMER_STOP) {
        return false;
    }
    if (now_ms >= *deadline_ms) {
        *deadline_ms = TCP_TIMER_STOP;
        return true;
    }
    return false;
}


static int tcp_pcb_init(Socket* sock){
    tcp_pcb* pcb = calloc(1, sizeof(*pcb));
    if(!pcb){
        goto fail;
    }
    sock->pcb=pcb;
    pcb->sock=sock;
    pcb->state=TCP_STATE_CLOSED;
    pcb->retransmit_tree.root = RB_ROOT;
    pcb->retransmit_tree.count = 0;
    pcb->reorder_tree.root = RB_ROOT;
    pcb->reorder_tree.count = 0;
    tcp_rack_init(pcb);

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
    pcb->retransmits_out = 0;
    pcb->persist_probes_out = 0;
    pcb->retries_max = TCP_RETRIES2_DEFAULT;
    pcb->timewait_timeout   = TCP_TIMEWAIT_TIMEOUT_MS_DEFAULT;
    pcb->finwait2_timeout   = TCP_FINWAIT2_TIMEOUT_MS_DEFAULT;
    pcb->ack_timeout     = TCP_DELACK_TIMEOUT_MS_DEFAULT;
    pcb->nagle_interval    = TCP_NAGLE_INTERVAL_MS_DEFAULT;
    pcb->connect_timeout = TCP_CONNECT_TIMEOUT_MS_DEFAULT;

    pcb->peer_mss = sock->family == AF_INET6 ? TCP_IPV6_MIN_MSS : TCP_IPV4_MIN_MSS;
    pcb->rcv_mss = pcb->peer_mss;
    tcp_update_mss(pcb);
    pcb->rcv_wnd = sock->recv_buffer_len_max;
    pcb->rcv_wnd_scale = TCP_RCV_WND_SCALE_DEFAULT;
    pcb->snd_wnd = pcb->rcv_wnd;//tmp set

    if (tcp_ca_init(pcb) < 0)
        goto fail;

    uint32_t iss = (uint32_t)(uintptr_t)pcb % 0xaFFFFFFF;
    pcb->snd_una = iss;
    pcb->snd_nxt = iss;
    pcb->snd_end = iss;

    pcb->last_ack = iss;

    /* A route is selected later, after the local/remote tuple is known. */
    pcb->retransmit_timeout = tcp_metrics_default_rto();

    return 0;

fail:
    if (pcb) {
        tcp_ca_release(pcb);
        destroy_task(pcb->timer_task);
        PUT_REF(pcb->metrics);
    }
    sock->pcb = NULL;
    free(pcb);
    return -1;
}

static void tcp_receive_data(tcp_pcb* pcb, skbuff* skb){
    uint32_t seq = skb->l4_private.tcp.seq;
    uint32_t seg_len = tcp_skb_seq_len(skb);
    bool out_of_order = SEQ_GT(seq, pcb->rcv_nxt);

    /* Trim data before rcv_nxt (retransmitted/overlapping prefix) */
    if(SEQ_LT(seq, pcb->rcv_nxt)){
        uint32_t overlap = pcb->rcv_nxt - seq;
        if(overlap >= seg_len){
            goto schedule_ack;
        }
        skb_consume(skb, overlap, false);
        seq += overlap;
        seg_len -= overlap;
        skb->l4_private.tcp.seq = seq;
    }
    if(SEQ_GT(seq + seg_len, pcb->rcv_nxt + pcb->rcv_wnd)){
        uint32_t overlap = seq + seg_len - (pcb->rcv_nxt + pcb->rcv_wnd);
        if(overlap >= seg_len){
            goto schedule_ack;
        }
        if(skb->l4_private.tcp.flag & TCP_FLAG_FIN){
            skb->l4_private.tcp.flag &= ~TCP_FLAG_FIN;
            overlap--;
        }
        skb_truncate(skb, skb_data_len(skb) - overlap );
        tcp_skb_update_seq_end(skb);
    }

    if (pcb->reorder_tree.count >= TCP_OOO_SKB_MAX &&
        seq != pcb->rcv_nxt)
        goto schedule_ack;

    INC_REF(skb);
    TCP_TREE_INSERT(pcb, reorder, skb);
    if (out_of_order)
        tcp_sack_recv_ooo_skb(pcb, skb);


    if(!out_of_order){
        skbuff* it;
        while ((it = TCP_TREE_FIRST(pcb, reorder))) {
                uint32_t it_seq = it->l4_private.tcp.seq;
                uint32_t it_seq_end = it->l4_private.tcp.seq_end;

                if (SEQ_LEQ(it_seq_end, pcb->rcv_nxt)) {
                    tcp_skb_tree_remove(&pcb->reorder_tree, it,
                                        offsetof(skbuff, reorder_node));
                    PUT_REF(it);
                    continue;
                }

                if (SEQ_GT(it_seq, pcb->rcv_nxt))
                    break;

                tcp_skb_tree_remove(&pcb->reorder_tree, it,
                                    offsetof(skbuff, reorder_node));

                /* Discard the prefix that overlaps data already delivered. */
                if (SEQ_LT(it_seq, pcb->rcv_nxt)) {
                    skb_consume(it, pcb->rcv_nxt - it_seq, false);
                    it->l4_private.tcp.seq = pcb->rcv_nxt;
                }

                add_queue(&pcb->sock->recv_queue, &it->queue_node);
                pcb->sock->recv_buffer_len += skb_data_len(it);
                pcb->rcv_nxt += tcp_skb_seq_len(it);

                if (it->l4_private.tcp.flag & TCP_FLAG_FIN) {
                    pcb->tcp_flag.recv_fin = 1;
                    break;
                }
            }
        socket_notify_event(pcb->sock, notify_data_read);
        tcp_sack_rcv_nxt_advance(pcb);
        pcb->rcv_wnd = SOCKET_USEABLE_RECV_BUFF_SIZE(pcb->sock);
    }

schedule_ack:
    if (out_of_order) {
        tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                         get_current_time_ms(), true);
    } else {
        uint64_t deadline = ++pcb->ack_pending_segments >= 3
            ? get_current_time_ms()
            : get_current_time_ms() + pcb->ack_timeout;
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, deadline, false);
    }
}

/* ── 连接生命周期与统一 TCP 定时�?─────────────────────── */

static void tcp_abort_connect(Socket* sock)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;

    if (sock->flag.is_hash)
        uninstall_tuple(sock, tcp_tuple_hash(sock->family));

    skbuff* skb;
    while ((skb = TCP_TREE_FIRST(pcb, retransmit))) {
        TCP_REMOVE_RETRASMIT(pcb, skb);
        PUT_REF(skb);
    }

    tcp_sack_reset(pcb);

    pcb->snd_nxt = pcb->snd_una;
    pcb->snd_end = pcb->snd_una;
    pcb->tcp_flag.recv_fin = 0;
    memset(sock->dip6, 0, sizeof(sock->dip6));
    sock->dip6_scope_id = 0;
    sock->dport = 0;
    sock->flag.is_connected = 0;
}

static void tcp_complete_linger(Socket* sock)
{
    pending_node* pn;
    list_node* tmp;

    FOR_EACH_LIST_SAFE_OFFSET(&sock->pending, pn, tmp, pending_node, node) {
        req* r = (req*)pn->value;
        if (pn->cb == stack_request_pending_cb && r && r->type == REQ_CLOSE &&
            r->status == REQ_WAITING_CLOSE)
            req_notify(r, 0);
    }
}

static void tcp_destroy_socket(Socket* sock){
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    pcb->state = TCP_STATE_CLOSED;
    
    if(sock->fd_entry){// user hold the socket
        socket_notify_event(sock, notify_err);
        return;
    }

    tcp_complete_linger(sock);
    tcp_destroy_pcb(pcb);
    destroy_socket(sock);
}


void tcp_update_timer(tcp_pcb* pcb, uint64_t* which,
                      uint64_t deadline_ms, bool override)
{
    if (*which == deadline_ms ||
        (!override && *which != TCP_TIMER_STOP && *which < deadline_ms))
        return;

    task* tk = pcb->timer_task;
    bool reset = !tk->registered || *which == tk->timeout;
    *which = deadline_ms;

    if (reset) {
        tcp_reset_timer(pcb);
    } else if (deadline_ms != TCP_TIMER_STOP &&
               deadline_ms < tk->timeout) {
        tk->timeout = deadline_ms;
        register_task(pcb->sock->owner->master, tk);
    }
}

static void tcp_reset_timer(tcp_pcb* pcb)
{
    task* tk = pcb->timer_task;
    uint64_t next = 0;
    uint64_t timeouts[] = {
        pcb->recovery_deadline_ms,
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
    uint32_t fired = 0;
    if (tcp_deadline_due(now_ms, &pcb->nagle_deadline_ms)) {
        fired++;
        if (sock->send_queue.element_number)
            ret = tcp_send_new(pcb);
    }

    if (tcp_deadline_due(now_ms, &pcb->retransmit_deadline_ms)) {
        fired++;
        if(pcb->retransmit_tree.count){
            if (pcb->state == TCP_STATE_SYN_SENT ||
                pcb->state == TCP_STATE_SYN_RECEIVED) {
                /* SYN retransmission with exponential backoff */
                if (pcb->connect_retry_times++ >= TCP_CONNECT_RETRY_MAX) {
                    sock->error = ETIMEDOUT;
                    tcp_destroy_socket(sock);
                    return;
                }
                pcb->connect_timeout *= 2;
                tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                                get_current_time_ms() + pcb->connect_timeout, true);
            } else {

                if (pcb->retransmits_out++ >= pcb->retries_max) {
                    sock->error = ETIMEDOUT;
                    tcp_destroy_socket(sock);
                    return;
                }

                pcb->recovery_deadline_ms = TCP_TIMER_STOP;
                tcp_ca_rto_timeout(pcb);

                pcb->retransmit_timeout =
                    tcp_metrics_backoff(pcb->retransmit_timeout);
                tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                                get_current_time_ms() + pcb->retransmit_timeout,
                                true);
            }
            skbuff* skb = TCP_TREE_FIRST(pcb, retransmit);
            tcp_retransmit_skb(pcb, skb);
        }
    } else if (tcp_deadline_due(now_ms,
                               &pcb->recovery_deadline_ms)) {
        fired++;
        if (pcb->retransmit_tree.count) {
            tcp_fast_retransmit(pcb);
            //DEBUG_LOG("TCP recovery timer fired");
        }
    }
    if (tcp_deadline_due(now_ms, &pcb->ack_deadline_ms)) {
        fired++;
        ret = tcp_send_new_flag(sock, pcb->snd_nxt, pcb->rcv_nxt, TCP_FLAG_ACK);
    }
    if (tcp_deadline_due(now_ms, &pcb->persist_deadline_ms)) {
        fired++;
        if (!pcb->snd_wnd && (pcb->retransmit_tree.count ||
                              sock->send_queue.element_number)) {
            if (pcb->persist_probes_out++ >= pcb->retries_max) {
                sock->error = ETIMEDOUT;
                tcp_destroy_socket(sock);
                return;
            }
            pcb->persist_backoff = min(pcb->persist_backoff * 2,
                                       TCP_PERSIST_BACKOFF_MS_MAX);
            tcp_update_timer(pcb, &pcb->persist_deadline_ms, get_current_time_ms() + pcb->persist_backoff, true);
            ret = tcp_send_new_flag(sock, pcb->snd_una - 1u, pcb->rcv_nxt,
                                TCP_FLAG_ACK);
        }
    }
    if (tcp_deadline_due(now_ms, &pcb->timewait_deadline_ms)) {
        fired++;
        tcp_destroy_socket(sock);
        return;
    }
    if (tcp_deadline_due(now_ms, &pcb->finwait2_deadline_ms)) {
        fired++;
        if(pcb->state == TCP_STATE_FIN_WAIT_2){
            DEBUG_LOG("TCP FIN_WAIT_2 timeout, closing connection");
            sock->error = ETIMEDOUT;
            tcp_destroy_socket(sock);
            return;
        }
    }
    if (tcp_deadline_due(now_ms, &pcb->keepalive_deadline_ms)) {
        fired++;
        if (!sock->options.keepalive) {
            pcb->keepalive_repeat_count = 0;
        } else if(pcb->keepalive_repeat_count++ >= pcb->keepalive_repeat_max){
            sock->error = ETIMEDOUT;
            tcp_destroy_socket(sock);
            return;
        } else {
            tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                             get_current_time_ms() + pcb->keepalive_retry_timeout,
                             false);
            ret = tcp_send_new_flag(sock, pcb->snd_una - 1, pcb->rcv_nxt,
                                TCP_FLAG_ACK);
        }
    }



    tcp_reset_timer(pcb);

    DEBUG_LOG("TCP timer: fired=%u ret=%d", fired, ret);
    (void)ret;
}

static void tcp_clear_associated_sockets(tcp_pcb *pcb){
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
        tcp_destroy_socket(child_pcb->sock);
    }
    pcb->syn_list_num=0;
    FOR_EACH_LIST_SAFE_OFFSET(&pcb->accept_list, child_pcb, tmp, tcp_pcb, accept_list){
        remove_list_node(&child_pcb->accept_list);
        tcp_destroy_socket(child_pcb->sock);
    }
    pcb->accept_list_num=0;
}
static void tcp_destroy_pcb(tcp_pcb *pcb)
{
    destroy_task(pcb->timer_task);
    tcp_ca_release(pcb);
    PUT_REF(pcb->metrics);
    tcp_clear_associated_sockets(pcb);
    skbuff* skb;
    while ((skb = TCP_TREE_FIRST(pcb, reorder))) {
        tcp_skb_tree_remove(&pcb->reorder_tree, skb,
                            offsetof(skbuff, reorder_node));
        PUT_REF(skb);
    }
    while ((skb = TCP_TREE_FIRST(pcb, retransmit))) {
        TCP_REMOVE_RETRASMIT(pcb, skb);
        PUT_REF(skb);
    }
    if(pcb->sock)
        pcb->sock->pcb = NULL;
    free(pcb);
}

/* ── 报文校验、连接查找与输入状态机 ─────────────────────── */

static int tcp_set_socket_route(Socket* sock, const uint8_t* dip,
                                uint32_t if_index)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    if(set_socket_route(sock, dip, if_index) < 0){
        return -1;
    }
    if(route_is_broadcast(sock->route) || route_is_multicast(sock->route)){
        route_info* route = sock->route;
        sock->route = NULL;
        PUT_REF(route);
        return -1;
    }

    if (pcb->metrics && pcb->metrics->key.ifindex != sock->route->ifindex) {
        PUT_REF(pcb->metrics);
        pcb->metrics = NULL;
    }
    if (!pcb->metrics) {
        pcb->metrics = tcp_metrics_get(sock->family, dip, sock->route->ifindex);
        pcb->retransmit_timeout = tcp_metrics_rto(pcb->metrics);
    }

    tcp_update_mss(pcb);

    return 0;
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


static uint32_t tcp_validate_header(skbuff* skb)
{
    if (skb_data0_len(skb) < sizeof(tcp_hdr))
        return 0;

    tcp_hdr* hdr = (tcp_hdr*)skb_start(skb);
    uint32_t hdr_len = (uint32_t)(hdr->doff_res_flags >> 4) * 4u;

    /* TCP header length: 5..15 (20..60 bytes), 32-bit aligned */
    if (hdr_len < sizeof(tcp_hdr) || hdr_len > MAX_TCP_HDR_LEN ||
        hdr_len > skb_data0_len(skb))
    {
        DEBUG_LOG("Invalid TCP header length %u", hdr_len);
        return 0;
    }
    skb->tcp_hdr = hdr;

    /* Verify checksum (pseudo header + tcp header + payload). */
    if (skb->flag.is_hw_rcv_checksum)
        return hdr_len;
    uint32_t seg_len = skb_data_len(skb);
    uint16_t csum = (skb->family == AF_INET6)
        ? skb_checksum_protocol6(skb, seg_len,
                                 skb->ipv6_hdr->saddr, skb->ipv6_hdr->daddr, IPPROTO_TCP)
        : skb_checksum_protocol(skb, seg_len,
                                skb->ipv4_hdr->saddr, skb->ipv4_hdr->daddr, IPPROTO_TCP);
    if (csum != 0)
    {
        DEBUG_LOG("Invalid TCP checksum csum=0x%04x seg_len=%u", ntohs(csum), seg_len);
        return 0;
    }

    return hdr_len;
}
static void tcp_parse_options(const tcp_hdr* hdr, tcp_options* options)
{
    memset(options, 0, sizeof(*options));
    uint32_t hdr_len = (uint32_t)((hdr->doff_res_flags >> 4) & 0x0Fu) * 4u;
    int options_len = (int)hdr_len - (int)sizeof(tcp_hdr);
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

        if (kind == 2 && len == 4) { /* MSS */
            uint16_t mss_n;
            memcpy(&mss_n, &opt[i + 2], sizeof(mss_n));
            options->mss = ntohs(mss_n);
            options->flags |= TCP_OPTION_MSS_SEEN;
        }
        else if (kind == 3 && len == 3) { /* Window Scale */
            options->wnd_scale = min(opt[i + 2], 14u);
            options->flags |= TCP_OPTION_WINDOW_SCALE_SEEN;
        }
        else if (kind == TCP_OPTION_SACK_PERMITTED && len == 2) {
            options->flags |= TCP_OPTION_SACK_PERMITTED_SEEN;
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
            /* SYN 阶段出现时间戳选项，表示对端支�?Timestamps */
            options->tsval = tsval;
            options->tsecr = tsecr;
            options->flags |= TCP_OPTION_TIMESTAMP_SEEN;
        }
        else if (kind == TCP_OPTION_SACK && len >= 10u &&
                 ((len - 2u) % 8u) == 0) {
            uint32_t count = min((uint32_t)(len - 2u) / 8u,
                                 (uint32_t)TCP_MAX_SACK_BLOCKS);
            for (uint32_t block = 0; block < count &&
                 options->sack_count < TCP_MAX_SACK_BLOCKS; block++) {
                uint32_t left;
                uint32_t right;
                memcpy(&left, &opt[i + 2u + block * 8u], sizeof(left));
                memcpy(&right, &opt[i + 6u + block * 8u], sizeof(right));
                options->sacks[options->sack_count++] = (tcp_sack_block){
                    .left = ntohl(left),
                    .right = ntohl(right),
                };
            }
            if (options->sack_count)
                options->flags |= TCP_OPTION_SACK_SEEN;
        }

        i += len;
    }

}

static int tcp_apply_peer_syn_options(tcp_pcb* pcb,
                                      const tcp_options* options,
                                      uint8_t tcp_flags)
{
    if (options->flags & TCP_OPTION_MSS_SEEN) {
        uint16_t min_mss = pcb->sock->family == AF_INET6
            ? TCP_IPV6_MIN_MSS : TCP_IPV4_MIN_MSS;
        if (options->mss < min_mss)
            return -1;
        pcb->peer_mss = options->mss;
        tcp_update_mss(pcb);
        tcp_ca_mss_changed(pcb);
    }
    if (options->flags & TCP_OPTION_WINDOW_SCALE_SEEN) {
        pcb->snd_wnd_scale = options->wnd_scale;
        pcb->tcp_flag.peer_wnd_scale_ok = 1;
    }
    if (options->flags & TCP_OPTION_SACK_PERMITTED_SEEN)
        pcb->tcp_flag.peer_sack_ok = 1;
    if (options->flags & TCP_OPTION_TIMESTAMP_SEEN) {
        pcb->tcp_flag.peer_ts_ok = 1;
        pcb->ts_recent = options->tsval;
    }
    /* ECN negotiation uses SYN flags rather than a TCP option:
     * active SYN-ACK confirms ECE, while a passive SYN requests ECE+CWR. */
    if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
            (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        if (tcp_flags & TCP_FLAG_ECE)
            pcb->tcp_flag.ecn_ok = 1;
    } else if ((tcp_flags & TCP_FLAG_SYN) &&
               (tcp_flags & (TCP_FLAG_ECE | TCP_FLAG_CWR)) ==
                   (TCP_FLAG_ECE | TCP_FLAG_CWR)) {
        pcb->tcp_flag.ecn_ok = 1;
    }
    return 0;
}

static int tcp_reply_rst(Socket* sock, skbuff* recv_skb)
{
    tcp_hdr* tcp=recv_skb->tcp_hdr;

    if(tcp->flags & TCP_FLAG_RST)
        return 0;
    if(!(tcp->flags & TCP_FLAG_ACK))
        return tcp_send_new_flag(sock, 0, recv_skb->l4_private.tcp.seq_end,
                             TCP_FLAG_RST | TCP_FLAG_ACK);
    return tcp_send_new_flag(sock, ntohl(tcp->ack_seq), 0, TCP_FLAG_RST);
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
    tcp_hdr* tcp;
    uint32_t tcp_hdr_len;
    bool is_v6 = (skb->family == AF_INET6);

    if (skb->process == tcp_recv) {
        tcp = skb->tcp_hdr;
        tcp_hdr_len = (uint32_t)(tcp->doff_res_flags >> 4) * 4u;
    } else {
        tcp_hdr_len = tcp_validate_header(skb);
        if (!tcp_hdr_len)
            return -1;
        tcp = skb->tcp_hdr;
    }

    bool is_syn = (tcp->flags & TCP_FLAG_SYN) && !(tcp->flags & TCP_FLAG_ACK);
    worker* aim_worker;
    Socket* sock;
    if (is_v6) {
        ipv6_hdr* ip6 = skb->ipv6_hdr;
        sock = tcp_lookup_socket6(ip6->saddr, tcp->sport,
                                  ip6->daddr, tcp->dport,
                                  is_syn, &aim_worker);
    } else {
        ipv4_hdr* ip = skb->ipv4_hdr;
        sock = tcp_lookup_socket(ip->saddr, tcp->sport,
                                 ip->daddr, tcp->dport,
                                 is_syn, &aim_worker);
    }
    if (sock && aim_worker != get_current_worker()) {
        worker_enqueue_skb(aim_worker, skb, tcp_recv);
        return 0;
    }

    uint8_t flags = tcp->flags;
    uint32_t seq = ntohl(tcp->seq);
    if (!skb_consume(skb, tcp_hdr_len, true))
        return -1;
    skb->l4_private.tcp.seq = seq;
    skb->l4_private.tcp.flag = flags;
    tcp_skb_update_seq_end(skb);

    if (!sock) {
        if (flags & TCP_FLAG_RST)
            return 0;

        static __thread Socket sock_tmp;
        static __thread tcp_pcb pcb_tmp;
        pcb_tmp.sock = &sock_tmp;
        sock_tmp.pcb = &pcb_tmp;

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

        const uint8_t* reply_dip = is_v6 ? sock_tmp.dip6 : (const uint8_t*)&sock_tmp.dip;

        if (set_socket_route(&sock_tmp, reply_dip, 0) < 0)
            return -EHOSTUNREACH;
        return tcp_reply_rst(&sock_tmp, skb);
    }

    if (sock->tuple_node.next) {
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
static void tcp_update_retransmit_tree(tcp_pcb* pcb){
    uint32_t ack = pcb->snd_una;
    uint32_t acked_bytes = 0;
    while (pcb->retransmit_tree.count) {
        skbuff* skb = TCP_TREE_FIRST(pcb, retransmit);

        if(SEQ_GT(ack, skb->l4_private.tcp.seq)){
            if(SEQ_GEQ(ack, skb->l4_private.tcp.seq_end)){
                tcp_rack_update_last_acked(pcb, skb);
                uint32_t data_len = skb_data_len(skb);
                TCP_REMOVE_RETRASMIT(pcb, skb);
                pcb->sock->send_buffer_len -= data_len;
                acked_bytes += data_len;
                PUT_REF(skb);
            }
            else{
                uint32_t consumed = ack - skb->l4_private.tcp.seq;
                uint32_t old_state = skb->l4_private.tcp.sack_state;
                tcp_sack_set_state(pcb, skb, 0);
                if (skb->l4_private.tcp.flag & TCP_FLAG_SYN) {
                    skb->l4_private.tcp.flag &= ~TCP_FLAG_SYN;
                    consumed--;
                }

                uint32_t data_acked = min(consumed, skb_data_len(skb));
                if (data_acked) {
                    skb_consume(skb, data_acked, false);
                    pcb->sock->send_buffer_len -= data_acked;
                    acked_bytes += data_acked;
                }
                tcp_skb_tree_remove(&(pcb)->retransmit_tree, (skb),
                                    offsetof(skbuff, retransmit_node));
                skb->l4_private.tcp.seq = ack;
                tcp_skb_tree_insert(&pcb->retransmit_tree, skb,
                                    offsetof(skbuff, retransmit_node));
                tcp_sack_set_state(pcb, skb, old_state);
                break;
            }
        }
        else
            break;
    }

    if (acked_bytes) {
        pcb->retransmits_out = 0;
        pcb->retransmit_timeout = tcp_metrics_rto(pcb->metrics);

        socket_notify_event(pcb->sock, notify_data_write);

        tcp_update_transmit_timer(pcb);
        tcp_update_persist_timer(pcb);

        tcp_ca_ack_bytes(pcb, acked_bytes);
        if (pcb->ca.status == TCP_CA_STATUS_RECOVERY &&
            !pcb->tcp_flag.peer_sack_ok)
            tcp_retransmit_first(pcb);
    }

    if (!pcb->retransmit_tree.count) {
        tcp_update_timer(pcb, &pcb->recovery_deadline_ms,
                         TCP_TIMER_STOP, true);
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms, TCP_TIMER_STOP, true);
        pcb->last_ack_repeat = 0;
    } else if (acked_bytes) {
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         get_current_time_ms() + pcb->retransmit_timeout,
                         true);
    }

}

/* ── 报文构造、发送与重传 ──────────────────────────────── */

static void tcp_fast_retransmit(tcp_pcb* pcb)
{
    tcp_rack_retransmit_lost(pcb);
    tcp_rack_update_timer(pcb);
}

static void tcp_retransmit_first(tcp_pcb* pcb)
{
    queue* q = &pcb->rack.unacked_queue;
    skbuff* skb;
    uint8_t state;

    if (!q->element_number)
        return;
    skb = SKB_FROM_NODE(get_queue_first(q), rack_node);
    if (!pcb->tcp_flag.peer_sack_ok) {
        tcp_retransmit_skb(pcb, skb);
        return;
    }
    state = skb->l4_private.tcp.sack_state;
    state |= TCP_SACKED_LOST;
    state &= ~TCP_SACKED_RETRANS;
    tcp_sack_set_state(pcb, skb, state);
    tcp_update_timer(pcb, &pcb->recovery_deadline_ms,
                     get_current_time_ms(), false);
}

static skbuff* tcp_alloc_skb(Socket* sock, uint32_t data_len)
{
    uint32_t reserve_len = tcp_hdr_reserve_len(sock);
    skbuff* skb = skb_alloc(reserve_len + data_len);
    if (!skb)
        return NULL;
    skb_reserve(skb, reserve_len);
    return skb;
}

static uint32_t tcp_build_options(tcp_pcb* pcb, skbuff* skb)
{
    uint8_t flags = skb->l4_private.tcp.flag;
    bool is_syn = (flags & TCP_FLAG_SYN) != 0;
    bool send_wscale = is_syn && (!(flags & TCP_FLAG_ACK) ||
                                  pcb->tcp_flag.peer_wnd_scale_ok);
    bool send_timestamps = pcb->tcp_flag.peer_ts_ok ||
        ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN);
    bool send_sack_permitted = is_syn &&
        (!(flags & TCP_FLAG_ACK) || pcb->tcp_flag.peer_sack_ok);
    uint32_t sack_option_len = tcp_sack_option_len(pcb, flags);

    uint32_t option_len = is_syn
        ? 4u + (send_sack_permitted ? 4u : 0u) +
          (send_wscale ? 4u : 0u)
        : 0u;
    if (send_timestamps)
        option_len += 12u;
    option_len += sack_option_len;
    if (!option_len)
        return 0;

    uint8_t* options = skb_data_push(skb, option_len, option_len);

    uint8_t* pos = options;
    if (is_syn) {
        uint16_t mss = htons((uint16_t)pcb->rcv_mss);

        pos[0] = 2; /* MSS */
        pos[1] = 4;
        memcpy(pos + 2, &mss, sizeof(mss));
        pos += 4;

        if (send_sack_permitted) {
            pos[0] = TCP_OPTION_SACK_PERMITTED;
            pos[1] = 2;
            pos[2] = 1; /* NOP padding */
            pos[3] = 1;
            pos += 4;
        }

        if (send_wscale) {
            pos[0] = 1; /* NOP */
            pos[1] = 3; /* Window Scale */
            pos[2] = 3;
            pos[3] = TCP_RCV_WND_SCALE_DEFAULT;
            pos += 4;
        }
    }

    if (send_timestamps) {
        uint32_t tsval = htonl((uint32_t)get_current_time_ms());
        uint32_t tsecr = htonl(pcb->ts_recent);

        pos[0] = 1;  /* NOP */
        pos[1] = 1;  /* NOP */
        pos[2] = 8;  /* Timestamps */
        pos[3] = 10;
        memcpy(pos + 4, &tsval, sizeof(tsval));
        memcpy(pos + 8, &tsecr, sizeof(tsecr));
        pos += 12;
    }

    if (sack_option_len)
        tcp_sack_write_option(pcb, flags, pos);

    return option_len;
}

static int tcp_send_new_flag(Socket* sock, uint32_t seq, uint32_t ack, uint8_t flag)
{
    skbuff* skb = tcp_alloc_skb(sock, 0);
    if (!skb) {
        return -ENOMEM;
    }

    skb->l4_private.tcp.seq = seq;
    skb->l4_private.tcp.flag = flag;
    tcp_skb_update_seq_end(skb);
    int ret = tcp_xmit_skb((tcp_pcb*)sock->pcb, skb, ack, 0);
    PUT_REF(skb);
    return ret;
}

static int tcp_send_new_syn(Socket* sock)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    skbuff* skb = tcp_alloc_skb(sock, 0);
    if (!skb)
        return -ENOMEM;

    uint32_t seq = pcb->snd_nxt;
    bool with_ack = pcb->state == TCP_STATE_SYN_RECEIVED;
    uint32_t ack = with_ack ? pcb->rcv_nxt : 0;
    skb->l4_private.tcp.seq = seq;
    skb->l4_private.tcp.flag = TCP_FLAG_SYN |
        (with_ack ? TCP_FLAG_ACK : 0);
    if (!with_ack)
        skb->l4_private.tcp.flag |= TCP_FLAG_ECE | TCP_FLAG_CWR;
    else if (pcb->tcp_flag.ecn_ok)
        skb->l4_private.tcp.flag |= TCP_FLAG_ECE;
    tcp_skb_update_seq_end(skb);
    INC_REF(skb);

    /* 提交 SYN 占用的序号空间，再将已经构建好的报文交给输出层�?*/
    int ret = tcp_xmit_skb(pcb, skb, ack, TCP_XMIT_FLAG_NEW_TRANSMIT);
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
                tcp_send_new_flag(pcb->sock, ack, 0, TCP_FLAG_RST);
            }
            return 0;
        }
    }

    if(flags & TCP_FLAG_RST){
        pcb->sock->error = ECONNREFUSED;
        tcp_destroy_socket(pcb->sock);
    }

    //to do security/compartment

    if (flags & TCP_FLAG_SYN) {
        tcp_options options;
        tcp_parse_options(hdr, &options);
        if (tcp_apply_peer_syn_options(pcb, &options, flags) < 0)
            return 0;
        pcb->rcv_nxt = seq + 1;
        if (flags & TCP_FLAG_ACK) {
            pcb->snd_una = ack;
            pcb->last_ack = ack;
            pcb->last_ack_repeat = 0;
            pcb->state = TCP_STATE_ESTABLISHED;
            tcp_update_retransmit_tree(pcb);
            if (sock->options.keepalive) {
                tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                                 get_current_time_ms() + pcb->keepalive_timeout,
                                 true);
            }

            socket_notify_event(sock, notify_data_write);
            tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                             get_current_time_ms(), false);
            //to do urg
        }
        else {
            pcb->state = TCP_STATE_SYN_RECEIVED;
            skbuff* syn_skb = TCP_TREE_FIRST(pcb, retransmit);
            syn_skb->l4_private.tcp.flag |= TCP_FLAG_ACK;
            tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                             get_current_time_ms(),
                             false);
        }
        tcp_update_sndwin(pcb, tcp_decode_window(pcb, window, flags));
        pcb->snd_wl1 = seq;
        pcb->snd_wl2 = ack;

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
        tcp_send_new_flag(sock, ack, 0, TCP_FLAG_RST);
        return 0;
    }

    if (!(flags & TCP_FLAG_SYN))
        return 0;

    tcp_options options;
    tcp_parse_options(hdr, &options);

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
    /* 只继承监�?PCB 的拥塞控制算法，不继承其实时 cwnd/恢复状态�?*/
    if (tcp_ca_inherit(child_pcb, pcb) < 0) {
        tcp_destroy_socket(new_sock);
        return -1;
    }
    new_sock->options = sock->options;
    new_sock->options.reuseport = true;//for bind
    new_sock->send_timeout = sock->send_timeout;
    new_sock->recv_timeout = sock->recv_timeout;
    new_sock->linger_seconds = sock->linger_seconds;
    new_sock->send_buffer_len_max = sock->send_buffer_len_max;
    new_sock->recv_buffer_len_max = sock->recv_buffer_len_max;
    child_pcb->rcv_wnd = new_sock->recv_buffer_len_max;
    child_pcb->nagle_interval = pcb->nagle_interval;
    child_pcb->keepalive_timeout = pcb->keepalive_timeout;
    child_pcb->keepalive_interval = pcb->keepalive_interval;
    child_pcb->keepalive_retry_timeout = pcb->keepalive_retry_timeout;
    child_pcb->keepalive_repeat_max = pcb->keepalive_repeat_max;

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
        tcp_destroy_socket(new_sock);
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
    if (tcp_set_socket_route(new_sock,
                             is_v6 ? new_sock->dip6 : (const uint8_t*)&new_sock->dip,
                             is_v6 ? new_sock->dip6_scope_id : 0) < 0) {
        ERR_LOG("tcp_process_listen: failed to set route for new socket");
        tcp_destroy_socket(new_sock);
        return -1;
    }

    //install tuple
    if (!install_tuple(new_sock, tcp_tuple_hash(new_sock->family))) {
        ERR_LOG("tcp_process_listen: failed to install tuple for new socket");
        tcp_destroy_socket(new_sock);
        return -1;
    }

    //add to parent sock
    child_pcb->state = TCP_STATE_SYN_RECEIVED;
    child_pcb->parent_sock = pcb->sock;
    add_list_node(&pcb->syn_list, &child_pcb->syn_list);
    pcb->syn_list_num++;
    set_socket_worker(new_sock, get_current_worker());
    if (new_sock->options.keepalive) {
        tcp_update_timer(child_pcb, &child_pcb->keepalive_deadline_ms,
                         get_current_time_ms() + child_pcb->keepalive_timeout,
                         true);
    }

    if (tcp_apply_peer_syn_options(child_pcb, &options, flags) < 0) {
        tcp_destroy_socket(new_sock);
        return 0;
    }
    child_pcb->rcv_nxt = seq + 1;
    tcp_update_sndwin(child_pcb,
                       tcp_decode_window(child_pcb, window, flags));
    return tcp_send_new_syn(new_sock);
}

static int tcp_input(Socket *sock, skbuff *skb)
{

    tcp_pcb *pcb = (tcp_pcb *)sock->pcb;
    tcp_hdr *hdr = skb->tcp_hdr;
    uint8_t flags = skb->l4_private.tcp.flag;
    uint32_t seq = skb->l4_private.tcp.seq;
    uint32_t ack = ntohl(hdr->ack_seq);
    uint16_t window = ntohs(hdr->window);

    uint32_t data_len = skb_data_len(skb);
    uint32_t seg_len = tcp_skb_seq_len(skb);
    if (pcb->state == TCP_STATE_CLOSED) {
        if (flags & TCP_FLAG_RST)
            return 0;
        if (!(flags & TCP_FLAG_ACK))
            return tcp_send_new_flag(pcb->sock, 0,
                                 skb->l4_private.tcp.seq_end,
                                 TCP_FLAG_RST | TCP_FLAG_ACK);
        return tcp_send_new_flag(pcb->sock, ack, 0, TCP_FLAG_RST);
    }

    if (pcb->state == TCP_STATE_LISTEN) {
        return tcp_process_listen(sock, skb);
    }
    if(pcb->state == TCP_STATE_SYN_SENT){
        return tcp_process_syn_sent(sock, skb);
    }

    /*
3.10.7.4. Other States 其他状�?
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
步的处理。如果段的内容跨越新旧之间的边界，则仅处理新的部分�?
通常，必须实现对接收段的处理，以尽可能聚合ACK段（MUST-58）。例如，如果TCP端点正在处理一系列排队的段，则它必须在发送任何ACK段之前处理所有这些段（MUST59）�?
传入段的可接受性测试有四种情况�?
Segment Length	Receive Window	Test
0	    0	    SEG.SEQ = RCV.NXT
0	    >0	    RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND
>0	    0	    not acceptable
>0	    >0	    RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND or RCV.NXT <= SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
在实现此处所述的序列号验证时，请参见附录A.2
如果RCV.WND�?，不接受任何段，但应特别考虑接受有效的ACK、URG和RST�?
如果传入段不可接受，则应发送应答确认（除非设置了RST位，否则删除段并返回）：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
发送确认后，丢弃不可接受的段并返回�?
注意，对于TIME-WAIT状态，[40]中描述了一种改进的算法，用于处理利用时间戳而不是依
赖于这里描述的序列号检查的传入SYN段。当实现改进的算法时，上述逻辑不适用于在
TIME-WAIT状态下的连接上接收的具有时间戳选项的传入SYN段。当实现改进的算法时，上述逻辑不适用于在TIME-WAIT状态下的连接上接收的具有时间戳选项的传入SYN段�?
在下文中，假设段是从RCV.NXT开始的理想段，不超过窗口大小。可以通过修剪位于窗口
之外的任何部分（包括SYN和FIN）来定制实际段以适应该假设，并且如果段随后从
RCV.NXT开始，则仅进一步处理。具有较高起始序列号的段应保留以供以后处理（SHLD31）�?
*/

    tcp_options options;
    tcp_parse_options(hdr, &options);

    if ((options.flags & TCP_OPTION_TIMESTAMP_SEEN) &&
        pcb->tcp_flag.peer_ts_ok &&
        SEQ_LT(options.tsval, pcb->ts_recent)) {
        tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                         get_current_time_ms(), false);
        return 0;
    }

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
        uint32_t seg_end = skb->l4_private.tcp.seq_end;
        uint32_t window_end = pcb->rcv_nxt + pcb->rcv_wnd;
        if (SEQ_LT(seq, window_end) && SEQ_GT(seg_end, pcb->rcv_nxt))
            seg_allow = true;
    }

    if (!seg_allow && pcb->state == TCP_STATE_TIME_WAIT &&
        flags == (TCP_FLAG_ACK | TCP_FLAG_FIN) &&
        skb->l4_private.tcp.seq_end == pcb->rcv_nxt) {
        seg_allow = true;
    }

    if (!seg_allow && !(flags & TCP_FLAG_RST)){
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
        return 0;
    }

/*
第二步，校验RST位：
RFC5961[9]的第3节描述了潜在的盲重置攻击和可选的缓解方法。这不提供加密保护（例如，在
IPsec或TCP-AO中），但可以适用于RFC5961中描述的情况。对于实现RFC5961中描述的保护的堆
栈，下面的三个检查适用；否则，下面进一步指示对这些状态的处理�?
1. 如果设置了RST位，并且序列号在当前接收窗口之外，则静默丢弃该段�?
2. 如果设置了RST位，并且序列号与下一个期望的序列号（RCV.NXT）完全匹配，则TCP端点�?
须根据连接状态，以下面规定的方式重置连接�?
3. 如果设置了RST位，并且序列号不完全匹配下一个期望的序列值，但仍然在当前接收窗口内，
则TCP端点必须发送确认（challenge ACK）：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
在发送challenge ACK后，TCP端点必须丢弃不可接受的段，并停止进一步处理传入数据包。请
注意，RFC5961和勘误表ID4772[99]包含实现中ACK调节的其他注意事项�?
SYN-RECEIVED STATE
如果设置了RST位，
如果该连接是通过被动OPEN（即来自LISTEN状态）初始化的，则将该连接返回到LISTEN状�?
并返回。无需通知用户。如果此连接是通过主动OPEN（即来自SYN-SENT状态）初始化的，则
拒绝连接；向用户发出“connection refused”的信号。在任何一种情况下，都应该刷新重传�?
列。在主动OPEN情况下，进入CLOSED状态并删除TCB，然后返回�?
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
如果设置了RST位，则任何未完成的RECEIVE和SEND都应接收“重置”的响应。应刷新所有段�?
列。用户还应收到未被要求的常规“connection reset”信号。进入CLOSED（关闭）状态，删除
TCB，返回�?
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
如果设置了RST位，则进入关闭状态，删除TCB，返回�?
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
                tcp_destroy_socket(pcb->sock);
                return 0;
            }else {
                pcb->sock->error = ECONNREFUSED;
                tcp_destroy_socket(pcb->sock);
                return 0;
            }
            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_FIN_WAIT_1:
            case TCP_STATE_FIN_WAIT_2:
            case TCP_STATE_CLOSE_WAIT:
            {
                pcb->sock->error = ECONNRESET;
                tcp_destroy_socket(pcb->sock);
                return 0;
            }
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
            case TCP_STATE_TIME_WAIT:
                tcp_destroy_socket(pcb->sock);
                return 0;
            default:
                return 0;
        }
    }

    if ((options.flags & TCP_OPTION_TIMESTAMP_SEEN) &&
        pcb->tcp_flag.peer_ts_ok &&
        SEQ_GEQ(options.tsval, pcb->ts_recent) &&
        SEQ_LEQ(seq, pcb->last_ack_sent)) {
        pcb->ts_recent = options.tsval;
    }
    /*

第三步，校验安全�?
SYN-RECEIVED STATE
如果段中的security/compartment没有完全匹配TCB中的security/compartment，则发送一个重置并返回�?
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
如果段中的security/compartment没有完全匹配TCB中的security/compartment，则发送一个重
置；任何未完成的RECEIVE和SEND都应收到“reset’”响应。应刷新所有段队列。用户还应收�?
未被要求的常规“connection reset”信号。进入CLOSED状态，删除TCB，返回�?
请注意，此检查放在序列检查之后，以防止来自这些具有不同安全性的端口号之间的旧连接的段导
致当前连接中止�?
*/
// to do security/compartment

/*
第四步，校验SYN位：
SYN-RECEIVED STATE
如果连接是通过被动OPEN初始化的，则将该连接返回到LISTEN状态并返回。否则，请按照以
下同步状态的说明进行处理�?
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
如果在这些同步状态下设置SYN位，则它可能是合法的新连接尝试（例如，在TIME-WAIT
的情况下）、应重置连接的错误或攻击尝试的结果，如RFC5961[9]中所述。对于TIMEWAIT状态，
如果使用时间戳选项并满足预期，则可以接受新连接（根据[40]）。对于所�?
其他情况，RFC5961提供了适用于某些情况的缓解措施，尽管也有提供加密保护的替代�?
案（见第7节）。RFC5961推荐，在这些同步状态下，如果设置了SYN位，则无论序列号�?
何，TCP端点都必须向远程端发送“challenge ACK”：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
发送确认后，TCP实现必须丢弃不可接受的段并停止进一步的处理。请注意，RFC5961�?
勘误表ID4772[99]包含用于实现的额外ACK调节的说明�?
对于不遵循RFC5961的实现，本段中遵循RFC793中描述的原始行为。如果SYN在窗�?
中，则它是一个错误：发送重置，任何未完成的RECEIVE和SEND应接收“reset”响应，�?
刷新所有段队列，用户还应收到未被要求的常规“connection reset”信号，进入CLOSED�?
态，删除TCB，返回�?
如果SYN不在窗口中，则不会到达该步骤，并且会在第一步中发送ACK（序列号检查）�?
*/
    if(flags & TCP_FLAG_SYN){
        switch(pcb->state){
            case TCP_STATE_SYN_RECEIVED:
                tcp_send_new_flag(pcb->sock, pcb->snd_nxt, pcb->rcv_nxt,
                              TCP_FLAG_RST | TCP_FLAG_ACK);
                tcp_destroy_socket(pcb->sock);
                return 0;

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
如果ACK位关闭，则丢弃段并返回�?
如果设置了ACK位，
RFC5961[9]的第5节描述了潜在的盲数据注入攻击，以及实现可以选择包括的缓解（MAY-12）。实
现RFC5961的TCP堆栈必须添加输入检查，以确保只有在ACK值在�?(SND.UNA - MAX.SND.WND)
=< SEG.ACK =< SND.NXT)的范围内时，ACK值才可接受。必须丢弃ACK值不满足上述条件的所�?
传入段，并发回ACK。新的状态变量MAX.SND.WND被定义为本地发送方从其对端接收到的最�?
窗口（受窗口缩放影响），或者可以硬编码为最大允许窗口值。当ACK值可接受时，适用于以下各
个状态处理：
SYN-RECEIVED STATE
如果SND.UNA < SEG.ACK =< SND.NXT，则进入ESTABLISHED状态，并继续处理，�?
置以下的变量�?
SND.WND <- SEG.WND
SND.WL1 <- SEG.SEQ
SND.WL2 <- SEG.ACK
如果该段的确认不可接受，形成一个重置段
<SEQ=SEG.ACK><CTL=RST>
并发送它�?
ESTABLISHED STATE
如果SND.UNA < SEG.ACK =< SND.NXT，那么设置SND.UNA <- SEG.ACK。因此已完全
确认的重传队列上的任何段都被删除。用户应收到已发送和完全确认的缓冲区的肯定确�?
（即，SEND缓冲区应返回“ok”响应）。如果ACK是重复的（SEG.ACK=<SND.UNA），�?
可以忽略它。如果ACK确认尚未发送的内容（SEG.ACK>SND.NXT），则发送ACK，丢�?
该段，返回�?
如果SND.UNA =< SEG.ACK =< SND.NXT，发送窗口应该更新。如�?(SND.WL1 <
SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK))，设置SND.WND <-
SEG.WND，设置SND.WL1 <- SEG.SEQ，并设置SND.WL2 <- SEG.ACK�?
请注意SND.WND是来自SND.UNA的偏移量。那个SND.WL1记录用于更新SND.WND的最
后一个段的序列号，SND.WL2记录用于更新SND.WND的最后一个段的确认号。此处的�?
验防止使用旧段更新窗口�?
FIN-WAIT-1 STATE
除了ESTABLISHED状态的处理外，如果FIN段现在被确认，则进入FIN-WAIT-2并在该状态下�?
续处理�?
FIN-WAIT-2 STATE
除了ESTABLISHED状态的处理外，如果重传队列为空，则可以确认用户的CLOSE（“ok”），但
不要删除TCB�?
CLOSE-WAIT STATE
执行与ESTABLISHED状态相同的处理�?
CLOSING STATE
除了ESTABLISHED状态的处理外，如果ACK确认我们的FIN，则进入TIME-WAIT状态；否则�?
忽略该段�?
LAST-ACK STATE
在这种状态下，唯一可以到达的是对我们的FIN的确认。如果我们的FIN现在已被确认，则删除
TCB，进入CLOSED状态，并返回�?
TIME-WAIT STATE
唯一可以达到这种状态的是远程FIN的重传。确认它，并重新启动2 MSL超时�?
*/
    if(!(flags & TCP_FLAG_ACK)){
        return 0;
    }
    if(SEQ_LT(ack,pcb->snd_una - pcb->snd_wnd) ||
        SEQ_GT(ack, pcb->snd_nxt)){
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
        return 0;
    }

    if (pcb->tcp_flag.ecn_ok &&
        pcb->state >= TCP_STATE_ESTABLISHED &&
        pcb->state != TCP_STATE_TIME_WAIT && !(flags & TCP_FLAG_RST)) {
        if (flags & TCP_FLAG_CWR)
            pcb->tcp_flag.ecn_echo_pending = 0;
        if ((flags & TCP_FLAG_ECE) && !pcb->tcp_flag.ecn_cwr_pending) {
            tcp_ca_event(pcb, TCP_CA_EVENT_ECN);
            pcb->tcp_flag.ecn_cwr_pending = 1;
        }
        if (skb->l4_private.tcp.ip_ecn == TCP_ECN_CE) {
            pcb->tcp_flag.ecn_echo_pending = 1;
            tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                             get_current_time_ms(), false);
        }
    }

    switch(pcb->state){
        case TCP_STATE_SYN_RECEIVED:
            if(SEQ_LT(pcb->snd_una, ack) && SEQ_LEQ(ack, pcb->snd_nxt)){
                pcb->state = TCP_STATE_ESTABLISHED;
                pcb->snd_una = ack;
                pcb->last_ack = ack;
                pcb->last_ack_repeat = 0;

                tcp_update_retransmit_tree(pcb);
                tcp_update_sndwin(pcb,
                                   tcp_decode_window(pcb, window, flags));
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
                } else
                    socket_notify_event(sock, notify_data_write |
                                             notify_connect);
            }
            else if(SEQ_LEQ(ack, pcb->snd_una)){
                tcp_send_new_flag(sock, ack, 0, TCP_FLAG_RST);
                return 0;
            }
            break;
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
            /* An old ACK must not roll back window/duplicate-ACK state. */
            if (SEQ_LT(ack, pcb->snd_una))
                break;
            if(SEQ_LT(pcb->snd_una, ack)){
                pcb->snd_una = ack;
                tcp_update_retransmit_tree(pcb);
                tcp_sack_process_options(pcb, &options);
                tcp_update_transmit_timer(pcb);
                pcb->last_ack = ack;
                pcb->last_ack_repeat = 0;

                uint64_t now = get_current_time_ms();
                uint32_t sample = 0;

                if (pcb->tcp_flag.peer_ts_ok &&
                    (options.flags & TCP_OPTION_TIMESTAMP_SEEN) &&
                    options.tsecr) {
                    if (now > options.tsecr)
                        sample = (uint32_t)(now - options.tsecr);
                } else if (pcb->rtt_meas_time &&
                           SEQ_LEQ(pcb->rtt_meas_seq, pcb->snd_una)) {
                    sample = (uint32_t)(now - pcb->rtt_meas_time);
                }

                if (sample && pcb->metrics) {
                    pcb->retransmit_timeout =
                        tcp_metrics_sample(pcb->metrics, sample);
                }
                pcb->rtt_meas_time = 0;

                if(SEQ_LT(pcb->snd_wl1, seq) || (pcb->snd_wl1 == seq && SEQ_LEQ(pcb->snd_wl2, ack))){
                    tcp_update_sndwin(pcb,
                                       tcp_decode_window(pcb, window, flags));
                    pcb->snd_wl1 = seq;
                    pcb->snd_wl2 = ack;
                }

            }else{

                tcp_sack_process_options(pcb, &options);

                bool duplicate_ack = tcp_duplicate_ack(pcb, skb);
                uint32_t new_wnd = tcp_decode_window(pcb, window, flags);

                if (SEQ_LT(pcb->snd_wl1, seq) ||
                    (pcb->snd_wl1 == seq &&
                     SEQ_LEQ(pcb->snd_wl2, ack))) {
                    tcp_update_sndwin(pcb, new_wnd);
                    pcb->snd_wl1 = seq;
                    pcb->snd_wl2 = ack;
                }

                if (!duplicate_ack) {
                    pcb->last_ack_repeat = 0;
                    break;
                }

                pcb->last_ack = ack;
                pcb->last_ack_repeat++;
                if (pcb->last_ack_repeat == 3u) {
                    tcp_retransmit_first(pcb);
                    tcp_ca_event(pcb, TCP_CA_EVENT_LOSS);
                } else if (pcb->last_ack_repeat > 3u) {
                    tcp_ca_event(pcb, TCP_CA_EVENT_DUP_ACK);
                }
                break;
            }
            if(pcb->state == TCP_STATE_FIN_WAIT_1 && pcb->snd_una == pcb->snd_end){
                pcb->state = TCP_STATE_FIN_WAIT_2;
                tcp_complete_linger(pcb->sock);
                if(!pcb->sock->fd_entry)
                tcp_update_timer(pcb, &pcb->finwait2_deadline_ms,
                    get_current_time_ms() + pcb->finwait2_timeout, true);
            }
            else if(pcb->state == TCP_STATE_CLOSING){
                if(pcb->snd_una == pcb->snd_end){
                    pcb->state = TCP_STATE_TIME_WAIT;
                    tcp_complete_linger(pcb->sock);
                    tcp_update_timer(pcb, &pcb->timewait_deadline_ms, get_current_time_ms() + pcb->timewait_timeout, true);
                }
            }
            else if(pcb->state == TCP_STATE_LAST_ACK &&
                    pcb->snd_una == pcb->snd_end){
                tcp_complete_linger(pcb->sock);
                tcp_destroy_socket(pcb->sock);
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
如果设置了URG位，那么设置RCV.UP <- max(RCV.UP,SEG.UP)，并且如果紧急指�?
（RCV.UP）在消耗的数据之前，则向用户发送信号，告知远程侧具有紧急数据。如果用户已�?
收到此连续紧急数据序列的信号（或仍处于“紧急模式”），则不要再次向用户发出信号�?
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
这不应该发生，因为已经从远程端接收到FIN。忽略URG�?
*/
//to do
/*
第七步，处理段的文本�?
ESTABLISHED STATE
FIN-WAIT-1 STATE
FIN-WAIT-2 STATE
一旦处于ESTABLISHED状态，就可以将段数据传递到用户RECEIVE缓冲区。来自段的数
据可以移动到缓冲区中，直到缓冲区已满或段为空。如果段清空并带有PUSH标志，则当返
回缓冲区时，通知用户已收到PUSH�?
当TCP端点负责将数据交付给用户时，它还必须确认数据的接收�?
一旦TCP端点对数据负责，它就会提高RCV.NXT超过接受的数据，并调整RCV.WND适用
于当前可用缓冲区。RCV.NXT与RCV.WND的和不应降低�?
当一个有效段到达时，该段位于窗口中，但不在窗口左侧边缘，TCP实现可以发送确�?
RCV.NXT的ACK段（MAY-13）�?
请注意第3.8节中的窗口管理建议�?
发送一个该格式的确认：
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
如果可能，该确认应捎带（piggybacked ）在正在传输的段上，而不会引起过度的延迟�?
CLOSE-WAIT STATE
CLOSING STATE
LAST-ACK STATE
TIME-WAIT STATE
这不应该发生，因为已经从远程端接收到FIN。忽略段文本�?
*/
switch(pcb->state){
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
        if(data_len > 0 || (flags & TCP_FLAG_FIN))
            tcp_receive_data(pcb, skb);
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
并返回�?
如果设置了FIN位，则向用户发出“connection closing”信号，并以相同消息返回任何即将发送的
RECEIVE，基于FIN提高RCV.NXT，并发送FIN的确认。请注意，FIN表示对任何段文本的PUSH�?
尚未传递给用户�?
SYN-RECEIVED STATE
ESTABLISHED STATE
进入CLOSE-WAIT状�?
FIN-WAIT-1 STATE
如果我们的FIN已被确认（可能在该段中），则进入TIME-WAIT，启动时间等待计时器，关闭其
他计时器；否则，进入CLOSING状态�?
FIN-WAIT-2 STATE
进入TIME-WAIT状态。启动时间等待计时器，关闭其他计时器�?
CLOSE-WAIT STATE
Remain in the CLOSE-WAIT state.
保持在CLOSE-WAIT状态�?
CLOSING STATE
保持在CLOSING状态�?
LAST-ACK STATE
保持在LAST-ACK状态�?
TIME-WAIT STATE
保持在TIME-WAIT状态。重�? MSL时间等待超时�?
并返回�?
    */
    if(pcb->state == TCP_STATE_CLOSED || pcb->state == TCP_STATE_SYN_SENT) {
        return 0;
    }
    if ((flags & TCP_FLAG_FIN) && pcb->state == TCP_STATE_TIME_WAIT &&
        skb->l4_private.tcp.seq_end == pcb->rcv_nxt) {
        uint64_t now_ms = get_current_time_ms();
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, now_ms, true);
        tcp_update_timer(pcb, &pcb->timewait_deadline_ms,
                         now_ms + pcb->timewait_timeout, true);
        return 0;
    }

    /* recv_fin is persistent EOF state.  Restrict sequence-space
     * consumption to states that have not processed the peer FIN yet. */
    if (pcb->tcp_flag.recv_fin &&
        (pcb->state == TCP_STATE_SYN_RECEIVED ||
         pcb->state == TCP_STATE_ESTABLISHED ||
         pcb->state == TCP_STATE_FIN_WAIT_1 ||
         pcb->state == TCP_STATE_FIN_WAIT_2)) {
        pcb->rcv_nxt++;

        socket_notify_event(sock, notify_recv_fin);
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
        switch(pcb->state) {
            case TCP_STATE_SYN_RECEIVED:
            case TCP_STATE_ESTABLISHED:
                pcb->state = TCP_STATE_CLOSE_WAIT;
                break;
            case TCP_STATE_FIN_WAIT_1:
                if(pcb->snd_una == pcb->snd_end){
                    pcb->state = TCP_STATE_TIME_WAIT;
                    tcp_complete_linger(pcb->sock);
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

    if (pcb->state == TCP_STATE_TIME_WAIT) {
        pcb->keepalive_repeat_count = 0;
        tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                         TCP_TIMER_STOP, true);
    } else if (sock->options.keepalive &&
               pcb->state != TCP_STATE_CLOSED &&
               pcb->state != TCP_STATE_LISTEN &&
               pcb->state != TCP_STATE_SYN_SENT) {
        pcb->keepalive_repeat_count = 0;
        tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                         get_current_time_ms() + pcb->keepalive_timeout, true);
    }
    return 0;
}
static void tcp_build_header(tcp_pcb* pcb, skbuff* skb, uint32_t ack){
    uint8_t flags = tcp_ecn_tx_flags(pcb, skb->l4_private.tcp.flag);
    skb->l4_private.tcp.flag = flags;
    uint32_t opt_len = tcp_build_options(pcb, skb);

    tcp_hdr* hdr = (tcp_hdr*)skb_data_push(
        skb, sizeof(tcp_hdr), sizeof(tcp_hdr));
    memset(hdr, 0, sizeof(tcp_hdr));
    skb->tcp_hdr = hdr;
    skb->tx_checksum_offset = 0;

    hdr->sport = pcb->sock->sport;
    hdr->dport = pcb->sock->dport;

    hdr->seq = htonl(skb->l4_private.tcp.seq);
    hdr->ack_seq = htonl(ack);

    hdr->flags = flags;
    hdr->doff_res_flags = (uint8_t)(((sizeof(tcp_hdr) + opt_len) / 4) << 4);

    hdr->window = htons(tcp_encode_window(pcb, flags));
    hdr->urg_ptr = 0;

    hdr->check = 0;
    if (pcb->sock->route->if_info->hw_tx_checksum_enabled) {
        hdr->check = pcb->sock->family == AF_INET6
            ? skb_checksum_protocol6(NULL, skb_data_len(skb),
                                     pcb->sock->sip6, pcb->sock->dip6,
                                     IPPROTO_TCP)
            : skb_checksum_protocol(NULL, skb_data_len(skb),
                                    pcb->sock->sip, pcb->sock->dip,
                                    IPPROTO_TCP);
        skb->tx_checksum_offset = offsetof(tcp_hdr, check);
    } else {
        if (pcb->sock->family == AF_INET6)
            hdr->check = skb_checksum_protocol6(
                skb, skb_data_len(skb), pcb->sock->sip6,
                pcb->sock->dip6, IPPROTO_TCP);
        else
            hdr->check = skb_checksum_protocol(
                skb, skb_data_len(skb), pcb->sock->sip,
                pcb->sock->dip, IPPROTO_TCP);
    }
}
static int tcp_xmit_skb(tcp_pcb* pcb, skbuff* skb, uint32_t ack,
                        uint32_t xmit_flags)
{
    Socket* sock = pcb->sock;
    skbuff* send_skb = skb;
    bool tracked = (xmit_flags & (TCP_XMIT_FLAG_NEW_TRANSMIT |
                                  TCP_XMIT_FLAG_RETRANSMIT)) != 0;
    if (tracked) {
        send_skb = skb_clone(skb);
        if (!send_skb)
            return -ENOMEM;
    }

    bool has_payload = skb_data_len(send_skb) != 0;

    const uint8_t* dest_ip = sock->family == AF_INET6
                                 ? sock->dip6
                                 : (const uint8_t*)&sock->dip;
    uint32_t scope_id = sock->family == AF_INET6
                            ? sock->dip6_scope_id : 0;
    if (!socket_route_is_valid(sock, dest_ip, scope_id)) {
        int ret = tcp_set_socket_route(sock, dest_ip, scope_id);
        if (ret < 0) {
            sock->error = EHOSTUNREACH;
            socket_notify_event(sock, notify_err);
            if (tracked)
                PUT_REF(send_skb);
            return ret;
        }
    }

    set_skb_by_socket(send_skb, sock);

    tcp_build_header(pcb, send_skb, ack);

    if ((xmit_flags & TCP_XMIT_FLAG_NEW_TRANSMIT) &&
        pcb->tcp_flag.ecn_ok && has_payload &&
        !(send_skb->l4_private.tcp.flag & TCP_FLAG_SYN))
        send_skb->l4_private.tcp.ip_ecn = TCP_ECN_ECT0;


    int ret = sock->family == AF_INET6
        ? ipv6_output(send_skb) : ipv4_output(send_skb);

    if (ret == 0 && (send_skb->l4_private.tcp.flag & TCP_FLAG_ACK)) {
        pcb->last_ack_sent = ack;
        pcb->ack_pending_segments = 0;
        tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                         TCP_TIMER_STOP, true);
    }

    if (xmit_flags & TCP_XMIT_FLAG_NEW_TRANSMIT) {
        if (skb->l4_private.tcp.flag & TCP_FLAG_SYN)
            pcb->snd_end++;
        pcb->snd_nxt += tcp_skb_seq_len(skb);
        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                         get_current_time_ms() + pcb->retransmit_timeout,
                         false);
        if (skb->l4_private.tcp.flag & TCP_FLAG_FIN)
            tcp_commit_fin_send(pcb);
        if (!(skb->l4_private.tcp.flag & TCP_FLAG_SYN) &&
            !pcb->rtt_meas_time) {
            pcb->rtt_meas_time = get_current_time_ms();
            pcb->rtt_meas_seq = skb->l4_private.tcp.seq;
        }
        tcp_skb_tree_insert(&pcb->retransmit_tree, skb,
                        offsetof(skbuff, retransmit_node));
        tcp_rack_skb_sent(pcb, skb, get_current_time_ms());
    } else if (xmit_flags & TCP_XMIT_FLAG_RETRANSMIT) {
        tcp_rack_skb_sent(pcb, skb, get_current_time_ms());
    }

    if (tracked)
        PUT_REF(send_skb);

    return ret;
}


skbuff* tcp_skb_split(tcp_pcb* pcb, skbuff* skb, uint32_t seq_len)
{
    uint32_t data_len = skb_data_len(skb);
    uint32_t split_seq = skb->l4_private.tcp.seq + seq_len;
    uint64_t pkt_send_ms = skb->l4_private.tcp.pkt_send_ms;
    uint8_t sack_state = skb->l4_private.tcp.sack_state;
    bool in_send_queue = LIST_ATTACHED(&skb->queue_node);
    bool in_retransmit_tree = !RB_EMPTY_NODE(&skb->retransmit_node);
    bool in_rack_queue = LIST_ATTACHED(&skb->rack_node);
    list_node* send_prev = in_send_queue ? skb->queue_node.pre : NULL;
    skbuff* tail;

    /* Splitting changes the byte ranges, so re-account SACK state on both
     * resulting skbs after the split. */
    tcp_sack_set_state(pcb, skb, 0);

    if (in_send_queue) {
        remove_list_node(&skb->queue_node);
        pcb->sock->send_queue.element_number--;
    }
    if (in_retransmit_tree)
        tcp_skb_tree_remove(&pcb->retransmit_tree, skb,
                            offsetof(skbuff, retransmit_node));
    if (in_rack_queue)
        tcp_rack_queue_remove(pcb, skb);

    if (seq_len < data_len) {
        tail = skb_split(skb, seq_len);
    } else {
        /* The split is between payload and FIN (or after SYN). */
        tail = tcp_alloc_skb(pcb->sock, 0);
    }
    if (!tail) {
        tcp_sack_set_state(pcb, skb, sack_state);
        if (in_send_queue) {
            add_list_node(send_prev, &skb->queue_node);
            pcb->sock->send_queue.element_number++;
        }
        if (in_retransmit_tree) {
            tcp_skb_tree_insert(&pcb->retransmit_tree, skb,
                                offsetof(skbuff, retransmit_node));
        }
        if (in_rack_queue)
            tcp_rack_update_skb(pcb, skb);
        return NULL;
    }

    tail->l4_private = skb->l4_private;
    /* Both pieces belong to the same original transmission. */
    tail->l4_private.tcp.pkt_send_ms = pkt_send_ms;
    tail->l4_private.tcp.seq = split_seq;
    tail->l4_private.tcp.seq_end = skb->l4_private.tcp.seq_end;
    if (skb->l4_private.tcp.flag & TCP_FLAG_SYN)
        tail->l4_private.tcp.flag &= ~TCP_FLAG_SYN;

    skb->l4_private.tcp.seq_end = split_seq;
    skb->l4_private.tcp.flag &= ~TCP_FLAG_FIN;

    tcp_sack_set_state(pcb, skb, sack_state);
    tcp_sack_set_state(pcb, tail, sack_state);

    if (in_send_queue) {
        add_list_node(send_prev, &skb->queue_node);
        add_list_node(&skb->queue_node, &tail->queue_node);
        pcb->sock->send_queue.element_number += 2;
    }
    if (in_retransmit_tree) {
        tcp_skb_tree_insert(&pcb->retransmit_tree, skb,
                            offsetof(skbuff, retransmit_node));
        tcp_skb_tree_insert(&pcb->retransmit_tree, tail,
                            offsetof(skbuff, retransmit_node));
    }
    if (in_rack_queue) {
        tcp_rack_update_skb(pcb, skb);
        tcp_rack_update_skb(pcb, tail);
    }
    return tail;
}

static void tcp_commit_fin_send(tcp_pcb* pcb)
{
    switch (pcb->state) {
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

static int tcp_send_new(tcp_pcb* pcb)
{
    Socket* sock = pcb->sock;
    uint32_t sent_bytes = 0;
    int ret = 0;

    while (sock->send_queue.element_number) {
        skbuff* skb = SKB_FROM_NODE(
            get_queue_first(&sock->send_queue), queue_node);

        if (!pcb->snd_wnd) {
            tcp_update_persist_timer(pcb);
            break;
        }

        uint32_t seq_budget = tcp_skb_budget(pcb, skb);
        if (!seq_budget)
            break;

        uint32_t seq_len = tcp_skb_seq_len(skb);
        seq_budget = min(seq_budget, seq_len);
        if (seq_budget < seq_len) {
            skbuff* tail_skb = tcp_skb_split(pcb, skb, seq_budget);
            if (!tail_skb) {
                tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                                 get_current_time_ms() +
                                     TCP_NAGLE_INTERVAL_MS_DEFAULT,
                                 false);
                ret = -ENOMEM;
                break;
            }
        }

        tcp_xmit_skb(pcb, skb, pcb->rcv_nxt,
                     TCP_XMIT_FLAG_NEW_TRANSMIT);

        (void)pop_queue(&sock->send_queue);

        sent_bytes += seq_budget;
        if (sent_bytes >= TCP_OUTPUT_BURST_MAX * pcb->snd_mss) {
            if (sock->send_queue.element_number)
                tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                                 get_current_time_ms(), false);
            break;
        }
    }
    return ret;
}


static inline uint32_t tcp_skb_budget(tcp_pcb* pcb, skbuff* skb)
{
    if(SEQ_GEQ(skb->l4_private.tcp.seq, pcb->snd_una + tcp_win_limit(pcb)))
        return 0;
    uint32_t t = pcb->snd_una + tcp_win_limit(pcb) - skb->l4_private.tcp.seq;
    uint32_t mss = pcb->snd_mss;
    return t - t % mss;
    
}

void tcp_retransmit_skb(tcp_pcb* pcb, skbuff* skb)
{
    uint64_t budget = tcp_skb_budget(pcb, skb);
    if(budget < tcp_skb_seq_len(skb)){
        WARN_LOG("send win or cwnd win decrease ???");
    }
    pcb->rtt_meas_time = 0;
    tcp_xmit_skb(pcb, skb, pcb->rcv_nxt,
                 TCP_XMIT_FLAG_RETRANSMIT);
}
static void tcp_send_new_fin(tcp_pcb* pcb){
    Socket* sock = pcb->sock;
    skbuff* last_send_skb = SKB_FROM_NODE(get_queue_last(&sock->send_queue), queue_node);
    if(!last_send_skb){
        last_send_skb = tcp_alloc_skb(sock, 0);
        if(!last_send_skb){
            ERR_LOG("Failed to allocate skb for sending FIN");
            tcp_destroy_socket(sock);
            return;
        }
        last_send_skb->l4_private.tcp.seq = pcb->snd_end;
        last_send_skb->l4_private.tcp.flag = TCP_FLAG_ACK;
        tcp_skb_update_seq_end(last_send_skb);
        add_queue(&sock->send_queue, &last_send_skb->queue_node);
    }
    last_send_skb->l4_private.tcp.flag |= TCP_FLAG_FIN;
    tcp_skb_update_seq_end(last_send_skb);
    pcb->snd_end++;

    if (pcb->nagle_deadline_ms == TCP_TIMER_STOP &&
        SEQ_LT(pcb->snd_nxt, pcb->snd_una + pcb->snd_wnd)) {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                         get_current_time_ms(), false);
    }
}

/* ── Socket 协议操作回调 ───────────────────────────────── */

static int tcp_connect(Socket *sock, req* req, const sockaddr_in *addr, socklen_t addrlen)
{
    int ret = 0;
    bool is_v6 = sock->family == AF_INET6;
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)addr;
    tcp_pcb* pcb = sock->pcb;
    socklen_t required = is_v6 ? sizeof(*addr6) : sizeof(*addr);

    if (req->status == REQ_WAITING_CONNECT)
        goto retry;
    if (addrlen < required)
        return -EINVAL;
    if (addr->sin_family != sock->family)
        return -EAFNOSUPPORT;
    if (pcb->state == TCP_STATE_SYN_SENT || pcb->state == TCP_STATE_SYN_RECEIVED)
        return -EALREADY;
    if (sock->flag.is_connected)
        return -EISCONN;
    if (pcb->state != TCP_STATE_CLOSED)
    {
        DEBUG_LOG("TCP Socket in invalid state %d for connect", pcb->state);
        return -EINVAL;
    }
    if(tcp_set_socket_route(sock,
        is_v6 ? (const uint8_t*)&addr6->sin6_addr : (const uint8_t*)&addr->sin_addr.s_addr,
        is_v6 ? addr6->sin6_scope_id : 0) < 0){
        ret = -EHOSTUNREACH;
        goto exit;
    }

    if (!sock->flag.is_bound)
    {
        if(socket_auto_bind(sock, tcp_bound_table(sock->family), NULL,
            is_v6 ? (const uint8_t*)&addr6->sin6_addr : (const uint8_t*)&addr->sin_addr.s_addr,
            is_v6 ? addr6->sin6_port : addr->sin_port,
            is_v6 ? addr6->sin6_scope_id : 0) < 0)
        {
            ret = -EADDRNOTAVAIL;
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
            ret = -EADDRNOTAVAIL;
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
            ret = -EADDRNOTAVAIL;
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
        worker* tuple_worker = rss_select_worker_by_tuple(sock->family,
            is_v6 ? sock->sip6 : (const uint8_t*)&sock->sip,
            is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip,
            sock->sport, dest_port);
        if (tuple_worker != get_current_worker()) {
            set_socket_worker(sock, tuple_worker);
            worker_move_request(req, tuple_worker);
            return REQ_PENDING;
        }
    }

    if (!install_tuple(sock, tcp_tuple_hash(sock->family)))
    {
        ret = -EADDRINUSE;
        goto exit;
    }

    pcb->state = TCP_STATE_SYN_SENT;
    ret = tcp_send_new_syn(sock);
    if (ret < 0) {
        ret = ret == -ENOMEM ? -ENOMEM : -ENETUNREACH;
        pcb->state = TCP_STATE_CLOSED;
        goto exit;
    }

    sock->flag.is_connected = true;
    if (sock->file_flags & O_NONBLOCK) {
        return -EINPROGRESS;
    }
    if(sock->options.send_timeout){
        stack_wait_request_until(sock, req, REQ_WAITING_CONNECT, get_current_time_ms() + get_time(&sock->send_timeout));
        return REQ_PENDING;
    }
    stack_wait_request(sock, req, REQ_WAITING_CONNECT);
    return REQ_PENDING;
retry:
    if (sock->error) {
        ret = -sock->error;
        sock->error = 0;
        goto exit;
    }
    bool is_expired = false;
    if(req->timeout_task && req->timeout_task->timeout <= get_current_time_ms())
        is_expired = true;
    if(pcb->state==TCP_STATE_ESTABLISHED || pcb->state==TCP_STATE_CLOSE_WAIT){
        ret=0;
    }else if(pcb->state==TCP_STATE_SYN_SENT || pcb->state==TCP_STATE_SYN_RECEIVED){
        if(is_expired){
            ret = -ETIMEDOUT;
        }else{
            ret = REQ_PENDING;
        }
    }else {
        DEBUG_LOG("TCP connect failed with state %d", pcb->state);
        ret = -ECONNREFUSED;
    }
    
exit:
    if (ret < 0 && ret != REQ_PENDING) {
        pcb->state = TCP_STATE_CLOSED;
        tcp_abort_connect(sock);
    }
    return ret;
}
static int tcp_bind(Socket *sock, req* r, const sockaddr_in *addr, socklen_t addrlen)
{
    (void)r;
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;
    if(pcb->state != TCP_STATE_CLOSED){
        DEBUG_LOG("TCP Socket in invalid state %d for bind", pcb->state);
        return -EINVAL;
    }
    return socket_bind_local(sock, addr, addrlen,
                             tcp_bound_table(sock->family));
}

static int tcp_listen(Socket* sock,req* req,int backlog){
    (void)req;
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    if(!sock->flag.is_bound){
        ret = -EINVAL;
        goto exit;
    }
    if(pcb->state != TCP_STATE_CLOSED){
        DEBUG_LOG("TCP Socket in invalid state %d for listen", pcb->state);
        ret = -EINVAL;
        goto exit;
    }
    if(!install_tuple(sock, tcp_tuple_hash(sock->family))){
        ret = -EADDRINUSE;
        goto exit;
    }

    pcb->state=TCP_STATE_LISTEN;
    pcb->backlog = max(backlog, 1);

exit:
    return ret;
}

static int tcp_accept(Socket* sock,req* r, sockaddr_in *addr, socklen_t *addrlen){
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    tcp_pcb* child_pcb;
    if(pcb->state!=TCP_STATE_LISTEN){
        //WARN_LOG("TCP Socket in invalid state %d for accept", pcb->state);
        ret = -EINVAL;
        goto exit;
    }
    if(!pcb->accept_list_num){
        if(!r || (sock->file_flags & O_NONBLOCK)){
            ret = -EAGAIN;
            goto exit;
        }
        if (r->status == REQ_WAITING_ACCEPT && r->timeout_task &&
            r->timeout_task->timeout <= get_current_time_ms()) {
            ret = -EAGAIN;
            goto exit;
        }
        if (sock->options.recv_timeout)
            stack_wait_request_until(sock, r, REQ_WAITING_ACCEPT,
                       get_current_time_ms() + get_time(&sock->recv_timeout));
        else
            stack_wait_request(sock, r, REQ_WAITING_ACCEPT);
        return REQ_PENDING;
    }
    child_pcb = (tcp_pcb*)((uint8_t*)pcb->accept_list.next - offsetof(tcp_pcb, accept_list));
    Socket* child_sock = child_pcb->sock;

    if (addr && !addrlen) {
        ret = -EFAULT;
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

    worker* child_worker = rss_select_worker_by_tuple(child_sock->family,
        child_sock->dip6, child_sock->sip6,
        child_sock->dport, child_sock->sport);
    fd_entry* entry = alloc_fd_entry_with_worker(child_sock, &socket_fd_ops,
                                                 child_worker);
    if(!entry){
        ERR_LOG("Failed to allocate fd entry for child socket");
        ret = -EMFILE;
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

static int tcp_read(Socket* sock,req* req,void *buf,uint32_t len)
{
    int ret = 0;
    tcp_pcb* pcb = sock->pcb;
    if (sock->error) {
        ret = -sock->error;
        sock->error = 0;
        return ret;
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
            ret = -ENOTCONN;
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
            ret = -ENOTCONN;
            goto exit;
    }
    /* If the receive queue is empty, either return EOF or wait. */
    if (!sock->recv_queue.element_number) {
        if (!req || (sock->file_flags & O_NONBLOCK)) {
            ret = -EAGAIN;
            goto exit;
        }
        if (req->status == REQ_WAITING_READ && req->timeout_task &&
            req->timeout_task->timeout <= get_current_time_ms()) {
            ret = -EAGAIN;
            goto exit;
        }
        if (sock->options.recv_timeout) {
            stack_wait_request_until(sock, req, REQ_WAITING_READ, get_current_time_ms() + get_time(&sock->recv_timeout));
            return REQ_PENDING;
        }
        stack_wait_request(sock, req, REQ_WAITING_READ);
        return REQ_PENDING;
    }

    uint32_t copied = 0;
    while (copied < len && sock->recv_queue.element_number) {
        skbuff* skb = SKB_FROM_NODE(get_queue_first(&sock->recv_queue), queue_node);

        uint32_t avail = skb_data_len(skb);
        if (avail == 0) {
            pop_queue(&sock->recv_queue);
            PUT_REF(skb);
            continue;
        }

        uint32_t n = (avail <= (len - copied)) ? avail : (len - copied);

        if (!skb_copy_bits(skb, 0, (uint8_t*)buf + copied, n)) {
            ERR_LOG("tcp_read: skb_copy_bits failed");
            if (!copied) {
                ret = -EIO;
                goto exit;
            }
            break;
        }
        copied += n;
        sock->recv_buffer_len -= n;

        if (n < avail) {
            skb_consume(skb, n, false);
            break;
        }

        pop_queue(&sock->recv_queue);
        PUT_REF(skb);
    }
    uint32_t old_wnd = pcb->rcv_wnd;
    pcb->rcv_wnd = SOCKET_USEABLE_RECV_BUFF_SIZE(sock);
    if (pcb->rcv_wnd > old_wnd) {
        tcp_update_timer(pcb, &pcb->ack_deadline_ms, get_current_time_ms(), false);
    }

    ret = (int)copied;

exit:
    return ret;
}

static int tcp_write(Socket* sock, req* req, const void *buf, uint32_t len)
{
    int ret = 0;
    tcp_pcb* pcb=sock->pcb;
    uint32_t send_len = 0;
    if (sock->error) {
        ret = -sock->error;
        sock->error = 0;
        return ret;
    }
    if (!len) {
        return 0;
	}
	if (sock->flag.close_send) {
		return -EPIPE;
	}

    if(!sock->flag.is_connected || !sock->flag.is_bound){
        ret = -ENOTCONN;
        goto exit;
    }
    switch(pcb->state){
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:
            break;
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
            ret = -EPIPE;
            goto exit;
        case TCP_STATE_LISTEN:
        case TCP_STATE_CLOSED:
            DEBUG_LOG("TCP Socket in invalid state %d for write", pcb->state);
            ret = -ENOTCONN;
            goto exit;
    }

    if(sock->send_buffer_len >= sock->send_buffer_len_max
        || pcb->state == TCP_STATE_SYN_SENT || pcb->state == TCP_STATE_SYN_RECEIVED){
        if(!req || (sock->file_flags & O_NONBLOCK)){
            ret = -EAGAIN;
            goto exit;
        }
        if (req->status == REQ_WAITING_WRITE && req->timeout_task &&
            req->timeout_task->timeout <= get_current_time_ms()) {
            ret = -EAGAIN;
            goto exit;
        }
        if(sock->options.send_timeout){
            stack_wait_request_until(sock,req,REQ_WAITING_WRITE, get_current_time_ms() + get_time(&sock->send_timeout));
        } else {
            stack_wait_request(sock,req,REQ_WAITING_WRITE);
        }
        return REQ_PENDING;
    }
    if(tcp_set_socket_route(sock, sock->family == AF_INET6 ? sock->dip6 : (const uint8_t*)&sock->dip,
                            sock->family == AF_INET6 ? sock->dip6_scope_id : 0) < 0){
        ret = -EHOSTUNREACH;
        goto exit;
    }

    /* Treat send_buffer_len_max as a high-water mark for a write request.
     * Once a request starts while the buffer is below the mark, enqueue the
     * whole request.  This keeps async writes from completing one MSS at a
     * time when only a small amount of space remains.  The next request will
     * wait until ACKs drain the queue below the mark again. */


    uint32_t seg_limit = pcb->snd_mss;


    uint32_t skb_capacity = tcp_skb_capacity(pcb);

    while (send_len < len) {
        uint32_t chunk = (len - send_len);
        if (chunk > skb_capacity)
            chunk = skb_capacity;

        skbuff* skb = SKB_FROM_NODE(get_queue_last(&sock->send_queue), queue_node);
        if (!skb || skb_data_len(skb) + chunk > skb_capacity) {
            skb = tcp_alloc_skb(sock, skb_capacity);
            if (!skb) {
                ERR_LOG("Failed to allocate skb for TCP write");
                break;
            }
            skb->l4_private.tcp.seq = pcb->snd_end;
            skb->l4_private.tcp.flag = TCP_FLAG_ACK;
            tcp_skb_update_seq_end(skb);
            add_queue(&sock->send_queue, &skb->queue_node);
        }

        if (!skb_data_append(skb, (uint8_t*)buf + send_len, chunk, seg_limit)) {
            ERR_LOG("Failed to append data to skb for TCP write");
            break;
        }

        tcp_skb_update_seq_end(skb);
        pcb->snd_end += chunk;
        sock->send_buffer_len += chunk;
        send_len += chunk;
    }

    if (send_len == 0) {
        ret = -ENOMEM;
        goto exit;
    }

    skbuff* first_skb = SKB_FROM_NODE(get_queue_first(&sock->send_queue), queue_node);
    if (skb_data_len(first_skb) >= (seg_limit / 2)
        || sock->send_queue.element_number > 1) {
        (void)tcp_send_new(pcb);
    } else {
        tcp_update_timer(pcb, &pcb->nagle_deadline_ms,
                         get_current_time_ms() + pcb->nagle_interval,
                         false);
    }

    ret = (int)send_len;
exit:
    return ret;
}
static int tcp_release(Socket* sock, req* req){
    tcp_pcb* pcb=sock->pcb;

    if (req->status == REQ_WAITING_CLOSE) {
        if (req->timeout_task &&
            req->timeout_task->timeout <= get_current_time_ms())
            return 0;
        return REQ_PENDING;
    }

    if (sock->options.linger && sock->linger_seconds == 0 &&
        pcb->state != TCP_STATE_CLOSED &&
        pcb->state != TCP_STATE_LISTEN &&
        pcb->state != TCP_STATE_TIME_WAIT) {
            (void)tcp_send_new_flag(sock, pcb->snd_nxt, pcb->rcv_nxt,
                                TCP_FLAG_RST | TCP_FLAG_ACK);
        pcb->state = TCP_STATE_CLOSED;
        tcp_destroy_socket(sock);
        return 0;
    }

    switch(pcb->state){
        case TCP_STATE_CLOSED:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_LISTEN:
            pcb->state=TCP_STATE_CLOSED;
            tcp_destroy_socket(sock);
            return 0;
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
            if (!sock->flag.close_send) {
                sock->flag.close_send = 1;
                tcp_send_new_fin(pcb);
            }
            break;
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:

            pcb->retries_max = TCP_ORPHAN_RETRIES_DEFAULT;
            break;
        case TCP_STATE_FIN_WAIT_2:
            pcb->retries_max = TCP_ORPHAN_RETRIES_DEFAULT;
            tcp_update_timer(pcb, &pcb->finwait2_deadline_ms,
                get_current_time_ms() + pcb->finwait2_timeout, true);
            break;
        case TCP_STATE_TIME_WAIT:
            break;
        default:
            ERR_LOG("tcp_release: unexpected TCP state %d on release", pcb->state);
            break;
    }

    if (sock->options.linger && sock->linger_seconds > 0 &&
        (pcb->state == TCP_STATE_ESTABLISHED ||
         pcb->state == TCP_STATE_CLOSE_WAIT ||
         pcb->state == TCP_STATE_FIN_WAIT_1 ||
         pcb->state == TCP_STATE_CLOSING ||
         pcb->state == TCP_STATE_LAST_ACK)) {
        stack_wait_request_until(sock, req, REQ_WAITING_CLOSE,
                   get_current_time_ms() +
                   (uint64_t)(uint32_t)sock->linger_seconds * 1000u);
        return REQ_PENDING;
    }
    return 0;
}
static int tcp_setsockopt(Socket* sock,req* req,int level,int optname,const void* optval,socklen_t optlen){
    tcp_pcb* pcb=sock->pcb;
    (void)req;
    if (level == SOL_SOCKET) {
        bool old_keepalive = sock->options.keepalive;
        int ret = socket_setsockopt(sock, level, optname, optval, optlen);
        if (ret != 0)
            return ret;

        if (optname == SO_RCVBUF) {
            uint32_t old_wnd = pcb->rcv_wnd;
            pcb->rcv_wnd = SOCKET_USEABLE_RECV_BUFF_SIZE(sock);
            if (old_wnd != pcb->rcv_wnd && sock->owner &&
                pcb->state >= TCP_STATE_SYN_RECEIVED &&
                pcb->state != TCP_STATE_TIME_WAIT) {
                tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                                 get_current_time_ms(), true);
            }
            return 0;
        }
        if (optname != SO_KEEPALIVE)
            return 0;

        if (!sock->options.keepalive) {
            pcb->keepalive_repeat_count = 0;
            tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                             TCP_TIMER_STOP, true);
        } else if (!old_keepalive &&
                   pcb->state != TCP_STATE_CLOSED &&
                   pcb->state != TCP_STATE_LISTEN &&
                   pcb->state != TCP_STATE_TIME_WAIT) {
            pcb->keepalive_repeat_count = 0;
            tcp_update_timer(pcb, &pcb->keepalive_deadline_ms,
                             get_current_time_ms() + pcb->keepalive_timeout,
                             true);
        }
        return 0;
    }

    if (level != IPPROTO_TCP)
        return -ENOPROTOOPT;
    if (optname != TCP_NODELAY)
        return -ENOPROTOOPT;
    if (optlen < sizeof(int))
        return -EINVAL;

    bool enabled = *(const int*)optval != 0;
    pcb->nagle_interval = enabled ? 0 : TCP_NAGLE_INTERVAL_MS_DEFAULT;
    return 0;
}
static int tcp_getsockopt(Socket* sock,req* req,int level,int optname,void* optval,socklen_t* optlen){
    tcp_pcb* pcb=sock->pcb;
    (void)req;
    if (level == SOL_SOCKET)
        return socket_getsockopt(sock, level, optname, optval, optlen);
    if (level != IPPROTO_TCP)
        return -ENOPROTOOPT;
    if (optname != TCP_NODELAY)
        return -ENOPROTOOPT;
    if (*optlen < sizeof(int))
        return -EINVAL;

    int value = pcb->nagle_interval == 0;
    memcpy(optval, &value, sizeof(value));
    *optlen = sizeof(value);
    return 0;
}

static int tcp_getsockname(Socket* sock,req* r,sockaddr_in* addr,socklen_t* addrlen){
    (void)r;
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
    (void)r;
    if(!sock->flag.is_connected)
        return -ENOTCONN;
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

/* ── ICMP 错误�?shutdown 回调 ──────────────────────────── */

static int tcp_icmp_process(Socket* sock, const icmp_error_info* info, int err)
{
    tcp_pcb* pcb = (tcp_pcb*)sock->pcb;

    if (info && info->has_tcp_seq &&
        !(SEQ_LEQ(pcb->snd_una, info->tcp_seq) &&
          SEQ_LT(info->tcp_seq, pcb->snd_nxt)))
        return 0;

    sock->error = err;


    switch (pcb->state) {
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RECEIVED:

            tcp_destroy_socket(sock);
            break;

        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
            socket_notify_event(sock, notify_err);
            break;

        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:

            tcp_destroy_socket(sock);
            break;

        default:
            break;
    }

    return 0;
}

static int tcp_shutdown(struct Socket* sock, req* req, int how)
{
    int ret = 0;

    (void)req;
    if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR)
        return -EINVAL;
    tcp_pcb *pcb = (tcp_pcb*)sock->pcb;
    if (!sock->flag.is_connected ||
        (pcb->state != TCP_STATE_ESTABLISHED &&
         pcb->state != TCP_STATE_CLOSE_WAIT &&
         pcb->state != TCP_STATE_FIN_WAIT_1 &&
         pcb->state != TCP_STATE_FIN_WAIT_2)) {
        return -ENOTCONN;
    }

    if ((how == SHUT_RD || how == SHUT_RDWR) &&
        !sock->flag.close_recv) {
        sock->flag.close_recv = 1;
        socket_notify_event(sock, notify_data_read);
    }

    if ((how == SHUT_WR || how == SHUT_RDWR) && !sock->flag.close_send) {
        sock->flag.close_send = 1;
        tcp_send_new_fin(pcb);
        ret = 0;
    }

    return ret;
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
    .shutdown = tcp_shutdown,
};
