#include <errno.h>
#include <fcntl.h>
#include "udp.h"
#include "log.h"
#include "base.h"
#include "queue.h"
#include "ip.h"
#include "ipv6.h"
#include "ipv6_ext.h"
#include "ether.h"
#include "fd_entry.h"
#include "worker.h" /* g_workers/g_worker_num */
#include "req_epoll.h"
#include "icmp.h"
#include "thread.h"

static int udp_recvfrom(struct Socket *sock, req* r, void *buf, uint32_t len, int flags, sockaddr_in* daddr, socklen_t* addrlen);
static int udp_sendto(struct Socket *sock, req* r, const void *buf, uint32_t len, int flags, sockaddr_in* dest_addr, socklen_t addrlen);
static int udp_recv_(skbuff* skb);
static int udp_release(struct Socket *sock, req* r);
static int udp_pcb_init(struct Socket* sock);
static bool udp_drain_send_queue(Socket* sock);

/* IP fragmentation mutates and splits its input skb.  Send a shallow clone
 * when fragmentation is expected so an EAGAIN retry keeps the queued UDP
 * datagram intact. */
static int udp_output(skbuff* skb, bool* original_unchanged)
{
    *original_unchanged = false;
    skbuff* output = skb;
    uint32_t ip_header = skb->family == AF_INET6
        ? IPV6_HDR_LEN : sizeof(ipv4_hdr);
    if (route_info_check(skb->route) &&
        skb_data_len(skb) + ip_header > get_route_mtu(skb->route)) {
        output = skb_clone(skb);
        if (!output)
            return -ENOMEM;
        *original_unchanged = true;
    }

    int ret = skb->family == AF_INET6
        ? ipv6_output(output) : ipv4_output(output);
    if (output != skb)
        PUT_REF(output);
    return ret;
}

/* The socket queue is a backpressure queue, not the normal UDP output path.
 * The caller keeps success semantics after ownership has been transferred to
 * this queue; its timer retries the same skb in-order. */
static void udp_enqueue_send(Socket* sock, skbuff* skb)
{
    udp_pcb* pcb = (udp_pcb*)sock->pcb;
    uint32_t payload_len = skb_data_len(skb) - sizeof(udp_hdr);

    INC_REF(skb);
    add_queue(&sock->send_queue, &skb->queue_node);
    sock->send_buffer_len += payload_len;

    if (!pcb->send_task->registered || !pcb->send_task->timeout) {
        pcb->send_task->timeout =
            get_current_time_ms() + pcb->send_retry_interval;
        register_task(sock->owner->master, pcb->send_task);
    }

    PUT_REF(skb);
}

static Socket* udp_lookup_recv_socket(uint32_t src_ip, uint16_t src_port,
                                      uint32_t dst_ip, uint16_t dst_port, worker** socket_worker){

    Socket* sock = search_socket_by_tuple(dst_ip, dst_port, src_ip, src_port, g_stack_maps->udp.tuple_hash4, socket_worker);
    if (sock) return sock;

    sock = search_socket_by_tuple(dst_ip, dst_port, 0, 0, g_stack_maps->udp.tuple_hash4, socket_worker);
    if (sock) return sock;

    return search_socket_by_tuple(INADDR_ANY, dst_port, 0, 0, g_stack_maps->udp.tuple_hash4, socket_worker);
}

static Socket* udp_lookup_recv_socket6(const uint8_t src_ip[16], uint16_t src_port,
                                       const uint8_t dst_ip[16], uint16_t dst_port,
                                       worker** socket_worker)
{
    static const uint8_t zero[16];
    Socket* sock = search_socket_by_tuple6(dst_ip, dst_port, src_ip, src_port,
                                            g_stack_maps->udp.tuple_hash6,
                                            socket_worker);
    if (sock)
        return sock;
    sock = search_socket_by_tuple6(dst_ip, dst_port, zero, 0,
                                   g_stack_maps->udp.tuple_hash6,
                                   socket_worker);
    if (sock)
        return sock;
    return search_socket_by_tuple6(zero, dst_port, zero, 0,
                                   g_stack_maps->udp.tuple_hash6,
                                   socket_worker);
}

static void make_udp_hdr(Socket* sock, skbuff* skb){
    udp_hdr* hdr = skb->udp_hdr;
    uint16_t udp_len = (uint16_t)skb_data_len(skb);
    hdr->sport = sock->sport;
    hdr->dport = sock->dport;
    hdr->len = htons(udp_len);
    hdr->check = 0;
    if (sock->family == AF_INET6)
        hdr->check = skb_checksum_protocol6(skb, udp_len, sock->sip6,
                                            sock->dip6, IPPROTO_UDP);
    else
        hdr->check = skb_checksum_protocol(skb, udp_len, sock->sip,
                                           sock->dip, IPPROTO_UDP);
    /* A computed zero checksum is represented as all ones. IPv6 never
     * permits an on-wire zero UDP checksum. */
    if (hdr->check == 0)
        hdr->check = 0xffffu;
    skb->udp_hdr = hdr;
}
static int socket_recv_skb(Socket* sock, skbuff* skb)
{
    uint32_t data_len = skb_data_len(skb);
    if (data_len > SOCKET_USEABLE_RECV_BUFF_SIZE(sock))
        return 0;
    skb->sock = sock;
    INC_REF(skb);
    add_queue(&sock->recv_queue, &skb->queue_node);
    sock->recv_buffer_len += data_len;
    socket_notify_event(sock, notify_data_read);
    return (int)data_len;
}

int udp_recv(skbuff* skb){
    if (skb_data0_len(skb) < sizeof(udp_hdr))
        return -1;

    udp_hdr* udp=(udp_hdr*)skb_start(skb);
    skb->udp_hdr = udp;
    uint16_t udp_total_len = ntohs(udp->len);
    if (udp_total_len < sizeof(udp_hdr)) {
        DEBUG_LOG("Invalid UDP length=%u", udp_total_len);
        return -1;
    }

    uint32_t avail = skb_data_len(skb);
    if (udp_total_len > avail) {
		DEBUG_LOG("UDP length exceeds available data udp_len=%u avail=%u", udp_total_len, avail);
        return -1;
    }
	if (skb->family == AF_INET6 && udp->check == 0)
		return -1;
	if ((skb->family == AF_INET6 || udp->check)
	    && !skb->flag.is_hw_rcv_checksum
	    && (skb->family == AF_INET6
	        ? skb_checksum_protocol6(skb, udp_total_len,
	                                 skb->ipv6_hdr->saddr,
	                                 skb->ipv6_hdr->daddr, IPPROTO_UDP)
	        : skb_checksum_protocol(skb, udp_total_len,
	                                skb->ipv4_hdr->saddr,
	                                skb->ipv4_hdr->daddr,
	                                IPPROTO_UDP)) != 0)
		return -1;
    skb_truncate(skb, udp_total_len);
    if (skb_consume(skb, sizeof(*udp), true) != sizeof(*udp))
        return -1;
    return udp_recv_(skb);
}
static int udp_recv_(skbuff* skb)
{
    udp_hdr*  udp = skb->udp_hdr;
    worker* socket_worker;
    Socket* sock;
    uint32_t rss = udp->sport;
    if (skb->family == AF_INET6) {
        sock = udp_lookup_recv_socket6(skb->ipv6_hdr->saddr, udp->sport,
                                       skb->ipv6_hdr->daddr, udp->dport,
                                       &socket_worker);
        for (uint32_t i = 0; i < 16; ++i)
            rss = rss * 33u + skb->ipv6_hdr->saddr[i];
    } else {
        ipv4_hdr* ip = skb->ipv4_hdr;
        sock = udp_lookup_recv_socket(ip->saddr, udp->sport,
                                      ip->daddr, udp->dport,
                                      &socket_worker);
        rss ^= ip->saddr;
    }
    if (!sock) {
        DEBUG_LOG("No socket found for received UDP packet family=%d dport=%u",
                  skb->family, ntohs(udp->dport));
        if (skb->family == AF_INET)
            (void)icmp_send_dest_unreach(skb, ICMP_PORT_UNREACH);
        return 0;
    }
    if (socket_worker != get_current_worker()) {
        transmit_skb_2_worker(socket_worker, skb, udp_recv_);
        return 0;
    }
    Socket* aim_sock = sock->tuple_node.next ? socket_select(sock, rss) : sock;
    socket_recv_skb(aim_sock, skb);
    return 0;
}
static int udp_read(struct Socket *sock, req* r, void *buf, uint32_t len){
    return udp_recvfrom(sock, r, buf, len, 0, NULL, NULL);
}
static int udp_recvfrom(struct Socket *sock, req* r, void *buf, uint32_t len, int flags, sockaddr_in* daddr, socklen_t* addrlen){
    if(!sock->flag.is_bound){
        r->saved_errno = ENOTCONN;
        //DEBUG_LOG("UDP Socket is not bound");
        return -1;
    }
    if(!sock->flag.is_hash){
        r->saved_errno = ENOTCONN;
        //DEBUG_LOG("UDP Socket is not hashed");
        return -1;
    }
    if (sock->recv_queue.element_number == 0 && sock->error) {
        int err = sock->error;
        sock->error = 0;
        r->saved_errno = err;
        return -1;
    }

    queue *q=&sock->recv_queue;
    if(q->element_number==0){
        /* MSG_DONTWAIT or O_NONBLOCK �?EAGAIN */
        if ((flags & MSG_DONTWAIT) || (sock->file_flags & O_NONBLOCK)) {
            r->saved_errno = EAGAIN;
            return -1;
        }

        /* Blocking semantics */
        if(!sock->options.recv_timeout){
            wait(sock, r, REQ_WAITING_READ);
            return REQ_PENDING;
        }

        /* SO_RCVTIMEO semantics */
        if(r->status == REQ_WAITING_READ && r->timeout_task
            && r->timeout_task->timeout <= get_current_time_ms()){
            r->saved_errno = EAGAIN;
            return -1;
        }

        wait_until(sock, r, REQ_WAITING_READ, get_current_time_ms() + get_time(&sock->recv_timeout));
        return REQ_PENDING;
    }

    bool is_peek = (flags & MSG_PEEK) != 0;

    /* MSG_PEEK: look at the head without dequeuing, no accounting change */
    skbuff* skb = is_peek ? SKB_FROM_QUEUE_NODE(get_queue_first(q))
                          : SKB_FROM_QUEUE_NODE(pop_queue(q));

    uint32_t avail = skb_data_len(skb);

    /* Update queue length accounting on dequeue (skip for peek). */
    if (!is_peek)
        sock->recv_buffer_len -= avail;

    /* Datagram semantics: if user buffer can't hold the whole packet, truncate it. */
    bool truncated = false;
    uint32_t recv_len = avail;
    if (recv_len > len) {
        DEBUG_LOG("udp_recvfrom: truncate datagram avail=%u buf_len=%u", avail, len);
        truncated = true;
        recv_len = len;
    }

    if (!skb_copy_bits(skb, 0, buf, recv_len)) {
        if (!is_peek)
            PUT_REF(skb);
        r->saved_errno = EIO;
        return -1;
    }

    if (daddr && addrlen) {
        /* sockaddr output follows recvfrom(2) semantics: *addrlen is the
         * caller's capacity on entry and receives the full required length;
         * copy only as many bytes as fit (important for sockaddr_in6). */
        struct sockaddr_storage out;
        socklen_t required;
        memset(&out, 0, sizeof(out));
        if (sock->family == AF_INET6) {
            struct sockaddr_in6 *out6 = (struct sockaddr_in6 *)&out;
            out6->sin6_family = AF_INET6;
            out6->sin6_port = skb->udp_hdr->sport;
            memcpy(&out6->sin6_addr, skb->ipv6_hdr->saddr, 16);
            if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr) && skb->recv_if)
                out6->sin6_scope_id = (uint32_t)skb->recv_if->ifindex;
            required = sizeof(*out6);
        } else {
            struct sockaddr_in *out4 = (struct sockaddr_in *)&out;
            out4->sin_family = AF_INET;
            out4->sin_port = skb->udp_hdr->sport;
            out4->sin_addr.s_addr = skb->ipv4_hdr->saddr;
            required = sizeof(*out4);
        }
        socklen_t capacity = *addrlen;
        if (capacity > required)
            capacity = required;
        if (capacity)
            memcpy(daddr, &out, capacity);
        *addrlen = required;
    }
    if (!is_peek)
        PUT_REF(skb);
    /* MSG_TRUNC: return real datagram length even when truncated */
    return (int)((truncated && (flags & MSG_TRUNC)) ? avail : recv_len);
}
static int udp_write(struct Socket *sock, req* r, const void *buf, uint32_t len){
    return udp_sendto(sock, r, buf, len, 0, NULL, 0);
}


static bool udp_drain_send_queue(Socket* sock)
{
    uint8_t entry_sip6[16];
    uint8_t entry_dip6[16];
    uint32_t entry_dip6_scope = sock->dip6_scope_id;
    memcpy(entry_sip6, sock->sip6, sizeof(entry_sip6));
    memcpy(entry_dip6, sock->dip6, sizeof(entry_dip6));
    uint16_t entry_dport = sock->dport;
    bool any_success = false;

    while (sock->send_queue.element_number) {
        skbuff* skb = SKB_FROM_QUEUE_NODE(get_queue_first(&sock->send_queue));
        if (!skb)
            break;

        uint32_t data_len = skb_data_len(skb) - sizeof(udp_hdr);

        /* Restore the addresses used when this datagram was checksummed. */
        if (sock->family == AF_INET6) {
            memcpy(sock->sip6, skb->l4_private.udp.src_ip6, 16);
            memcpy(sock->dip6, skb->l4_private.udp.dst_ip6, 16);
        } else {
            sock->sip = skb->l4_private.udp.src_ip;
            sock->dip = skb->l4_private.udp.dst_ip;
        }
        if (sock->family == AF_INET6)
            sock->dip6_scope_id = skb->l4_private.udp.dst_scope_id;
        sock->dport = skb->udp_hdr->dport;

        int route_ret = set_socket_route(sock,
            sock->family == AF_INET6 ? sock->dip6 : (const uint8_t*)&sock->dip,
            sock->family == AF_INET6 ? sock->dip6_scope_id : 0);
        if (route_ret < 0) {
            WARN_LOG("UDP send: route unavailable, dropping %u queued packets",
                    sock->send_queue.element_number);
            skbuff* drop;
            while ((drop = SKB_FROM_QUEUE_NODE(pop_queue(&sock->send_queue))) != NULL) {
                PUT_REF(drop);
            }
            sock->send_buffer_len = 0;
            sock->error = EHOSTUNREACH;
            socket_notify_event(sock, notify_err);
            goto out;
        }

        uint32_t pre_len = skb_data_len(skb);
        bool original_unchanged;
        int send_ret = udp_output(skb, &original_unchanged);

        if (send_ret < 0) {
            uint32_t pushed = !original_unchanged &&
                skb_data_len(skb) > pre_len ? skb_data_len(skb) - pre_len : 0;
            if (pushed) {
                skb_consume(skb, pushed, true);
                skb->udp_hdr = (udp_hdr*)skb_start(skb);
            }
            if (send_ret == -EAGAIN)
                goto out;

            /* Permanent error: drop this skb, try next. */
            DEBUG_LOG("UDP send failed: err=%d", -send_ret);
            (void)pop_queue(&sock->send_queue);
            sock->send_buffer_len -= data_len;
            sock->error = (send_ret == -ENETDOWN) ? ENETDOWN : EHOSTUNREACH;
            socket_notify_event(sock, notify_err);
            PUT_REF(skb);
            continue;
        }

        /* Success. */
        (void)pop_queue(&sock->send_queue);
        sock->send_buffer_len -= data_len;
        any_success = true;
        PUT_REF(skb);
    }

out:
    memcpy(sock->sip6, entry_sip6, sizeof(entry_sip6));
    memcpy(sock->dip6, entry_dip6, sizeof(entry_dip6));
    sock->dip6_scope_id = entry_dip6_scope;
    sock->dport = entry_dport;
    return any_success;
}

/* Timer callback: retry draining the send queue.  Exponential backoff on
 * consecutive failures; drop all queued packets after the limit. */
static void udp_send_timer_cb(task* tk)
{
    udp_pcb* pcb = (udp_pcb*)tk->argv;
    Socket* sock = pcb->sock;

    bool any_success = udp_drain_send_queue(sock);

    if (any_success) {
        pcb->send_retry_count = 0;
        pcb->send_retry_interval = UDP_SEND_RETRY_MIN_MS;
        socket_notify_event(sock, notify_data_write);
    }

    if (sock->send_queue.element_number) {
        /* No progress made → apply exponential backoff. */
        if (!any_success) {
            pcb->send_retry_count++;
            pcb->send_retry_interval = min(pcb->send_retry_interval * 2,
                                           UDP_SEND_RETRY_MAX_MS);
        }

        if (pcb->send_retry_count > UDP_SEND_RETRY_LIMIT) {
            WARN_LOG("UDP send retry limit reached, dropping %u queued packets",
                     sock->send_queue.element_number);
            skbuff* skb;
            while ((skb = SKB_FROM_QUEUE_NODE(pop_queue(&sock->send_queue))) != NULL) {
                uint32_t dl = skb_data_len(skb) - sizeof(udp_hdr);
                sock->send_buffer_len -= dl;
                PUT_REF(skb);
            }
            sock->error = ENETUNREACH;
            socket_notify_event(sock, notify_err);
            return;
        }

        update_task_timer(pcb->send_task,
                          get_current_time_ms() + pcb->send_retry_interval);
    } else {
        /* Queue empty → stop the retry timer. */
        if (pcb->send_task->timeout) {
            pcb->send_task->timeout = 0;
            unregister_task(pcb->send_task);
        }
    }
}

static int udp_sendto(struct Socket *sock, req* r, const void *buf, uint32_t len, int flags, sockaddr_in* dest_addr, socklen_t addrlen){
    int ret = 0;
    uint8_t orig_sip6[16], orig_dip6[16];
    uint32_t orig_sip6_scope = sock->sip6_scope_id;
    uint32_t orig_dip6_scope = sock->dip6_scope_id;
    memcpy(orig_sip6, sock->sip6, 16);
    memcpy(orig_dip6, sock->dip6, 16);
    uint16_t orig_dport = sock->dport;
    bool was_bound = sock->flag.is_bound;
    bool is_v6 = sock->family == AF_INET6;
    struct sockaddr_in6* dest6 = (struct sockaddr_in6*)dest_addr;
    static const uint8_t zero6[16];

    uint32_t max_payload = UINT16_MAX - sizeof(udp_hdr) -
        (is_v6 ? 0u : (uint32_t)sizeof(ipv4_hdr));
    if (len > max_payload) {
        r->saved_errno = EMSGSIZE;
        return -1;
    }
    bind_table* bound_table = udp_bound_table(sock->family);

    socklen_t required = is_v6 ? sizeof(*dest6) : sizeof(*dest_addr);
    if (dest_addr && addrlen < required) {
        r->saved_errno = EINVAL;
        return -1;
    }
    if (dest_addr && dest_addr->sin_family != sock->family) {
        r->saved_errno = EAFNOSUPPORT;
        return -1;
    }

    if (sock->flag.is_connected) {
        bool different = false;
        if (dest_addr) {
            different = is_v6
                ? (dest6->sin6_port != sock->dport ||
                   dest6->sin6_scope_id != sock->dip6_scope_id ||
                   memcmp(&dest6->sin6_addr, sock->dip6, 16) != 0)
                : (dest_addr->sin_port != sock->dport ||
                   dest_addr->sin_addr.s_addr != sock->dip);
        }
        if (different) {
            r->saved_errno = EISCONN;
            return -1;
        }
    } else {
        if (!dest_addr) {
            r->saved_errno = EDESTADDRREQ;
            return -1;
        }
        if (is_v6) {
            memcpy(sock->dip6, &dest6->sin6_addr, 16);
            sock->dip6_scope_id = dest6->sin6_scope_id;
            sock->dport = dest6->sin6_port;
        } else {
            sock->dip = dest_addr->sin_addr.s_addr;
            sock->dport = dest_addr->sin_port;
        }
    }

    if (sock->error) {
        int err = sock->error;
        sock->error = 0;
        r->saved_errno = err;
        ret = -1;
        goto exit;
    }

    int route_ret = set_socket_route(sock,
        is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip,
        is_v6 ? sock->dip6_scope_id : 0);
    if (route_ret < 0) {
        r->saved_errno = EHOSTUNREACH;
        ret = -1;
        goto exit;
    }

    if (!sock->flag.is_bound) {
        int bind_ret = socket_auto_bind(sock, bound_table,
            is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip,
            sock->dport,
            is_v6 ? sock->dip6_scope_id : 0);
        if (bind_ret < 0) {
            r->saved_errno = EADDRINUSE;
            ret = -1;
            goto exit;
        }
    } else if ((is_v6 && memcmp(sock->sip6, zero6, 16) == 0) ||
               (!is_v6 && sock->sip == 0)) {
        uint8_t saddr[16];
        const uint8_t* daddr = is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip;
        if (!if_search_best_saddr_by_daddr(sock->route->if_info, sock->family,
                                           daddr, saddr)) {
            r->saved_errno = EADDRNOTAVAIL;
            ret = -1;
            goto exit;
        }

        addr_key key = { .port = sock->sport,
                         .family = is_v6 ? AF_INET6 : AF_INET,
                         .scope_id = is_v6 ? sock->sip6_scope_id : 0 };
        if (is_v6)
            memcpy(key.addr6, saddr, 16);
        else
            memcpy(&key.addr, saddr, 4);
        if (bind_exist(&key, bound_table)) {
            r->saved_errno = EADDRINUSE;
            ret = -1;
            goto exit;
        }
        if (is_v6)
            memcpy(sock->sip6, saddr, 16);
        else
            memcpy(&sock->sip, saddr, 4);
    }

    /* Ensure the final (sip, sport, dip, dport) tuple maps to this worker. */
    {
        worker* tuple_worker = select_worker_by_tuple(sock->family,
            is_v6 ? sock->sip6 : (const uint8_t*)&sock->sip,
            is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip,
            sock->sport, sock->dport);
        if (tuple_worker != get_current_worker()) {
            set_socket_worker(sock, tuple_worker);
            change_req_worker(r, tuple_worker);
            return REQ_PENDING;
        }
    }

    if (!is_v6 && route_is_broadcast(sock->route) && !sock->options.broadcast) {
        r->saved_errno = EACCES;
        DEBUG_LOG("Broadcast address requires SO_BROADCAST option");
        ret = -1;
        goto exit;
    }

    /* Send-buffer space check. */
    if (SOCKET_USEABLE_SEND_BUFF_SIZE(sock) < len) {
        if ((flags & MSG_DONTWAIT) || (sock->file_flags & O_NONBLOCK)) {
            r->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        if (!sock->options.send_timeout) {
            wait(sock, r, REQ_WAITING_WRITE);
            ret = REQ_PENDING;
            goto exit;
        }
        if (r->status == REQ_WAITING_WRITE && r->timeout_task &&
            r->timeout_task->timeout <= get_current_time_ms()) {
            r->saved_errno = EAGAIN;
            ret = -1;
            goto exit;
        }
        wait_until(sock, r, REQ_WAITING_WRITE,
                   get_current_time_ms() + get_time(&sock->send_timeout));
        ret = REQ_PENDING;
        goto exit;
    }

    /* Build skb. */
    uint32_t udp_l2_len = sock->route->if_info->l2_len;
    uint32_t hdr_len = sizeof(udp_hdr) + (is_v6 ? MAX_IP6_HDR_WITH_EXT_LEN : MAX_IP_HDR_WITH_OPT_LEN) + udp_l2_len;
    skbuff* skb = skb_alloc(hdr_len + len);
    if (!skb) {
        r->saved_errno = ENOMEM;
        ERR_LOG("skb alloc failed");
        ret = -1;
        goto exit;
    }
    skb_reserve(skb, hdr_len);
    udp_hdr* udp = (udp_hdr*)skb_data_push(skb, sizeof(*udp));
    if (!udp) {
        r->saved_errno = ENOMEM;
        PUT_REF(skb);
        ret = -1;
        goto exit;
    }
    skb->udp_hdr = udp;

    uint32_t seg_len = 0;
    uint32_t pre_size = 0;
    uint32_t mtu = get_route_mtu(sock->route);
    uint32_t l2_len = sock->route->if_info->l2_len;
    uint32_t ip_headers = is_v6
            ? IPV6_HDR_LEN + sizeof(ipv6_frag_hdr) : sizeof(ipv4_hdr);
    seg_len  = (mtu + l2_len) & ~7u;
    pre_size = ip_headers + l2_len;

    if (!skb_data_append(skb, buf, len, pre_size, seg_len)) {
        r->saved_errno = ENOMEM;
        ERR_LOG("skb_data_append failed len=%u", (uint32_t)len);
        PUT_REF(skb);
        ret = -1;
        goto exit;
    }

    set_skb_by_socket(skb, sock);
    make_udp_hdr(sock, skb);
    if (is_v6) {
        memcpy(skb->l4_private.udp.src_ip6, sock->sip6, 16);
        memcpy(skb->l4_private.udp.dst_ip6, sock->dip6, 16);
    } else {
        skb->l4_private.udp.src_ip = sock->sip;
        skb->l4_private.udp.dst_ip = sock->dip;
    }
    if (is_v6)
        skb->l4_private.udp.dst_scope_id = sock->dip6_scope_id;

    /* Preserve datagram order while a previous output is back-pressured. */
    if (sock->send_queue.element_number) {
        udp_enqueue_send(sock, skb);
        ret = (int)len;
        goto exit;
    }

    /* Immediate output path. */
    uint32_t pre_len = skb_data_len(skb);
    bool original_unchanged;
    int send_ret = udp_output(skb, &original_unchanged);
    if (send_ret == 0) {
        PUT_REF(skb);
        ret = (int)len;
        goto exit;
    }

    /* Pop headers pushed by ipv4_output, restoring UDP-hdr-only state. */
    uint32_t pushed = !original_unchanged && skb_data_len(skb) > pre_len
        ? skb_data_len(skb) - pre_len : 0;
    if (pushed) {
        skb_consume(skb, pushed, true);
        skb->udp_hdr = (udp_hdr*)skb_start(skb);
    }

    if (send_ret == -EAGAIN) {
        udp_enqueue_send(sock, skb);
        ret = (int)len;
        goto exit;
    }

    r->saved_errno = (send_ret == -ENETDOWN) ? ENETDOWN : EHOSTUNREACH;
    PUT_REF(skb);
    ret = -1;

exit:
    if (was_bound)
        memcpy(sock->sip6, orig_sip6, 16);
    memcpy(sock->dip6, orig_dip6, 16);
    if (was_bound)
        sock->sip6_scope_id = orig_sip6_scope;
    sock->dip6_scope_id = orig_dip6_scope;
    sock->dport = orig_dport;
    return ret;
}

static int udp_connect(struct Socket *sock, req* r, const struct sockaddr_in *addr, socklen_t addrlen)
{
    bool was_connected = sock->flag.is_connected;
    bool was_hashed = sock->flag.is_hash;
    bool is_v6 = sock->family == AF_INET6;
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)addr;
    socklen_t required = is_v6 ? sizeof(*addr6) : sizeof(*addr);
    uint32_t old_dip = sock->dip;
    uint8_t old_dip6[16];
    uint32_t old_scope_id = sock->dip6_scope_id;
    uint16_t old_dport = sock->dport;
    memcpy(old_dip6, sock->dip6, sizeof(old_dip6));

    if (addrlen < required) {
        r->saved_errno = EINVAL;
        return -1;
    }
    if (addr->sin_family != sock->family) {
        r->saved_errno = EAFNOSUPPORT;
        return -1;
    }

    int route_ret = set_socket_route(sock,
        is_v6 ? (const uint8_t*)&addr6->sin6_addr : (const uint8_t*)&addr->sin_addr.s_addr,
        is_v6 ? addr6->sin6_scope_id : 0);
    if (route_ret < 0) {
        r->saved_errno = EHOSTUNREACH;
        return -1;
    }

    if (!sock->flag.is_bound) {
        int bind_ret = socket_auto_bind(sock, udp_bound_table(sock->family),
            is_v6 ? (const uint8_t*)&addr6->sin6_addr : (const uint8_t*)&addr->sin_addr.s_addr,
            is_v6 ? addr6->sin6_port : addr->sin_port,
            is_v6 ? addr6->sin6_scope_id : 0);
        if (bind_ret < 0) {
            r->saved_errno = EADDRINUSE;
            return -1;
        }
    }

    /* Reconnecting UDP is supported, but the old tuple must be removed
     * before overwriting the peer fields used to construct its hash key. */
    if (was_hashed && !uninstall_tuple(sock, udp_tuple_hash(sock->family))) {
        r->saved_errno = EIO;
        return -1;
    }

    if (is_v6) {
        memcpy(sock->dip6, &addr6->sin6_addr, 16);
        sock->dip6_scope_id = addr6->sin6_scope_id;
        sock->dport = addr6->sin6_port;
    } else {
        sock->dip = addr->sin_addr.s_addr;
        sock->dport = addr->sin_port;
    }

    /* Ensure the final tuple maps to this worker before installing it. */
    {
        worker* tuple_worker = select_worker_by_tuple(sock->family,
            is_v6 ? sock->sip6 : (const uint8_t*)&sock->sip,
            is_v6 ? sock->dip6 : (const uint8_t*)&sock->dip,
            sock->sport, sock->dport);
        if (tuple_worker != get_current_worker()) {
            set_socket_worker(sock, tuple_worker);
            change_req_worker(r, tuple_worker);
            return REQ_PENDING;
        }
    }

    if (!install_tuple(sock, udp_tuple_hash(sock->family))) {
        WARN_LOG("Failed to install UDP Socket tuple on connect");
        sock->dip = old_dip;
        memcpy(sock->dip6, old_dip6, sizeof(old_dip6));
        sock->dip6_scope_id = old_scope_id;
        sock->dport = old_dport;
        sock->flag.is_connected = was_connected;
        if (was_hashed && !install_tuple(sock, udp_tuple_hash(sock->family)))
            ERR_LOG("Failed to restore old UDP tuple after reconnect failure");
        r->saved_errno = EADDRINUSE;
        return -1;
    }
    sock->flag.is_connected = 1;
    return 0;
}

static int udp_bind(struct Socket *sock, req* r, const struct sockaddr_in *addr, socklen_t addrlen)
{
    bind_table* bound_table = udp_bound_table(sock->family);
    hash* tuple_hash = udp_tuple_hash(sock->family);

    bool is_v6 = sock->family == AF_INET6;
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)addr;
    socklen_t required = is_v6 ? sizeof(*addr6) : sizeof(*addr);
    if (addrlen < required) {
        r->saved_errno = EINVAL;
        return -1;
    }
    if (addr->sin_family != sock->family) {
        r->saved_errno = EAFNOSUPPORT;
        return -1;
    }
    if (sock->flag.is_bound) {
        r->saved_errno = EINVAL;
        return -1;
    }
    uint16_t port = is_v6 ? addr6->sin6_port : addr->sin_port;
    if (!port) {
        r->saved_errno = EINVAL;
        return -1;
    }
    static const uint8_t zero6[16];
    const uint8_t* ip = is_v6 ? (const uint8_t*)&addr6->sin6_addr
                              : (const uint8_t*)&addr->sin_addr.s_addr;
    bool any = is_v6 ? memcmp(ip, zero6, 16) == 0
                     : addr->sin_addr.s_addr == INADDR_ANY;
    if (is_v6 && IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && !addr6->sin6_scope_id) {
        r->saved_errno = EINVAL;
        DEBUG_LOG("IPv6 link-local bind requires a scope ID (e.g. fe80::1%%eth0)");
        return -1;
    }
    if (!any && !search_addr_exist(sock->family, ip,
            is_v6 ? addr6->sin6_scope_id : 0)) {
        r->saved_errno = EADDRNOTAVAIL;
        DEBUG_LOG("UDP bind address is not available for family=%d", sock->family);
        return -1;
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
    if (!bind_saddr(sock, &key, bound_table)) {
        r->saved_errno = EADDRINUSE;
        return -1;
    }
    if (is_v6)
        sock->sip6_scope_id = addr6->sin6_scope_id;
    if (!install_tuple(sock, tuple_hash)) {
        r->saved_errno = EADDRINUSE;
        WARN_LOG("Failed to install UDP Socket tuple");
        unbind_saddr(sock, bound_table);
        return -1;
    }
    return 0;
}

static int udp_getsockname(struct Socket *sock, req* r, struct sockaddr_in *addr, socklen_t *addrlen)
{
    (void)r;
    struct sockaddr_storage out;
    socklen_t required;
    memset(&out, 0, sizeof(out));
    if (sock->family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&out;
        addr6->sin6_family = AF_INET6;
        memcpy(&addr6->sin6_addr, sock->sip6, 16);
        addr6->sin6_port = sock->sport;
        addr6->sin6_scope_id = sock->sip6_scope_id;
        required = sizeof(*addr6);
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&out;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = sock->sip;
        addr4->sin_port = sock->sport;
        required = sizeof(*addr4);
    }
    socklen_t capacity = *addrlen;
    if (capacity > required) capacity = required;
    if (capacity) memcpy(addr, &out, capacity);
    *addrlen = required;
    return 0;
}

static int udp_getpeername(struct Socket *sock, req* r, struct sockaddr_in *addr, socklen_t *addrlen)
{
    if (!sock->flag.is_connected) {
        r->saved_errno = ENOTCONN;
        return -1;
    }
    struct sockaddr_storage out;
    socklen_t required;
    memset(&out, 0, sizeof(out));
    if (sock->family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&out;
        addr6->sin6_family = AF_INET6;
        memcpy(&addr6->sin6_addr, sock->dip6, 16);
        addr6->sin6_port = sock->dport;
        addr6->sin6_scope_id = sock->dip6_scope_id;
        required = sizeof(*addr6);
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)&out;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = sock->dip;
        addr4->sin_port = sock->dport;
        required = sizeof(*addr4);
    }
    socklen_t capacity = *addrlen;
    if (capacity > required) capacity = required;
    if (capacity) memcpy(addr, &out, capacity);
    *addrlen = required;
    return 0;
}

static int udp_setsockopt(struct Socket* sock, req* r, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == SOL_SOCKET) {
        int ret = socket_setsockopt(sock, level, optname, optval, optlen);
        if (ret < 0 && r->saved_errno == 0)
            r->saved_errno = ENOPROTOOPT;
        return ret;
    }
    r->saved_errno = ENOPROTOOPT;
    return -1;
}

static int udp_getsockopt(struct Socket* sock, req* r, int level, int optname, void* optval, socklen_t* optlen)
{
    if (!optval || !optlen || *optlen == 0) {
        r->saved_errno = EINVAL;
        return -1;
    }

    if (level == SOL_SOCKET) {
        int ret = socket_getsockopt(sock, level, optname, optval, optlen);
        if (ret < 0 && r->saved_errno == 0)
            r->saved_errno = ENOPROTOOPT;
        return ret;
    }
    r->saved_errno = ENOPROTOOPT;
    return -1;
}

static uint32_t udp_poll(struct Socket* sock)
{
    uint32_t mask = 0;

    if (sock->error)
        mask |= EPOLLERR;

    if (sock->recv_buffer_len > 0 && !sock->flag.close_recv)
        mask |= EPOLLIN;

    if (SOCKET_USEABLE_SEND_BUFF_SIZE(sock) > 0 && !sock->flag.close_send)
        mask |= EPOLLOUT;

    return mask;
}

static int udp_release(struct Socket *sock, req* r)
{
    (void)r;
    udp_pcb* pcb = (udp_pcb*)sock->pcb;
    if (pcb) {
        if (pcb->send_task) {
            destroy_task(pcb->send_task);
        }
        skbuff* skb;
        while ((skb = SKB_FROM_QUEUE_NODE(pop_queue(&sock->send_queue))) != NULL) {
            PUT_REF(skb);
        }
        free(pcb);
        sock->pcb = NULL;
    }
    destroy_socket(sock);
    return 0;
}
static int udp_pcb_init(struct Socket* sock)
{
    udp_pcb* pcb = calloc(1, sizeof(udp_pcb));
    if (!pcb) {
        ERR_LOG("udp_pcb_init: calloc failed");
        return -1;
    }
    sock->pcb = pcb;
    pcb->sock = sock;

    pcb->send_task = create_task(TASK_TYPE_TIMER);
    if (!pcb->send_task) {
        ERR_LOG("udp_pcb_init: create_task failed");
        free(pcb);
        sock->pcb = NULL;
        return -1;
    }
    pcb->send_task->cb_timer = udp_send_timer_cb;
    pcb->send_task->argv = (uint64_t)pcb;

    pcb->send_retry_interval = UDP_SEND_RETRY_MIN_MS;
    pcb->send_retry_count = 0;

    return 0;
}

static int udp_icmp_process(struct Socket* sock,
                            const icmp_error_info* info, int err)
{
    (void)info;
    if (!sock->flag.is_bound || !sock->flag.is_connected) {
        return 0;
    }

    sock->error = err;
    socket_notify_event(sock, notify_err);
    return 0;
}
protocol_ops udp_protocol_ops = {
    .protocol = IPPROTO_UDP,
    .pcb_init = udp_pcb_init,
    .icmp_process = udp_icmp_process,
    .read = udp_read,
    .write = udp_write,
    .recvfrom = udp_recvfrom,
    .sendto = udp_sendto,
    .release = udp_release,
    .connect = udp_connect,
    .bind = udp_bind,
    .listen = NULL,
    .accept = NULL,
    .getsockname = udp_getsockname,
    .getpeername = udp_getpeername,
    .setsockopt = udp_setsockopt,
    .getsockopt = udp_getsockopt,
    .poll = udp_poll,
};
