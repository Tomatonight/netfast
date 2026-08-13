#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base.h"
#include "loopback.h"
#include "netfast.h"
#include "ipv6_ext.h"
#include "route_arp_ndp.h"
#include "skbuff.h"
#include "socket.h"
#include "tcp.h"
#include "udp.h"
#include "worker.h"
#include "xdp.h"

#include "test_common.h"

static worker test_worker;
static pthread_t worker_thread;
static atomic_bool worker_running;

static void *run_test_worker(void *opaque)
{
    worker *worker = opaque;
    set_current_worker(worker);
    current_time_ms = read_now_ms();
    while (atomic_load_explicit(&worker_running, memory_order_acquire))
        (void)thread_step(worker->master);
    set_current_worker(NULL);
    return NULL;
}

static int setup_loopback_runtime(void)
{
    current_time_ms = read_now_ms();
    TEST_ASSERT(xdp_frame_pool_init() == 0);
    memset(&test_worker, 0, sizeof(test_worker));
    g_workers = &test_worker;
    g_worker_num = 1;
    main_worker = &test_worker;
    TEST_ASSERT(worker_init(&test_worker) == 0);
    TEST_ASSERT(route_init() == 0);
    TEST_ASSERT(loopback_init() == 0);
    atomic_store_explicit(&worker_running, true, memory_order_release);
    TEST_ASSERT(pthread_create(&worker_thread, NULL, run_test_worker,
                               &test_worker) == 0);
    return 0;
}

static int wait_for_read(int fd, void *buffer, size_t len)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        int ret = net_read(fd, buffer, (uint32_t)len);
        if (ret >= 0)
            return ret;
        if (errno != EAGAIN)
            return -1;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int wait_for_recvfrom(int fd, void *buffer, size_t len,
                             struct sockaddr_in *from, socklen_t *from_len)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        int ret = net_recvfrom(fd, buffer, (uint32_t)len, MSG_DONTWAIT,
                               (struct sockaddr *)from, from_len);
        if (ret >= 0)
            return ret;
        if (errno != EAGAIN)
            return -1;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static uint32_t skb_chain_count(const skbuff *skb, uint32_t *total_len)
{
    uint32_t count = 0;
    uint32_t total = 0;
    for (const data_info *di = &skb->data0; di; di = di->next) {
        count++;
        total += (uint32_t)(di->end - di->start);
    }
    if (total_len)
        *total_len = total;
    return count;
}

static int test_skb_multisegment_clone_copy(void)
{
    worker allocation_worker = {0};
    allocation_worker.master = create_thread();
    TEST_ASSERT(allocation_worker.master);
    set_current_worker(&allocation_worker);

    uint8_t payload[3000];
    uint8_t copied[3000];
    for (uint32_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i * 31u + 7u);

    skbuff *source = skb_alloc(128);
    TEST_ASSERT(source);
    TEST_ASSERT(skb_data_append(source, payload, sizeof(payload), 0, 1024));
    uint32_t total = 0;
    TEST_ASSERT(source->data_num > 1);
    TEST_ASSERT(skb_chain_count(source, &total) == source->data_num);
    TEST_ASSERT(total == sizeof(payload) && total == skb_data_len(source));
    source->l4_hdr = skb_start(source);
    source->tx_checksum_offset = 16;

    skbuff *clone = skb_clone(source);
    TEST_ASSERT(clone);
    TEST_ASSERT(clone->l4_hdr == source->l4_hdr);
    TEST_ASSERT(clone->tx_checksum_offset == 16);
    TEST_ASSERT(skb_chain_count(clone, &total) == clone->data_num);
    TEST_ASSERT(total == sizeof(payload));
    TEST_ASSERT(skb_copy_bits(clone, 0, copied, sizeof(copied)));
    TEST_ASSERT(memcmp(copied, payload, sizeof(payload)) == 0);

    skbuff *copy = skb_copy(source);
    TEST_ASSERT(copy);
    TEST_ASSERT(copy->l4_hdr == skb_start(copy));
    TEST_ASSERT(copy->tx_checksum_offset == 16);
    TEST_ASSERT(skb_chain_count(copy, &total) == copy->data_num);
    TEST_ASSERT(total == sizeof(payload));
    TEST_ASSERT(copy->data0.slot != source->data0.slot);
    TEST_ASSERT(skb_copy_bits(copy, 0, copied, sizeof(copied)));
    TEST_ASSERT(memcmp(copied, payload, sizeof(payload)) == 0);

    void *l4_hdr = source->l4_hdr;
    TEST_ASSERT(skb_data_push(source, 20));
    TEST_ASSERT(source->l4_hdr == l4_hdr);
    TEST_ASSERT(source->tx_checksum_offset == 16);

    skb_truncate(clone, 1500);
    TEST_ASSERT(skb_chain_count(clone, &total) == clone->data_num);
    TEST_ASSERT(total == 1500 && total == skb_data_len(clone));

    skbuff *tail = skb_split(copy, 1500);
    TEST_ASSERT(tail);
    TEST_ASSERT(skb_chain_count(copy, &total) == copy->data_num);
    TEST_ASSERT(total == 1500 && total == skb_data_len(copy));
    TEST_ASSERT(skb_chain_count(tail, &total) == tail->data_num);
    TEST_ASSERT(total == sizeof(payload) - 1500 &&
                total == skb_data_len(tail));

    PUT_REF(tail);
    PUT_REF(copy);
    PUT_REF(clone);
    PUT_REF(source);
    set_current_worker(NULL);
    destroy_thread(allocation_worker.master);
    return 0;
}

static skbuff *make_ipv6_packet(uint32_t payload_len, uint8_t next_header,
                                uint32_t segment_len)
{
    uint8_t *packet = calloc(1, IPV6_HDR_LEN + payload_len);
    if (!packet)
        return NULL;

    ipv6_hdr *ip6 = (ipv6_hdr *)packet;
    ip6->vtf = ipv6_make_vtf(0, 0);
    ip6->payload_len = htons((uint16_t)payload_len);
    ip6->next_hdr = next_header;
    ip6->hop_limit = 64;
    ip6->saddr[15] = 1;
    ip6->daddr[15] = 2;
    for (uint32_t i = 0; i < payload_len; ++i)
        packet[IPV6_HDR_LEN + i] = (uint8_t)(i * 17u + 3u);

    skbuff *skb = skb_alloc(128);
    if (!skb || !skb_data_append(skb, packet, IPV6_HDR_LEN + payload_len,
                                 0, segment_len)) {
        PUT_REF(skb);
        skb = NULL;
    }
    free(packet);
    if (skb)
        skb->ipv6_hdr = (ipv6_hdr *)skb_start(skb);
    return skb;
}

static int test_ipv6_extension_fragmentation(void)
{
    worker allocation_worker = {0};
    allocation_worker.master = create_thread();
    TEST_ASSERT(allocation_worker.master);
    set_current_worker(&allocation_worker);
    allocation_worker.stack.ipq6_hash = hash_create(32,
        HASH_KEY_OFFSET(ipq6, hash_node, key), sizeof(ipq6_key));
    TEST_ASSERT(allocation_worker.stack.ipq6_hash);

    skbuff *plain = make_ipv6_packet(32, IPPROTO_UDP, 32);
    TEST_ASSERT(plain && !ipv6_has_frag(plain));
    PUT_REF(plain);

    skbuff *skb = make_ipv6_packet(4000, IPPROTO_UDP, 512);
    TEST_ASSERT(skb);
    if_info iface = {.mtu = 1280};
    route_info *route = calloc(1, sizeof(*route));
    TEST_ASSERT(route);
    INIT_REF(route, NULL);
    route->if_info = &iface;
    skb->route = route;
    TEST_ASSERT(ipv6_frag(skb));
    TEST_ASSERT(ipv6_has_frag(skb));

    skbuff *fragments[8] = {0};
    uint32_t count = 0;
    skbuff *fragment;
    list_node *next;
    FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, fragment, next,
                              skbuff, frag_list) {
        TEST_ASSERT(count < 8);
        remove_list_node(&fragment->frag_list);
        fragments[count++] = fragment;
    }
    TEST_ASSERT(count >= 2);

    skbuff *reassembled = NULL;
    for (uint32_t i = count; i > 0; --i) {
        TEST_ASSERT(ipv6_has_frag(fragments[i - 1]));
        skbuff *result = ipv6_defrag(fragments[i - 1]);
        if (result)
            reassembled = result;
        PUT_REF(fragments[i - 1]);
    }
    skbuff *result = ipv6_defrag(skb);
    if (result)
        reassembled = result;
    PUT_REF(skb);

    TEST_ASSERT(reassembled);
    TEST_ASSERT(reassembled->flag.is_defrag);
    TEST_ASSERT(!ipv6_has_frag(reassembled));
    TEST_ASSERT(reassembled->protocol == IPPROTO_UDP);
    TEST_ASSERT(skb_data_len(reassembled) == IPV6_HDR_LEN + 4000);
    uint8_t data[64];
    TEST_ASSERT(skb_copy_bits(reassembled, IPV6_HDR_LEN, data, sizeof(data)));
    for (uint32_t i = 0; i < sizeof(data); ++i)
        TEST_ASSERT(data[i] == (uint8_t)(i * 17u + 3u));
    PUT_REF(reassembled);

    skbuff *pending = make_ipv6_packet(2000, IPPROTO_UDP, 512);
    TEST_ASSERT(pending);
    route_info *pending_route = calloc(1, sizeof(*pending_route));
    TEST_ASSERT(pending_route);
    INIT_REF(pending_route, NULL);
    pending_route->if_info = &iface;
    pending->route = pending_route;
    TEST_ASSERT(ipv6_frag(pending));
    skbuff *queued = (skbuff *)((uint8_t *)pending->frag_list.next -
                                offsetof(skbuff, frag_list));
    remove_list_node(&queued->frag_list);
    TEST_ASSERT(ipv6_defrag(queued) == NULL);
    PUT_REF(queued);
    while (pending->frag_list.next) {
        skbuff *rest = (skbuff *)((uint8_t *)pending->frag_list.next -
                                  offsetof(skbuff, frag_list));
        remove_list_node(&rest->frag_list);
        PUT_REF(rest);
    }
    PUT_REF(pending);
    task timer = {
        .task_type = TASK_TYPE_TIMER,
        .parent_thread = allocation_worker.master,
    };
    current_time_ms += IPQ6_TIMEOUT + 1;
    ipq6_timer(&timer);
    TEST_ASSERT(hash_is_empty(allocation_worker.stack.ipq6_hash));
    unregister_task(&timer);

    hash_destroy(allocation_worker.stack.ipq6_hash);
    set_current_worker(NULL);
    destroy_thread(allocation_worker.master);
    return 0;
}

static int test_tcp_unit_defaults_and_boundaries(void)
{
    Socket *socket = create_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(socket && socket->pcb);
    tcp_pcb *pcb = socket->pcb;
    TEST_ASSERT(pcb->state == TCP_STATE_CLOSED);
    TEST_ASSERT(pcb->retransmit_timeout == tcp_metrics_default_rto());
    TEST_ASSERT(pcb->keepalive_timeout == TCP_KEEPALIVE_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(pcb->persist_backoff == TCP_PERSIST_BACKOFF_MS_DEFAULT);
    TEST_ASSERT(pcb->timewait_timeout == TCP_TIMEWAIT_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(pcb->ack_timeout == TCP_DELACK_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(pcb->connect_timeout == TCP_CONNECT_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(SEQ_LT(UINT32_MAX, 0) && SEQ_GT(0, UINT32_MAX));
    TEST_ASSERT(SEQ_LEQ(7, 7) && SEQ_GEQ(7, 7));

    pcb->rcv_wnd = 256u * 1024u;
    pcb->rcv_wnd_scale = TCP_RCV_WND_SCALE_DEFAULT;
    pcb->snd_wnd_scale = TCP_RCV_WND_SCALE_DEFAULT;
    TEST_ASSERT(tcp_should_send_window_scale(pcb, TCP_FLAG_SYN));
    TEST_ASSERT(!tcp_should_send_window_scale(
        pcb, TCP_FLAG_SYN | TCP_FLAG_ACK));
    pcb->tcp_flag.wnd_scale_sent = 1;
    TEST_ASSERT(!tcp_window_scale_negotiated(pcb));
    TEST_ASSERT(tcp_encode_window(pcb, TCP_FLAG_ACK) == 65535u);
    TEST_ASSERT(tcp_decode_window(pcb, 4096u, TCP_FLAG_ACK) == 4096u);

    pcb->tcp_flag.peer_wnd_scale_ok = 1;
    TEST_ASSERT(tcp_should_send_window_scale(
        pcb, TCP_FLAG_SYN | TCP_FLAG_ACK));
    TEST_ASSERT(tcp_window_scale_negotiated(pcb));
    TEST_ASSERT(tcp_encode_window(pcb, TCP_FLAG_SYN) == 65535u);
    TEST_ASSERT(tcp_encode_window(pcb, TCP_FLAG_ACK) == 4096u);
    TEST_ASSERT(tcp_decode_window(pcb, 4096u, TCP_FLAG_SYN) == 4096u);
    TEST_ASSERT(tcp_decode_window(pcb, 4096u, TCP_FLAG_ACK) == 256u * 1024u);

    pcb->snd_mss = 100;
    tcp_congestion_init(pcb);
    TEST_ASSERT(pcb->snd_cwnd == 1000 && pcb->ca_state == NET_TCP_CA_OPEN);
    uint32_t initial_cwnd = pcb->snd_cwnd;
    TEST_ASSERT(!tcp_congestion_on_ack(pcb, 100, true));
    TEST_ASSERT(pcb->snd_cwnd >= initial_cwnd);
    pcb->snd_nxt = 5000;
    TEST_ASSERT(tcp_congestion_on_duplicate_ack(pcb, 3));
    TEST_ASSERT(pcb->ca_state == NET_TCP_CA_RECOVERY);
    tcp_congestion_on_timeout(pcb);
    TEST_ASSERT(pcb->ca_state == NET_TCP_CA_LOSS && pcb->snd_cwnd == 100);
    TEST_ASSERT(tcp_metrics_backoff(TCP_RETRANSMIT_TIMEOUT_MS_MAX) ==
                TCP_RETRANSMIT_TIMEOUT_MS_MAX);
    TEST_ASSERT(tcp_protocol_ops.release(socket, NULL) == 0);
    return 0;
}

static int test_udp_unit_defaults(void)
{
    Socket *socket = create_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(socket && !socket->pcb);
    TEST_ASSERT(socket->send_queue.element_number == 0);
    TEST_ASSERT((udp_protocol_ops.poll(socket) & EPOLLOUT) != 0);
    socket->flag.close_send = 1;
    TEST_ASSERT((udp_protocol_ops.poll(socket) & EPOLLOUT) == 0);
    TEST_ASSERT(udp_protocol_ops.release(socket, NULL) == 0);
    return 0;
}

static int test_bind_ephemeral_ports(void)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    uint16_t tcp_ports[2] = {0};
    uint16_t udp_ports[2] = {0};
    int tcp_fds[2] = {-1, -1};
    int udp_fds[2] = {-1, -1};

    for (uint32_t i = 0; i < 2; ++i) {
        int fd = net_socket(AF_INET, SOCK_STREAM, 0);
        TEST_ASSERT(fd >= 0);
        tcp_fds[i] = fd;
        TEST_ASSERT(net_bind(fd, (struct sockaddr *)&address,
                             sizeof(address)) == 0);
        struct sockaddr_in bound = {0};
        socklen_t bound_len = sizeof(bound);
        TEST_ASSERT(net_getsockname(fd, (struct sockaddr *)&bound,
                                    &bound_len) == 0);
        TEST_ASSERT(bound_len == sizeof(bound));
        TEST_ASSERT(bound.sin_family == AF_INET);
        TEST_ASSERT(ntohs(bound.sin_port) >= 1024);
        tcp_ports[i] = bound.sin_port;
        TEST_ASSERT(net_listen(fd, 1) == 0);
    }
    TEST_ASSERT(tcp_ports[0] != tcp_ports[1]);
    TEST_ASSERT(net_close(tcp_fds[0]) == 0);
    TEST_ASSERT(net_close(tcp_fds[1]) == 0);

    for (uint32_t i = 0; i < 2; ++i) {
        int fd = net_socket(AF_INET, SOCK_DGRAM, 0);
        TEST_ASSERT(fd >= 0);
        udp_fds[i] = fd;
        TEST_ASSERT(net_bind(fd, (struct sockaddr *)&address,
                             sizeof(address)) == 0);
        struct sockaddr_in bound = {0};
        socklen_t bound_len = sizeof(bound);
        TEST_ASSERT(net_getsockname(fd, (struct sockaddr *)&bound,
                                    &bound_len) == 0);
        TEST_ASSERT(bound_len == sizeof(bound));
        TEST_ASSERT(bound.sin_family == AF_INET);
        TEST_ASSERT(ntohs(bound.sin_port) >= 1024);
        udp_ports[i] = bound.sin_port;
    }
    TEST_ASSERT(udp_ports[0] != udp_ports[1]);
    TEST_ASSERT(net_close(udp_fds[0]) == 0);
    TEST_ASSERT(net_close(udp_fds[1]) == 0);

    struct sockaddr_in6 address6 = {
        .sin6_family = AF_INET6,
        .sin6_port = 0,
        .sin6_addr = IN6ADDR_ANY_INIT,
    };
    int tcp6 = net_socket(AF_INET6, SOCK_STREAM, 0);
    TEST_ASSERT(tcp6 >= 0);
    TEST_ASSERT(net_bind(tcp6, (struct sockaddr *)&address6,
                         sizeof(address6)) == 0);
    struct sockaddr_in6 bound6 = {0};
    socklen_t bound6_len = sizeof(bound6);
    TEST_ASSERT(net_getsockname(tcp6, (struct sockaddr *)&bound6,
                                &bound6_len) == 0);
    TEST_ASSERT(bound6_len == sizeof(bound6));
    TEST_ASSERT(bound6.sin6_family == AF_INET6);
    TEST_ASSERT(ntohs(bound6.sin6_port) >= 1024);
    TEST_ASSERT(net_listen(tcp6, 1) == 0);
    TEST_ASSERT(net_close(tcp6) == 0);

    int udp6 = net_socket(AF_INET6, SOCK_DGRAM, 0);
    TEST_ASSERT(udp6 >= 0);
    TEST_ASSERT(net_bind(udp6, (struct sockaddr *)&address6,
                         sizeof(address6)) == 0);
    memset(&bound6, 0, sizeof(bound6));
    bound6_len = sizeof(bound6);
    TEST_ASSERT(net_getsockname(udp6, (struct sockaddr *)&bound6,
                                &bound6_len) == 0);
    TEST_ASSERT(bound6_len == sizeof(bound6));
    TEST_ASSERT(bound6.sin6_family == AF_INET6);
    TEST_ASSERT(ntohs(bound6.sin6_port) >= 1024);
    TEST_ASSERT(net_close(udp6) == 0);
    return 0;
}

static int test_tcp_loopback(void)
{
    const char request[] = "netfast tcp loopback";
    const char reply[] = "tcp reply";
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(32101),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int listener = net_socket(AF_INET, SOCK_STREAM, 0);
    int client = -1;
    int accepted = -1;
    TEST_ASSERT(listener >= 0);
    int reuse = 1;
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse,
                               sizeof(reuse)) == 0);
    TEST_ASSERT(net_bind(listener, (struct sockaddr *)&address,
                         sizeof(address)) == 0);
    TEST_ASSERT(net_listen(listener, 4) == 0);

    client = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client >= 0);
    TEST_ASSERT(net_connect(client, (struct sockaddr *)&address,
                            sizeof(address)) == 0);
    accepted = net_accept(listener, NULL, NULL);
    TEST_ASSERT(accepted >= 0);

    fd_entry *client_entry = hold_fd_entry(client);
    fd_entry *accepted_entry = hold_fd_entry(accepted);
    TEST_ASSERT(client_entry && accepted_entry);
    tcp_pcb *client_pcb = ((Socket *)client_entry->value)->pcb;
    tcp_pcb *accepted_pcb = ((Socket *)accepted_entry->value)->pcb;
    TEST_ASSERT(tcp_window_scale_negotiated(client_pcb));
    TEST_ASSERT(tcp_window_scale_negotiated(accepted_pcb));
    TEST_ASSERT(client_pcb->snd_wnd_scale == TCP_RCV_WND_SCALE_DEFAULT);
    TEST_ASSERT(accepted_pcb->snd_wnd_scale == TCP_RCV_WND_SCALE_DEFAULT);
    PUT_REF(accepted_entry);
    PUT_REF(client_entry);

    TEST_ASSERT(net_fcntl(accepted, F_SETFL, O_NONBLOCK) == 0);
    TEST_ASSERT(net_write(client, request, sizeof(request)) ==
                (int)sizeof(request));
    char buffer[64] = {0};
    TEST_ASSERT(wait_for_read(accepted, buffer, sizeof(buffer)) ==
                (int)sizeof(request));
    TEST_ASSERT(memcmp(buffer, request, sizeof(request)) == 0);

    TEST_ASSERT(net_fcntl(client, F_SETFL, O_NONBLOCK) == 0);
    TEST_ASSERT(net_write(accepted, reply, sizeof(reply)) == (int)sizeof(reply));
    memset(buffer, 0, sizeof(buffer));
    TEST_ASSERT(wait_for_read(client, buffer, sizeof(buffer)) == (int)sizeof(reply));
    TEST_ASSERT(memcmp(buffer, reply, sizeof(reply)) == 0);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(client) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

static int test_tcp_linger(void)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(32105),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int listener = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listener >= 0);
    int reuse = 1;
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse,
                               sizeof(reuse)) == 0);
    TEST_ASSERT(net_bind(listener, (struct sockaddr*)&address,
                         sizeof(address)) == 0);
    TEST_ASSERT(net_listen(listener, 2) == 0);

    int client = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client >= 0);
    TEST_ASSERT(net_connect(client, (struct sockaddr*)&address,
                            sizeof(address)) == 0);
    int accepted = net_accept(listener, NULL, NULL);
    TEST_ASSERT(accepted >= 0);

    struct linger linger = {.l_onoff = 1, .l_linger = 1};
    TEST_ASSERT(net_setsockopt(client, SOL_SOCKET, SO_LINGER, &linger,
                               sizeof(linger)) == 0);
    TEST_ASSERT(net_close(client) == 0); /* FIN ACK or one-second timeout */
    TEST_ASSERT(net_close(accepted) == 0);

    client = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client >= 0);
    TEST_ASSERT(net_connect(client, (struct sockaddr*)&address,
                            sizeof(address)) == 0);
    accepted = net_accept(listener, NULL, NULL);
    TEST_ASSERT(accepted >= 0);

    linger.l_linger = 0;
    TEST_ASSERT(net_setsockopt(client, SOL_SOCKET, SO_LINGER, &linger,
                               sizeof(linger)) == 0);
    TEST_ASSERT(net_close(client) == 0); /* abortive RST close */
    char byte;
    TEST_ASSERT(net_read(accepted, &byte, sizeof(byte)) == -1);
    TEST_ASSERT(errno == ECONNRESET);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

static int test_udp_loopback(void)
{
    const char payload[] = "netfast udp loopback";
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(32102),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int receiver = net_socket(AF_INET, SOCK_DGRAM, 0);
    int sender = -1;
    TEST_ASSERT(receiver >= 0);
    TEST_ASSERT(net_bind(receiver, (struct sockaddr *)&address,
                         sizeof(address)) == 0);
    sender = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sender >= 0);
    TEST_ASSERT(net_sendto(sender, payload, sizeof(payload), 0,
                           (struct sockaddr *)&address, sizeof(address)) ==
                (int)sizeof(payload));
    char buffer[64] = {0};
    struct sockaddr_in peer = {0};
    socklen_t peer_len = sizeof(peer);
    TEST_ASSERT(wait_for_recvfrom(receiver, buffer, sizeof(buffer), &peer,
                                  &peer_len) == (int)sizeof(payload));
    TEST_ASSERT(memcmp(buffer, payload, sizeof(payload)) == 0);
    TEST_ASSERT(peer.sin_family == AF_INET && peer.sin_port != 0);
    TEST_ASSERT(net_close(sender) == 0);
    TEST_ASSERT(net_close(receiver) == 0);
    return 0;
}

static int test_request_error_boundary(void)
{
    struct sockaddr_in unreachable = {
        .sin_family = AF_INET,
        .sin_port = htons(32103),
        .sin_addr.s_addr = htonl(0xc0000201u), /* 192.0.2.1 */
    };
    int socket_fd = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(socket_fd >= 0);

    errno = 0;
    TEST_ASSERT(net_connect(socket_fd, (struct sockaddr *)&unreachable,
                            sizeof(unreachable)) == -1);
    TEST_ASSERT(errno == EHOSTUNREACH);

    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);
    net_async_req *request = net_async_req_create(
        socket_fd, NET_ASYNC_CONNECT,
        (struct sockaddr *)&unreachable, (socklen_t)sizeof(unreachable));
    TEST_ASSERT(request);
    TEST_ASSERT(net_async_submit(cq_fd, request) == 0);

    net_async_req *completed = NULL;
    TEST_ASSERT(net_async_wait(cq_fd, &completed, 1, 1, 2000) == 1);
    TEST_ASSERT(completed == request);
    TEST_ASSERT(completed->ret == -EHOSTUNREACH);
    TEST_ASSERT(net_async_req_result(completed) == -EHOSTUNREACH);
    net_async_req_destroy(completed);

    TEST_ASSERT(net_async_close(cq_fd) == 0);
    TEST_ASSERT(net_close(socket_fd) == 0);
    return 0;
}

typedef struct async_wait_test_arg {
    int cq_fd;
    uint32_t min;
    uint32_t max;
    net_async_req *completed[8];
    int ret;
    int saved_errno;
} async_wait_test_arg;

static atomic_uint async_wait_test_started;

static void *run_async_wait_test(void *opaque)
{
    async_wait_test_arg *arg = opaque;
    atomic_fetch_add_explicit(&async_wait_test_started, 1,
                              memory_order_release);
    arg->ret = net_async_wait(arg->cq_fd, arg->completed,
                              arg->min, arg->max, 2000);
    arg->saved_errno = errno;
    return NULL;
}

static int test_async_multi_wait(void)
{
    enum { REQUESTS = 12, WAITERS = 4, ROUNDS = 32 };
    static const uint32_t batch[WAITERS] = {1, 2, 4, 5};
    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);

    for (uint32_t round = 0; round < ROUNDS; ++round) {
        net_async_req *requests[REQUESTS];
        for (uint32_t i = 0; i < REQUESTS; ++i) {
            requests[i] = net_async_req_create(-1, NET_ASYNC_SOCKET,
                                                AF_INET, SOCK_DGRAM, 0);
            TEST_ASSERT(requests[i]);
        }

        async_wait_test_arg args[WAITERS] = {0};
        pthread_t threads[WAITERS];
        atomic_store_explicit(&async_wait_test_started, 0,
                              memory_order_relaxed);
        for (uint32_t i = 0; i < WAITERS; ++i) {
            args[i].cq_fd = cq_fd;
            args[i].min = batch[i];
            args[i].max = batch[i];
            TEST_ASSERT(pthread_create(&threads[i], NULL, run_async_wait_test,
                                       &args[i]) == 0);
        }

        uint64_t deadline = read_now_ms() + 1000;
        while (atomic_load_explicit(&async_wait_test_started,
                                    memory_order_acquire) != WAITERS &&
               read_now_ms() < deadline) {
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
        TEST_ASSERT(atomic_load_explicit(&async_wait_test_started,
                                        memory_order_acquire) == WAITERS);
        struct timespec arm_delay = {.tv_nsec = 2000000};
        nanosleep(&arm_delay, NULL);

        TEST_ASSERT(net_async_submit_batch(cq_fd, requests, REQUESTS) ==
                    REQUESTS);
        for (uint32_t i = 0; i < WAITERS; ++i) {
            TEST_ASSERT(pthread_join(threads[i], NULL) == 0);
            TEST_ASSERT(args[i].ret == (int)batch[i]);
            for (uint32_t j = 0; j < batch[i]; ++j) {
                net_async_req* request = args[i].completed[j];
                TEST_ASSERT(request->async_fd == -1);
                TEST_ASSERT(request->type == (req_type)NET_ASYNC_SOCKET);
                TEST_ASSERT(request->ret >= 0);
                TEST_ASSERT(net_async_req_result(request) == request->ret);
                TEST_ASSERT(net_close(request->ret) == 0);
                net_async_req_destroy(args[i].completed[j]);
            }
        }
    }
    TEST_ASSERT(net_async_close(cq_fd) == 0);
    return 0;
}

static int test_async_multi_wait_close(void)
{
    enum { WAITERS = 4 };
    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);

    async_wait_test_arg args[WAITERS] = {0};
    pthread_t threads[WAITERS];
    atomic_store_explicit(&async_wait_test_started, 0, memory_order_relaxed);
    for (uint32_t i = 0; i < WAITERS; ++i) {
        args[i].cq_fd = cq_fd;
        args[i].min = 1;
        args[i].max = 1;
        TEST_ASSERT(pthread_create(&threads[i], NULL, run_async_wait_test,
                                   &args[i]) == 0);
    }

    uint64_t deadline = read_now_ms() + 1000;
    while (atomic_load_explicit(&async_wait_test_started,
                                memory_order_acquire) != WAITERS &&
           read_now_ms() < deadline) {
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    TEST_ASSERT(atomic_load_explicit(&async_wait_test_started,
                                    memory_order_acquire) == WAITERS);
    struct timespec arm_delay = {.tv_nsec = 10000000};
    nanosleep(&arm_delay, NULL);

    TEST_ASSERT(net_async_close(cq_fd) == 0);
    for (uint32_t i = 0; i < WAITERS; ++i) {
        TEST_ASSERT(pthread_join(threads[i], NULL) == 0);
        TEST_ASSERT(args[i].ret == -1 && args[i].saved_errno == EBADF);
    }
    return 0;
}

#ifndef TEST_EPOLL
static int test_epoll_disabled(void)
{
    errno = 0;
    TEST_ASSERT(net_epoll_create() == -1);
    TEST_ASSERT(errno == ENOTSUP);
    return 0;
}
#else
static int test_epoll_enabled(void)
{
    int epfd = net_epoll_create();
    TEST_ASSERT(epfd >= 0);
    int sockfd = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sockfd >= 0);
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLOUT,
        .data.fd = sockfd,
    };
    TEST_ASSERT(net_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &event) == 0);
    event.events = EPOLLIN;
    TEST_ASSERT(net_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &event) == 0);
    TEST_ASSERT(net_epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd, NULL) == 0);
    TEST_ASSERT(net_close(sockfd) == 0);

    sockfd = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sockfd >= 0);
    event.data.fd = sockfd;
    TEST_ASSERT(net_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &event) == 0);
    /* Closing a registered socket must remove its intrusive hash node. */
    TEST_ASSERT(net_close(sockfd) == 0);
    TEST_ASSERT(net_close(epfd) == 0);
    return 0;
}
#endif

int main(void)
{
    TEST_RUN(test_tcp_unit_defaults_and_boundaries);
    TEST_RUN(test_udp_unit_defaults);
#ifndef TEST_EPOLL
    TEST_RUN(test_epoll_disabled);
#endif
    TEST_ASSERT(setup_loopback_runtime() == 0);
#ifdef TEST_EPOLL
    TEST_RUN(test_epoll_enabled);
#endif
    TEST_RUN(test_skb_multisegment_clone_copy);
    TEST_RUN(test_ipv6_extension_fragmentation);
    TEST_RUN(test_bind_ephemeral_ports);
    TEST_RUN(test_tcp_loopback);
    TEST_RUN(test_tcp_linger);
    TEST_RUN(test_udp_loopback);
    TEST_RUN(test_request_error_boundary);
    TEST_RUN(test_async_multi_wait);
    TEST_RUN(test_async_multi_wait_close);

    /* Leave time for queued FIN/ACK packets to complete before process exit. */
    sleep(2);
    atomic_store_explicit(&worker_running, false, memory_order_release);
    TEST_ASSERT(pthread_join(worker_thread, NULL) == 0);
    puts("All TCP/UDP protocol tests passed.");
    return 0;
}
