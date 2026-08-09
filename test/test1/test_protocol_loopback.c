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
                int request_errno = 0;
                int fd = net_async_req_result(args[i].completed[j],
                                              &request_errno);
                TEST_ASSERT(fd >= 0 && request_errno == 0);
                TEST_ASSERT(net_close(fd) == 0);
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

int main(void)
{
    TEST_RUN(test_tcp_unit_defaults_and_boundaries);
    TEST_RUN(test_udp_unit_defaults);
    TEST_ASSERT(setup_loopback_runtime() == 0);
    TEST_RUN(test_skb_multisegment_clone_copy);
    TEST_RUN(test_tcp_loopback);
    TEST_RUN(test_udp_loopback);
    TEST_RUN(test_async_multi_wait);
    TEST_RUN(test_async_multi_wait_close);

    /* Leave time for queued FIN/ACK packets to complete before process exit. */
    sleep(2);
    atomic_store_explicit(&worker_running, false, memory_order_release);
    TEST_ASSERT(pthread_join(worker_thread, NULL) == 0);
    puts("All TCP/UDP protocol tests passed.");
    return 0;
}
