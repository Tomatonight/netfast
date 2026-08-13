/* NetFast async server for the many-short-TCP-flow benchmark. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "netfast.h"
#include "req.h"

#ifndef ACCEPT_DEPTH
#define ACCEPT_DEPTH 64U
#endif
#define CONNECTION_BUCKETS 4096U
#define COMPLETION_BATCH 1024U

typedef struct connection {
    struct connection *request_next;
    net_async_req *pending_request;
    int fd;
    bool failed;
    struct linger linger;
    size_t received;
    size_t sent;
    size_t payload_size;
    unsigned char data[];
} connection;

typedef struct server {
    int cq_fd;
    int listen_fd;
    uint64_t total;
    uint64_t accepted;
    uint64_t completed;
    uint64_t failed;
    uint32_t accept_pending;
    size_t payload_size;
    struct timespec started;
    bool timer_started;
    connection *requests[CONNECTION_BUCKETS];
} server;

static double seconds_between(const struct timespec *start,
                              const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static uint32_t request_bucket(const net_async_req *request)
{
    uintptr_t value = (uintptr_t)request;
    return (uint32_t)((value >> 4) * UINT64_C(11400714819323198485)) &
           (CONNECTION_BUCKETS - 1U);
}

static void request_add(server *state, connection *conn,
                        net_async_req *request)
{
    uint32_t bucket = request_bucket(request);
    conn->pending_request = request;
    conn->request_next = state->requests[bucket];
    state->requests[bucket] = conn;
}

static connection *request_remove(server *state, net_async_req *request)
{
    uint32_t bucket = request_bucket(request);
    connection **link = &state->requests[bucket];
    while (*link) {
        connection *conn = *link;
        if (conn->pending_request == request) {
            *link = conn->request_next;
            conn->request_next = NULL;
            conn->pending_request = NULL;
            return conn;
        }
        link = &conn->request_next;
    }
    return NULL;
}

static void connection_remove(connection *conn)
{
    free(conn);
}

static bool valid_pattern(const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (data[i] != (unsigned char)(i % 251U))
            return false;
    }
    return true;
}

static int submit_request(server *state, net_async_req *request)
{
    if (!request)
        return -1;
    if (net_async_submit(state->cq_fd, request) == 0)
        return 0;
    int saved_errno = errno;
    net_async_req_destroy(request);
    errno = saved_errno;
    return -1;
}

static int submit_connection_request(server *state, connection *conn,
                                     net_async_req *request)
{
    if (!request)
        return -1;
    if (conn->pending_request) {
        net_async_req_destroy(request);
        errno = EALREADY;
        return -1;
    }
    if (net_async_submit(state->cq_fd, request) != 0) {
        int saved_errno = errno;
        net_async_req_destroy(request);
        errno = saved_errno;
        return -1;
    }
    /* async_fd is informational and can be reused after close starts.  The
     * request object itself is the stable identity of this operation. */
    request_add(state, conn, request);
    return 0;
}

static int submit_accept(server *state)
{
    net_async_req *request = net_async_req_create(
        state->listen_fd, NET_ASYNC_ACCEPT, NULL, NULL);
    if (submit_request(state, request) != 0)
        return -1;
    state->accept_pending++;
    return 0;
}

static int fill_accept_pipeline(server *state)
{
    while (state->accepted + state->accept_pending < state->total &&
           state->accept_pending < ACCEPT_DEPTH) {
        if (submit_accept(state) != 0)
            return -1;
    }
    return 0;
}

static int submit_read(server *state, connection *conn)
{
    net_async_req *request = net_async_req_create(
        conn->fd, NET_ASYNC_READ, conn->data + conn->received,
        (uint32_t)(conn->payload_size - conn->received));
    return submit_connection_request(state, conn, request);
}

static int submit_linger(server *state, connection *conn)
{
    net_async_req *request = net_async_req_create(
        conn->fd, NET_ASYNC_SETSOCKOPT, SOL_SOCKET, SO_LINGER,
        &conn->linger, (socklen_t)sizeof(conn->linger));
    return submit_connection_request(state, conn, request);
}

static int submit_write(server *state, connection *conn)
{
    net_async_req *request = net_async_req_create(
        conn->fd, NET_ASYNC_WRITE, conn->data + conn->sent,
        (uint32_t)(conn->payload_size - conn->sent));
    return submit_connection_request(state, conn, request);
}

static int submit_close(server *state, connection *conn)
{
    return submit_connection_request(
        state, conn, net_async_req_create(conn->fd, NET_ASYNC_CLOSE));
}

static int fail_connection(server *state, connection *conn, int result)
{
    if (!conn->failed) {
        conn->failed = true;
        fprintf(stderr, "connection fd=%d failed: %s\n", conn->fd,
                strerror(result < 0 ? -result : EIO));
    }
    return submit_close(state, conn);
}

static int complete_accept(server *state, int result)
{
    state->accept_pending--;
    if (result < 0) {
        errno = -result;
        return -1;
    }
    connection *conn = calloc(1, sizeof(*conn) + state->payload_size);
    if (!conn) {
        net_async_req *close_request =
            net_async_req_create(result, NET_ASYNC_CLOSE);
        (void)submit_request(state, close_request);
        return -1;
    }
    conn->fd = result;
    conn->payload_size = state->payload_size;
    conn->linger.l_onoff = 1;
    conn->linger.l_linger = 1;
    if (!state->timer_started) {
        clock_gettime(CLOCK_MONOTONIC, &state->started);
        state->timer_started = true;
    }
    state->accepted++;
    if (submit_linger(state, conn) != 0 || fill_accept_pipeline(state) != 0)
        return -1;
    return 0;
}

static int complete_read(server *state, connection *conn, int result)
{
    if (result <= 0) {
        return fail_connection(state, conn,
                               result < 0 ? result : -ECONNRESET);
    }
    conn->received += (size_t)result;
    if (conn->received < conn->payload_size)
        return submit_read(state, conn);
    if (!valid_pattern(conn->data, conn->payload_size)) {
        errno = EBADMSG;
        return -1;
    }
    return submit_write(state, conn);
}

static int complete_write(server *state, connection *conn, int result)
{
    if (result <= 0) {
        return fail_connection(state, conn, result < 0 ? result : -EPIPE);
    }
    conn->sent += (size_t)result;
    return conn->sent < conn->payload_size
        ? submit_write(state, conn) : submit_close(state, conn);
}

static int complete_request(server *state, net_async_req *request)
{
    int type = request->type;
    int result = request->ret;

    if (type == REQ_ACCEPT) {
        net_async_req_destroy(request);
        return complete_accept(state, result);
    }
    connection *conn = request_remove(state, request);
    net_async_req_destroy(request);
    if (!conn) {
        errno = ENOENT;
        return -1;
    }
    switch (type) {
    case REQ_SETSOCKOPT:
        if (result < 0)
            return fail_connection(state, conn, result);
        return submit_read(state, conn);
    case REQ_READ:
        return complete_read(state, conn, result);
    case REQ_WRITE:
        return complete_write(state, conn, result);
    case REQ_CLOSE:
        if (result < 0) {
            errno = -result;
            return -1;
        }
        bool failed = conn->failed;
        connection_remove(conn);
        if (failed)
            state->failed++;
        else
            state->completed++;
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

static int setup_listener(server *state, const char *ip, uint16_t port)
{
    state->listen_fd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (state->listen_fd < 0)
        return -1;
    int reuse = 1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1 ||
        net_setsockopt(state->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                       sizeof(reuse)) != 0 ||
        net_bind(state->listen_fd, (const struct sockaddr *)&address,
                 sizeof(address)) != 0 ||
        net_listen(state->listen_fd, 4096) != 0)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s IP PORT CONNECTIONS PAYLOAD_BYTES\n",
                argv[0]);
        return 2;
    }
    char *end = NULL;
    unsigned long port = strtoul(argv[2], &end, 10);
    if (!end || *end || port == 0 || port > 65535)
        return 2;
    server state = {.cq_fd = -1, .listen_fd = -1};
    state.total = strtoull(argv[3], &end, 10);
    if (!end || *end || state.total == 0)
        return 2;
    state.payload_size = (size_t)strtoull(argv[4], &end, 10);
    if (!end || *end || state.payload_size == 0 ||
        state.payload_size > 1024 * 1024)
        return 2;

    if (setup_listener(&state, argv[1], (uint16_t)port) != 0) {
        perror("setup NetFast listener");
        return 1;
    }
    state.cq_fd = net_async_create();
    if (state.cq_fd < 0 || fill_accept_pipeline(&state) != 0) {
        perror("initialize NetFast async CQ");
        return 1;
    }
    printf("NetFast short-flow server %s:%lu, connections=%llu payload=%zu "
           "accept-depth=%u\n", argv[1], port,
           (unsigned long long)state.total, state.payload_size, ACCEPT_DEPTH);
    fflush(stdout);

    bool fatal = false;
    while (state.completed + state.failed < state.total) {
        net_async_req *completed[COMPLETION_BATCH];
        int count = net_async_wait(state.cq_fd, completed, 1,
                                   COMPLETION_BATCH, 30000);
        if (count <= 0) {
            fprintf(stderr, "NetFast completion wait %s: %s\n",
                    count < 0 ? "failed" : "timed out",
                    count < 0 ? strerror(errno) : "timeout");
            fatal = true;
            break;
        }
        for (int i = 0; i < count; ++i) {
            if (complete_request(&state, completed[i]) != 0) {
                fprintf(stderr, "NetFast request completion failed: %s\n",
                        strerror(errno));
                fatal = true;
                for (++i; i < count; ++i)
                    net_async_req_destroy(completed[i]);
                break;
            }
        }
        if (fatal)
            break;
    }
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = state.timer_started
        ? seconds_between(&state.started, &end_time) : 0.0;
    printf("NetFast server result: accepted=%llu completed=%llu failed=%llu "
           "elapsed=%.6f connections/s=%.2f\n",
           (unsigned long long)state.accepted,
           (unsigned long long)state.completed,
           (unsigned long long)state.failed, elapsed,
           elapsed > 0.0 ? (double)state.completed / elapsed : 0.0);
    fflush(stdout);
    /* close() may complete before the peer has consumed the final data/FIN.
     * Keep the userspace stack and XDP sockets alive for that tail traffic. */
    if (!fatal && state.completed == state.total)
        sleep(2);
    (void)net_async_close(state.cq_fd);
    return !fatal && state.completed == state.total ? 0 : 1;
}
