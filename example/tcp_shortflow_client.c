/* Nonblocking epoll client for the many-short-TCP-flow benchmark. */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS 2048

typedef enum client_state {
    CLIENT_CONNECTING,
    CLIENT_WRITING,
    CLIENT_READING,
} client_state;

typedef struct client_conn {
    int fd;
    client_state state;
    size_t sent;
    size_t received;
    size_t payload_size;
    struct timespec started;
    unsigned char data[];
} client_conn;

typedef struct benchmark {
    int epfd;
    struct sockaddr_in destination;
    struct sockaddr_in source;
    bool bind_source;
    uint64_t total;
    uint64_t started;
    uint64_t completed;
    uint64_t failed;
    uint32_t concurrency;
    uint32_t active;
    size_t payload_size;
    double *latencies_ms;
    struct timespec begin;
} benchmark;

static double seconds_between(const struct timespec *start,
                              const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static int compare_double(const void *left, const void *right)
{
    double a = *(const double *)left;
    double b = *(const double *)right;
    return (a > b) - (a < b);
}

static int modify_events(benchmark *bench, client_conn *conn, uint32_t events)
{
    struct epoll_event event = {.events = events, .data.ptr = conn};
    return epoll_ctl(bench->epfd, EPOLL_CTL_MOD, conn->fd, &event);
}

static int finish_connection(benchmark *bench, client_conn *conn, bool success)
{
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    (void)epoll_ctl(bench->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
    bench->active--;
    if (success) {
        bench->latencies_ms[bench->completed] =
            seconds_between(&conn->started, &end) * 1000.0;
        bench->completed++;
    } else {
        bench->failed++;
    }
    free(conn);
    return success ? 0 : -1;
}

static int start_connection(benchmark *bench)
{
    client_conn *conn = calloc(1, sizeof(*conn) + bench->payload_size);
    if (!conn)
        return -1;
    for (size_t i = 0; i < bench->payload_size; ++i)
        conn->data[i] = (unsigned char)(i % 251U);
    conn->payload_size = bench->payload_size;
    conn->state = CLIENT_CONNECTING;
    conn->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (conn->fd < 0)
        goto fail;
    if (bench->bind_source &&
        bind(conn->fd, (const struct sockaddr *)&bench->source,
             sizeof(bench->source)) != 0)
        goto fail_fd;
    clock_gettime(CLOCK_MONOTONIC, &conn->started);
    int ret = connect(conn->fd, (const struct sockaddr *)&bench->destination,
                      sizeof(bench->destination));
    if (ret != 0 && errno != EINPROGRESS)
        goto fail_fd;
    if (ret == 0)
        conn->state = CLIENT_WRITING;
    struct epoll_event event = {
        .events = EPOLLOUT | EPOLLRDHUP,
        .data.ptr = conn,
    };
    if (epoll_ctl(bench->epfd, EPOLL_CTL_ADD, conn->fd, &event) != 0)
        goto fail_fd;
    bench->started++;
    bench->active++;
    return 0;

fail_fd:
    close(conn->fd);
fail:
    free(conn);
    return -1;
}

static int check_pattern(const client_conn *conn)
{
    for (size_t i = 0; i < conn->payload_size; ++i) {
        if (conn->data[i] != (unsigned char)(i % 251U))
            return -1;
    }
    return 0;
}

static int process_connection(benchmark *bench, client_conn *conn,
                              uint32_t events)
{
    if (conn->state == CLIENT_CONNECTING && (events & EPOLLOUT)) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
            error != 0) {
            errno = error ? error : errno;
            return finish_connection(bench, conn, false);
        }
        conn->state = CLIENT_WRITING;
    }
    if (conn->state == CLIENT_WRITING && (events & EPOLLOUT)) {
        while (conn->sent < conn->payload_size) {
            ssize_t n = send(conn->fd, conn->data + conn->sent,
                             conn->payload_size - conn->sent, MSG_NOSIGNAL);
            if (n > 0) {
                conn->sent += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && errno == EAGAIN)
                return 0;
            return finish_connection(bench, conn, false);
        }
        memset(conn->data, 0, conn->payload_size);
        conn->state = CLIENT_READING;
        if (modify_events(bench, conn, EPOLLIN | EPOLLRDHUP) != 0)
            return finish_connection(bench, conn, false);
    }
    if (conn->state == CLIENT_READING && (events & EPOLLIN)) {
        while (conn->received < conn->payload_size) {
            ssize_t n = recv(conn->fd, conn->data + conn->received,
                             conn->payload_size - conn->received, 0);
            if (n > 0) {
                conn->received += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && errno == EAGAIN)
                return 0;
            return finish_connection(bench, conn, false);
        }
        return finish_connection(bench, conn, check_pattern(conn) == 0);
    }
    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
        return finish_connection(bench, conn, false);
    return 0;
}

static double percentile(const double *values, uint64_t count, double p)
{
    if (count == 0)
        return 0.0;
    uint64_t index = (uint64_t)ceil(p * (double)count) - 1;
    if (index >= count)
        index = count - 1;
    return values[index];
}

int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "Usage: %s HOST PORT SOURCE_IP CONNECTIONS "
                "CONCURRENCY PAYLOAD_BYTES\n", argv[0]);
        return 2;
    }
    benchmark bench = {0};
    char *end = NULL;
    unsigned long port = strtoul(argv[2], &end, 10);
    if (!end || *end || port == 0 || port > 65535)
        return 2;
    bench.destination.sin_family = AF_INET;
    bench.destination.sin_port = htons((uint16_t)port);
    bench.source.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &bench.destination.sin_addr) != 1 ||
        inet_pton(AF_INET, argv[3], &bench.source.sin_addr) != 1)
        return 2;
    bench.bind_source = strcmp(argv[3], "0.0.0.0") != 0;
    bench.total = strtoull(argv[4], &end, 10);
    if (!end || *end || bench.total == 0)
        return 2;
    unsigned long concurrency = strtoul(argv[5], &end, 10);
    if (!end || *end || concurrency == 0 || concurrency > 100000)
        return 2;
    bench.concurrency = (uint32_t)concurrency;
    bench.payload_size = (size_t)strtoull(argv[6], &end, 10);
    if (!end || *end || bench.payload_size == 0 ||
        bench.payload_size > 1024 * 1024)
        return 2;
    bench.latencies_ms = calloc((size_t)bench.total, sizeof(double));
    bench.epfd = epoll_create1(EPOLL_CLOEXEC);
    if (!bench.latencies_ms || bench.epfd < 0) {
        perror("initialize client");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &bench.begin);
    while (bench.active < bench.concurrency && bench.started < bench.total) {
        if (start_connection(&bench) != 0) {
            perror("start connection");
            return 1;
        }
    }
    struct epoll_event events[MAX_EVENTS];
    while (bench.completed + bench.failed < bench.total) {
        int count = epoll_wait(bench.epfd, events, MAX_EVENTS, 30000);
        if (count <= 0) {
            if (count < 0 && errno == EINTR)
                continue;
            fprintf(stderr, "client epoll wait failed/timed out: %s\n",
                    count < 0 ? strerror(errno) : "timeout");
            break;
        }
        for (int i = 0; i < count; ++i)
            (void)process_connection(&bench, events[i].data.ptr,
                                     events[i].events);
        while (bench.active < bench.concurrency && bench.started < bench.total) {
            if (start_connection(&bench) != 0) {
                perror("start connection");
                bench.failed += bench.total - bench.started;
                bench.started = bench.total;
                break;
            }
        }
    }
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = seconds_between(&bench.begin, &end_time);
    qsort(bench.latencies_ms, (size_t)bench.completed, sizeof(double),
          compare_double);
    double traffic_mib = (double)bench.completed * bench.payload_size * 2.0 /
                         (1024.0 * 1024.0);
    printf("short-flow result: started=%llu completed=%llu failed=%llu "
           "elapsed=%.6f connections/s=%.2f traffic=%.2f MiB/s\n",
           (unsigned long long)bench.started,
           (unsigned long long)bench.completed,
           (unsigned long long)bench.failed, elapsed,
           elapsed > 0.0 ? (double)bench.completed / elapsed : 0.0,
           elapsed > 0.0 ? traffic_mib / elapsed : 0.0);
    printf("latency ms: p50=%.3f p95=%.3f p99=%.3f max=%.3f\n",
           percentile(bench.latencies_ms, bench.completed, 0.50),
           percentile(bench.latencies_ms, bench.completed, 0.95),
           percentile(bench.latencies_ms, bench.completed, 0.99),
           percentile(bench.latencies_ms, bench.completed, 1.00));
    close(bench.epfd);
    free(bench.latencies_ms);
    return bench.completed == bench.total && bench.failed == 0 ? 0 : 1;
}
