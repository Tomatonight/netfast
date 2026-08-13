/* Linux epoll baseline for the many-short-TCP-flow benchmark. */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
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

#define MAX_EVENTS 1024

typedef struct connection {
    int fd;
    size_t received;
    size_t sent;
    size_t payload_size;
    unsigned char data[];
} connection;

static double seconds_between(const struct timespec *start,
                              const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static int update_events(int epfd, connection *conn, uint32_t events)
{
    struct epoll_event event = {.events = events, .data.ptr = conn};
    return epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &event);
}

static void close_connection(int epfd, connection *conn)
{
    (void)epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
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

static int create_listener(const char *ip, uint16_t port, const char *device)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    int reuse = 1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1 ||
        (device[0] && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device,
                                strlen(device) + 1) != 0) ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(fd, 4096) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int accept_ready(int epfd, int listen_fd, uint64_t total,
                        uint64_t *accepted, size_t payload_size,
                        struct timespec *start, bool *started)
{
    while (*accepted < total) {
        int fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            return -1;
        }
        connection *conn = calloc(1, sizeof(*conn) + payload_size);
        if (!conn) {
            close(fd);
            return -1;
        }
        conn->fd = fd;
        conn->payload_size = payload_size;
        struct epoll_event event = {
            .events = EPOLLIN | EPOLLRDHUP,
            .data.ptr = conn,
        };
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) != 0) {
            int saved_errno = errno;
            close(fd);
            free(conn);
            errno = saved_errno;
            return -1;
        }
        if (!*started) {
            clock_gettime(CLOCK_MONOTONIC, start);
            *started = true;
        }
        (*accepted)++;
    }
    return 0;
}

static int process_connection(int epfd, connection *conn, uint32_t events)
{
    if (events & EPOLLIN) {
        while (conn->received < conn->payload_size) {
            ssize_t n = recv(conn->fd, conn->data + conn->received,
                             conn->payload_size - conn->received, 0);
            if (n > 0) {
                conn->received += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            return -1;
        }
        if (conn->received == conn->payload_size) {
            if (!valid_pattern(conn->data, conn->payload_size)) {
                errno = EBADMSG;
                return -1;
            }
            if (update_events(epfd, conn, EPOLLOUT | EPOLLRDHUP) != 0)
                return -1;
        }
    }

    if ((events & EPOLLOUT) && conn->received == conn->payload_size) {
        while (conn->sent < conn->payload_size) {
            ssize_t n = send(conn->fd, conn->data + conn->sent,
                             conn->payload_size - conn->sent, MSG_NOSIGNAL);
            if (n > 0) {
                conn->sent += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            return -1;
        }
        if (conn->sent == conn->payload_size)
            return 1;
    }
    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        errno = ECONNRESET;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "Usage: %s IP PORT DEVICE CONNECTIONS PAYLOAD_BYTES\n",
                argv[0]);
        return 2;
    }
    char *end = NULL;
    unsigned long port_value = strtoul(argv[2], &end, 10);
    if (!end || *end || port_value == 0 || port_value > 65535)
        return 2;
    uint64_t total = strtoull(argv[4], &end, 10);
    if (!end || *end || total == 0)
        return 2;
    size_t payload_size = (size_t)strtoull(argv[5], &end, 10);
    if (!end || *end || payload_size == 0 || payload_size > 1024 * 1024)
        return 2;

    int listen_fd = create_listener(argv[1], (uint16_t)port_value, argv[3]);
    if (listen_fd < 0) {
        perror("create listener");
        return 1;
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event listener_event = {
        .events = EPOLLIN,
        .data.ptr = NULL,
    };
    if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd,
                              &listener_event) != 0) {
        perror("create epoll");
        close(listen_fd);
        return 1;
    }
    printf("Linux short-flow server %s:%lu, connections=%llu payload=%zu\n",
           argv[1], port_value, (unsigned long long)total, payload_size);
    fflush(stdout);

    struct epoll_event events[MAX_EVENTS];
    uint64_t accepted = 0, completed = 0, failed = 0;
    struct timespec start = {0}, end_time;
    bool started = false;
    while (completed + failed < total) {
        int count = epoll_wait(epfd, events, MAX_EVENTS, 30000);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        if (count == 0) {
            fprintf(stderr, "Linux server timed out\n");
            break;
        }
        for (int i = 0; i < count; ++i) {
            if (!events[i].data.ptr) {
                if (accept_ready(epfd, listen_fd, total, &accepted,
                                 payload_size, &start, &started) != 0)
                    perror("accept");
                continue;
            }
            connection *conn = events[i].data.ptr;
            int result = process_connection(epfd, conn, events[i].events);
            if (result == 0)
                continue;
            if (result > 0)
                completed++;
            else
                failed++;
            close_connection(epfd, conn);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = started ? seconds_between(&start, &end_time) : 0.0;
    printf("Linux server result: accepted=%llu completed=%llu failed=%llu "
           "elapsed=%.6f connections/s=%.2f\n",
           (unsigned long long)accepted, (unsigned long long)completed,
           (unsigned long long)failed, elapsed,
           elapsed > 0.0 ? (double)completed / elapsed : 0.0);
    close(epfd);
    close(listen_fd);
    return completed == total && failed == 0 ? 0 : 1;
}
