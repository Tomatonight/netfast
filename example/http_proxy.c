#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "netfast.h"
#include "req.h"

#define PROXY_PORT 8888
#define PROXY_BACKLOG 128
#define HEADER_CAPACITY (32u * 1024u)
#define RELAY_CAPACITY (32u * 1024u)
#define MAX_HOST_LENGTH 255u

typedef struct proxy_conn proxy_conn;
typedef struct proxy_op proxy_op;

typedef enum proxy_op_kind {
    PROXY_OP_ACCEPT,
    PROXY_OP_CLIENT_HEADERS,
    PROXY_OP_UPSTREAM_SOCKET,
    PROXY_OP_UPSTREAM_CONNECT,
    PROXY_OP_CONNECT_REPLY,
    PROXY_OP_ERROR_REPLY,
    PROXY_OP_INITIAL_UPSTREAM_WRITE,
    PROXY_OP_CLIENT_READ,
    PROXY_OP_UPSTREAM_READ,
    PROXY_OP_UPSTREAM_WRITE,
    PROXY_OP_CLIENT_WRITE,
} proxy_op_kind;

struct proxy_conn {
    uint64_t id;
    int client_fd;
    int upstream_fd;
    bool is_connect;
    bool closing;
    unsigned int pending_ops;
    char peer[INET_ADDRSTRLEN];
    char host[MAX_HOST_LENGTH + 1];
    uint16_t port;
    struct sockaddr_in upstream_addr;
    char *headers;
    size_t headers_len;
    char *initial_data;
    size_t initial_len;
    uint64_t client_to_upstream;
    uint64_t upstream_to_client;
};

struct proxy_op {
    proxy_op *next;
    net_async_req *request;
    proxy_op_kind kind;
    proxy_conn *conn;
    int fd;
    char *buffer;
    size_t length;
    size_t offset;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
};

static volatile sig_atomic_t g_stop;
static proxy_op *g_ops;
static uint64_t g_next_connection_id = 1;

static const char *op_name(proxy_op_kind kind)
{
    switch (kind) {
    case PROXY_OP_ACCEPT:                 return "accept";
    case PROXY_OP_CLIENT_HEADERS:         return "client-headers";
    case PROXY_OP_UPSTREAM_SOCKET:        return "upstream-socket";
    case PROXY_OP_UPSTREAM_CONNECT:       return "upstream-connect";
    case PROXY_OP_CONNECT_REPLY:          return "connect-reply";
    case PROXY_OP_ERROR_REPLY:            return "error-reply";
    case PROXY_OP_INITIAL_UPSTREAM_WRITE: return "initial-upstream-write";
    case PROXY_OP_CLIENT_READ:            return "client-read";
    case PROXY_OP_UPSTREAM_READ:          return "upstream-read";
    case PROXY_OP_UPSTREAM_WRITE:         return "upstream-write";
    case PROXY_OP_CLIENT_WRITE:           return "client-write";
    }
    return "unknown";
}

static void proxy_log(const char *level, const char *fmt, ...)
{
    struct timespec now;
    struct tm tm_now;
    char timestamp[32];
    va_list ap;

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm_now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

    fprintf(stderr, "%s.%03ld [%s] ", timestamp, now.tv_nsec / 1000000L,
            level);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

static void stop_proxy(int signal_number)
{
    (void)signal_number;
    g_stop = 1;
}

static proxy_op *op_create(proxy_op_kind kind, proxy_conn *conn)
{
    proxy_op *op = calloc(1, sizeof(*op));
    if (!op)
        return NULL;
    op->kind = kind;
    op->conn = conn;
    return op;
}

static void op_free(proxy_op *op)
{
    if (!op)
        return;
    free(op->buffer);
    free(op);
}

static void op_link(proxy_op *op)
{
    op->next = g_ops;
    g_ops = op;
    if (op->conn)
        op->conn->pending_ops++;
}

static void op_unlink(proxy_op *op)
{
    proxy_op **link = &g_ops;
    while (*link && *link != op)
        link = &(*link)->next;
    if (*link)
        *link = op->next;
    op->next = NULL;
    if (op->conn) {
        if (op->conn->pending_ops == 0)
            abort();
        op->conn->pending_ops--;
    }
}

static proxy_op *op_find(net_async_req *request)
{
    for (proxy_op *op = g_ops; op; op = op->next) {
        if (op->request == request)
            return op;
    }
    return NULL;
}

static void conn_destroy(proxy_conn *conn)
{
    free(conn->headers);
    free(conn->initial_data);
    free(conn);
}

static void conn_reap(proxy_conn *conn)
{
    if (conn && conn->closing && conn->pending_ops == 0)
        conn_destroy(conn);
}

static void conn_close(proxy_conn *conn, const char *reason)
{
    if (!conn || conn->closing)
        return;

    conn->closing = true;
    proxy_log("INFO",
              "conn=%llu close peer=%s target=%s:%u reason=%s c2u=%llu u2c=%llu",
              (unsigned long long)conn->id, conn->peer, conn->host,
              conn->port, reason, (unsigned long long)conn->client_to_upstream,
              (unsigned long long)conn->upstream_to_client);

    if (conn->client_fd >= 0) {
        (void)net_close(conn->client_fd);
        conn->client_fd = -1;
    }
    if (conn->upstream_fd >= 0) {
        (void)net_close(conn->upstream_fd);
        conn->upstream_fd = -1;
    }
}

static int submit_operation(int cq_fd, proxy_op *op)
{
    proxy_conn *conn = op->conn;

    switch (op->kind) {
    case PROXY_OP_ACCEPT:
        op->peer_addr_len = sizeof(op->peer_addr);
        op->request = net_async_req_create(op->fd, NET_ASYNC_ACCEPT,
            (struct sockaddr *)&op->peer_addr, &op->peer_addr_len);
        break;
    case PROXY_OP_CLIENT_HEADERS:
        op->request = net_async_req_create(conn->client_fd, NET_ASYNC_READ,
            conn->headers + conn->headers_len,
            (uint32_t)(HEADER_CAPACITY - conn->headers_len));
        break;
    case PROXY_OP_UPSTREAM_SOCKET:
        op->request = net_async_req_create(-1, NET_ASYNC_SOCKET, AF_INET,
                                            SOCK_STREAM, IPPROTO_TCP);
        break;
    case PROXY_OP_UPSTREAM_CONNECT:
        op->request = net_async_req_create(conn->upstream_fd,
            NET_ASYNC_CONNECT, (const struct sockaddr *)&conn->upstream_addr,
            (socklen_t)sizeof(conn->upstream_addr));
        break;
    case PROXY_OP_CONNECT_REPLY:
    case PROXY_OP_ERROR_REPLY:
    case PROXY_OP_CLIENT_WRITE:
        op->request = net_async_req_create(conn->client_fd, NET_ASYNC_WRITE,
            op->buffer + op->offset, (uint32_t)(op->length - op->offset));
        break;
    case PROXY_OP_INITIAL_UPSTREAM_WRITE:
    case PROXY_OP_UPSTREAM_WRITE:
        op->request = net_async_req_create(conn->upstream_fd, NET_ASYNC_WRITE,
            op->buffer + op->offset, (uint32_t)(op->length - op->offset));
        break;
    case PROXY_OP_CLIENT_READ:
        op->request = net_async_req_create(conn->client_fd, NET_ASYNC_READ,
            op->buffer, (uint32_t)op->length);
        break;
    case PROXY_OP_UPSTREAM_READ:
        op->request = net_async_req_create(conn->upstream_fd, NET_ASYNC_READ,
            op->buffer, (uint32_t)op->length);
        break;
    }

    if (!op->request) {
        proxy_log("ERROR", "conn=%llu %s create failed: %s",
                  conn ? (unsigned long long)conn->id : 0,
                  op_name(op->kind), strerror(errno));
        return -1;
    }

    op_link(op);
    if (net_async_submit(cq_fd, op->request) == 0) {
        proxy_log("DEBUG", "conn=%llu submitted op=%s async_fd=%d",
                  conn ? (unsigned long long)conn->id : 0,
                  op_name(op->kind), op->request->async_fd);
        return 0;
    }

    proxy_log("ERROR", "conn=%llu %s submit failed: %s",
              conn ? (unsigned long long)conn->id : 0,
              op_name(op->kind), strerror(errno));
    op_unlink(op);
    net_async_req_destroy(op->request);
    op->request = NULL;
    return -1;
}

static int submit_accept(int cq_fd, int listen_fd)
{
    proxy_op *op = op_create(PROXY_OP_ACCEPT, NULL);
    if (!op)
        return -1;
    op->fd = listen_fd;
    if (submit_operation(cq_fd, op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_headers_read(int cq_fd, proxy_conn *conn)
{
    proxy_op *op = op_create(PROXY_OP_CLIENT_HEADERS, conn);
    if (!op)
        return -1;
    if (submit_operation(cq_fd, op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_upstream_socket(int cq_fd, proxy_conn *conn)
{
    proxy_op *op = op_create(PROXY_OP_UPSTREAM_SOCKET, conn);
    if (!op)
        return -1;
    if (submit_operation(cq_fd, op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_upstream_connect(int cq_fd, proxy_conn *conn)
{
    proxy_op *op = op_create(PROXY_OP_UPSTREAM_CONNECT, conn);
    if (!op)
        return -1;
    if (submit_operation(cq_fd, op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_write(int cq_fd, proxy_conn *conn, proxy_op_kind kind,
                        const void *data, size_t len)
{
    proxy_op *op = op_create(kind, conn);
    if (!op)
        return -1;

    op->buffer = malloc(len ? len : 1);
    if (!op->buffer) {
        op_free(op);
        return -1;
    }
    if (len)
        memcpy(op->buffer, data, len);
    op->length = len;

    if (submit_operation(cq_fd, op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_relay_read(int cq_fd, proxy_conn *conn, bool from_client)
{
    proxy_op *op = op_create(from_client ? PROXY_OP_CLIENT_READ
                                          : PROXY_OP_UPSTREAM_READ,
                             conn);
    if (!op)
        return -1;
    op->buffer = malloc(RELAY_CAPACITY);
    if (!op->buffer) {
        op_free(op);
        return -1;
    }
    op->length = RELAY_CAPACITY;
    if (submit_operation(cq_fd, op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int start_relay(int cq_fd, proxy_conn *conn)
{
    if (conn->closing)
        return -1;
    if (submit_relay_read(cq_fd, conn, true) != 0 ||
        submit_relay_read(cq_fd, conn, false) != 0) {
        conn_close(conn, "cannot start relay");
        return -1;
    }
    return 0;
}

static bool header_name_equals(const char *line, size_t line_len,
                               const char *name)
{
    size_t name_len = strlen(name);
    return line_len > name_len && line[name_len] == ':' &&
           strncasecmp(line, name, name_len) == 0;
}

static int parse_port(const char *value, size_t value_len, uint16_t *port)
{
    if (value_len == 0 || value_len > 5)
        return -1;
    unsigned long parsed = 0;
    for (size_t i = 0; i < value_len; ++i) {
        if (value[i] < '0' || value[i] > '9')
            return -1;
        parsed = parsed * 10u + (unsigned long)(value[i] - '0');
        if (parsed > 65535u)
            return -1;
    }
    if (parsed == 0)
        return -1;
    *port = (uint16_t)parsed;
    return 0;
}

static int parse_authority(const char *authority, size_t authority_len,
                           uint16_t default_port, char *host,
                           uint16_t *port)
{
    const char *host_begin = authority;
    const char *host_end = authority + authority_len;
    const char *port_begin = NULL;

    while (host_begin < host_end && (*host_begin == ' ' || *host_begin == '\t'))
        host_begin++;
    while (host_end > host_begin &&
           (host_end[-1] == ' ' || host_end[-1] == '\t'))
        host_end--;
    if (host_begin == host_end)
        return -1;

    if (*host_begin == '[') {
        const char *close = memchr(host_begin, ']', (size_t)(host_end - host_begin));
        if (!close)
            return -1;
        host_begin++;
        if (close + 1 < host_end) {
            if (close[1] != ':')
                return -1;
            port_begin = close + 2;
        }
        host_end = close;
    } else {
        const char *colon = NULL;
        for (const char *p = host_begin; p < host_end; ++p) {
            if (*p == ':')
                colon = p;
        }
        if (colon) {
            port_begin = colon + 1;
            host_end = colon;
        }
    }

    size_t host_len = (size_t)(host_end - host_begin);
    if (host_len == 0 || host_len > MAX_HOST_LENGTH)
        return -1;
    memcpy(host, host_begin, host_len);
    host[host_len] = '\0';
    *port = default_port;
    if (port_begin && parse_port(port_begin,
                                 (size_t)((authority + authority_len) - port_begin),
                                 port) != 0)
        return -1;
    return 0;
}

static ssize_t find_headers_end(const char *data, size_t len)
{
    if (len < 4)
        return -1;
    for (size_t i = 0; i + 4 <= len; ++i) {
        if (memcmp(data + i, "\r\n\r\n", 4) == 0)
            return (ssize_t)(i + 4);
    }
    return -1;
}

static int host_from_header(const char *headers, size_t headers_len,
                            char *host, uint16_t *port)
{
    const char *line = headers;
    const char *end = headers + headers_len;
    const char *first_end = memmem(headers, headers_len, "\r\n", 2);
    if (!first_end)
        return -1;
    line = first_end + 2;

    while (line < end) {
        const char *line_end = memmem(line, (size_t)(end - line), "\r\n", 2);
        if (!line_end || line_end == line)
            break;
        size_t line_len = (size_t)(line_end - line);
        if (header_name_equals(line, line_len, "Host")) {
            const char *value = line + 5;
            while (value < line_end && (*value == ' ' || *value == '\t'))
                value++;
            return parse_authority(value, (size_t)(line_end - value), 80,
                                   host, port);
        }
        line = line_end + 2;
    }
    return -1;
}

static int prepare_http_request(proxy_conn *conn, size_t header_end)
{
    char *first_end = memmem(conn->headers, header_end, "\r\n", 2);
    if (!first_end)
        return -1;
    *first_end = '\0';

    char *method = conn->headers;
    char *target = strchr(method, ' ');
    if (!target)
        return -1;
    *target++ = '\0';
    char *version = strchr(target, ' ');
    if (!version)
        return -1;
    *version++ = '\0';

    const char *rest = first_end + 2;
    size_t rest_len = header_end - (size_t)(rest - conn->headers);
    bool absolute = strncasecmp(target, "http://", 7) == 0;

    if (strcasecmp(method, "CONNECT") == 0) {
        if (parse_authority(target, strlen(target), 443, conn->host,
                            &conn->port) != 0)
            return -1;
        conn->is_connect = true;
        size_t body_len = conn->headers_len - header_end;
        if (body_len) {
            conn->initial_data = malloc(body_len);
            if (!conn->initial_data)
                return -1;
            memcpy(conn->initial_data, conn->headers + header_end, body_len);
            conn->initial_len = body_len;
        }
        return 0;
    }

    const char *path = target;
    if (absolute) {
        const char *authority = target + 7;
        const char *slash = strchr(authority, '/');
        const char *authority_end = slash ? slash : authority + strlen(authority);
        if (parse_authority(authority, (size_t)(authority_end - authority), 80,
                            conn->host, &conn->port) != 0)
            return -1;
        path = slash ? slash : "/";
    } else {
        *first_end = '\r';
        int host_ret = host_from_header(conn->headers, header_end, conn->host,
                                        &conn->port);
        *first_end = '\0';
        if (host_ret != 0)
            return -1;
    }

    int line_len = snprintf(NULL, 0, "%s %s %s\r\n", method, path, version);
    if (line_len < 0)
        return -1;
    size_t body_len = conn->headers_len - header_end;
    size_t initial_len = (size_t)line_len + rest_len + body_len;
    conn->initial_data = malloc(initial_len);
    if (!conn->initial_data)
        return -1;
    snprintf(conn->initial_data, (size_t)line_len + 1, "%s %s %s\r\n",
             method, path, version);
    memcpy(conn->initial_data + line_len, rest, rest_len);
    if (body_len)
        memcpy(conn->initial_data + line_len + rest_len,
               conn->headers + header_end, body_len);
    conn->initial_len = initial_len;
    return 0;
}

static int resolve_target(proxy_conn *conn)
{
    char port[6];
    snprintf(port, sizeof(port), "%u", conn->port);

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *result = NULL;
    int ret = getaddrinfo(conn->host, port, &hints, &result);
    if (ret != 0) {
        proxy_log("ERROR", "conn=%llu resolve %s:%s failed: %s",
                  (unsigned long long)conn->id, conn->host, port,
                  gai_strerror(ret));
        return -1;
    }
    memcpy(&conn->upstream_addr, result->ai_addr, sizeof(conn->upstream_addr));
    freeaddrinfo(result);
    return 0;
}

static void send_error(int cq_fd, proxy_conn *conn, const char *status)
{
    char response[256];
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 %s\r\nConnection: close\r\n"
                       "Content-Length: 0\r\n\r\n", status);
    if (len < 0 || (size_t)len >= sizeof(response) ||
        submit_write(cq_fd, conn, PROXY_OP_ERROR_REPLY, response,
                     (size_t)len) != 0) {
        conn_close(conn, "cannot send error response");
    }
}

static void start_initial_upstream_write(int cq_fd, proxy_conn *conn)
{
    if (conn->initial_len == 0) {
        (void)start_relay(cq_fd, conn);
        return;
    }
    if (submit_write(cq_fd, conn, PROXY_OP_INITIAL_UPSTREAM_WRITE,
                     conn->initial_data, conn->initial_len) != 0) {
        conn_close(conn, "cannot submit initial upstream write");
    }
    free(conn->initial_data);
    conn->initial_data = NULL;
    conn->initial_len = 0;
}

static void complete_accept(int cq_fd, proxy_op *op, int ret, int saved_errno)
{
    int listen_fd = op->fd;
    (void)submit_accept(cq_fd, listen_fd);
    if (ret < 0) {
        proxy_log("ERROR", "accept failed: %s", strerror(saved_errno));
        return;
    }

    proxy_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        (void)net_close(ret);
        return;
    }
    conn->id = g_next_connection_id++;
    conn->client_fd = ret;
    conn->upstream_fd = -1;
    conn->headers = calloc(1, HEADER_CAPACITY + 1);
    if (!conn->headers) {
        conn_close(conn, "cannot allocate header buffer");
        conn_reap(conn);
        return;
    }
    const struct sockaddr_in *peer = (const struct sockaddr_in *)&op->peer_addr;
    if (!inet_ntop(AF_INET, &peer->sin_addr, conn->peer, sizeof(conn->peer)))
        snprintf(conn->peer, sizeof(conn->peer), "unknown");
    proxy_log("INFO", "conn=%llu accepted peer=%s fd=%d",
              (unsigned long long)conn->id, conn->peer, conn->client_fd);
    if (submit_headers_read(cq_fd, conn) != 0) {
        conn_close(conn, "cannot submit header read");
        conn_reap(conn);
    }
}

static void complete_headers(int cq_fd, proxy_conn *conn, int ret,
                             int saved_errno)
{
    if (ret <= 0) {
        conn_close(conn, ret == 0 ? "client closed before request" : strerror(saved_errno));
        return;
    }
    conn->headers_len += (size_t)ret;
    ssize_t header_end = find_headers_end(conn->headers, conn->headers_len);
    if (header_end < 0) {
        if (conn->headers_len == HEADER_CAPACITY) {
            send_error(cq_fd, conn, "431 Request Header Fields Too Large");
            return;
        }
        if (submit_headers_read(cq_fd, conn) != 0)
            conn_close(conn, "cannot continue header read");
        return;
    }

    if (prepare_http_request(conn, (size_t)header_end) != 0 ||
        resolve_target(conn) != 0) {
        send_error(cq_fd, conn, "400 Bad Request");
        return;
    }
    proxy_log("INFO", "conn=%llu request peer=%s target=%s:%u mode=%s",
              (unsigned long long)conn->id, conn->peer, conn->host,
              conn->port, conn->is_connect ? "CONNECT" : "HTTP");
    if (submit_upstream_socket(cq_fd, conn) != 0)
        send_error(cq_fd, conn, "502 Bad Gateway");
}

static void complete_write(int cq_fd, proxy_op *op, int ret, int saved_errno)
{
    proxy_conn *conn = op->conn;
    if (ret <= 0) {
        conn_close(conn, ret == 0 ? "short write" : strerror(saved_errno));
        return;
    }
    op->offset += (size_t)ret;
    if (op->offset < op->length) {
        if (submit_operation(cq_fd, op) != 0) {
            conn_close(conn, "cannot continue write");
            op_free(op);
        }
        return;
    }

    switch (op->kind) {
    case PROXY_OP_CONNECT_REPLY:
        op_free(op);
        start_initial_upstream_write(cq_fd, conn);
        return;
    case PROXY_OP_ERROR_REPLY:
        op_free(op);
        conn_close(conn, "error response sent");
        return;
    case PROXY_OP_INITIAL_UPSTREAM_WRITE:
        op_free(op);
        (void)start_relay(cq_fd, conn);
        return;
    case PROXY_OP_UPSTREAM_WRITE:
        conn->client_to_upstream += op->length;
        op_free(op);
        (void)submit_relay_read(cq_fd, conn, true);
        return;
    case PROXY_OP_CLIENT_WRITE:
        conn->upstream_to_client += op->length;
        op_free(op);
        (void)submit_relay_read(cq_fd, conn, false);
        return;
    default:
        op_free(op);
        conn_close(conn, "invalid write completion");
        return;
    }
}

static void complete_relay_read(int cq_fd, proxy_op *op, int ret,
                                int saved_errno)
{
    proxy_conn *conn = op->conn;
    if (ret <= 0) {
        op_free(op);
        conn_close(conn, ret == 0 ? "relay EOF" : strerror(saved_errno));
        return;
    }

    op->length = (size_t)ret;
    op->offset = 0;
    op->kind = op->kind == PROXY_OP_CLIENT_READ ? PROXY_OP_UPSTREAM_WRITE
                                                : PROXY_OP_CLIENT_WRITE;
    if (submit_operation(cq_fd, op) != 0) {
        op_free(op);
        conn_close(conn, "cannot submit relay write");
    }
}

static void dispatch_completion(int cq_fd, net_async_req *request)
{
    proxy_op *op = op_find(request);
    if (!op) {
        proxy_log("ERROR", "completion has no proxy operation");
        net_async_req_destroy(request);
        return;
    }

    proxy_conn *conn = op->conn;
    int ret = net_async_req_result(request);
    int saved_errno = ret < 0 ? -ret : 0;
    proxy_log("DEBUG", "conn=%llu completed op=%s async_fd=%d ret=%d errno=%d",
              conn ? (unsigned long long)conn->id : 0, op_name(op->kind),
              request->async_fd, ret, saved_errno);
    op_unlink(op);
    op->request = NULL;
    net_async_req_destroy(request);

    if (conn && conn->closing) {
        op_free(op);
        conn_reap(conn);
        return;
    }

    switch (op->kind) {
    case PROXY_OP_ACCEPT:
        complete_accept(cq_fd, op, ret, saved_errno);
        op_free(op);
        break;
    case PROXY_OP_CLIENT_HEADERS:
        op_free(op);
        complete_headers(cq_fd, conn, ret, saved_errno);
        break;
    case PROXY_OP_UPSTREAM_SOCKET:
        op_free(op);
        if (ret < 0) {
            send_error(cq_fd, conn, "502 Bad Gateway");
            break;
        }
        conn->upstream_fd = ret;
        if (submit_upstream_connect(cq_fd, conn) != 0)
            send_error(cq_fd, conn, "502 Bad Gateway");
        break;
    case PROXY_OP_UPSTREAM_CONNECT:
        op_free(op);
        if (ret < 0) {
            proxy_log("ERROR", "conn=%llu connect %s:%u failed: %s",
                      (unsigned long long)conn->id, conn->host, conn->port,
                      strerror(saved_errno));
            send_error(cq_fd, conn, "502 Bad Gateway");
            break;
        }
        proxy_log("INFO", "conn=%llu connected target=%s:%u fd=%d",
                  (unsigned long long)conn->id, conn->host, conn->port,
                  conn->upstream_fd);
        if (conn->is_connect) {
            static const char established[] =
                "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (submit_write(cq_fd, conn, PROXY_OP_CONNECT_REPLY, established,
                             sizeof(established) - 1) != 0)
                conn_close(conn, "cannot send CONNECT response");
        } else {
            start_initial_upstream_write(cq_fd, conn);
        }
        break;
    case PROXY_OP_CONNECT_REPLY:
    case PROXY_OP_ERROR_REPLY:
    case PROXY_OP_INITIAL_UPSTREAM_WRITE:
    case PROXY_OP_UPSTREAM_WRITE:
    case PROXY_OP_CLIENT_WRITE:
        complete_write(cq_fd, op, ret, saved_errno);
        break;
    case PROXY_OP_CLIENT_READ:
    case PROXY_OP_UPSTREAM_READ:
        complete_relay_read(cq_fd, op, ret, saved_errno);
        break;
    }

    conn_reap(conn);
}

int main(void)
{
    signal(SIGINT, stop_proxy);
    signal(SIGTERM, stop_proxy);

    int listen_fd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0) {
        perror("net_socket");
        return 1;
    }
    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PROXY_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (net_bind(listen_fd, (struct sockaddr *)&listen_addr,
                 sizeof(listen_addr)) != 0 ||
        net_listen(listen_fd, PROXY_BACKLOG) != 0) {
        perror("listen setup");
        (void)net_close(listen_fd);
        return 1;
    }

    int cq_fd = net_async_create();
    if (cq_fd < 0 || submit_accept(cq_fd, listen_fd) != 0) {
        perror("async accept setup");
        if (cq_fd >= 0)
            (void)net_async_close(cq_fd);
        (void)net_close(listen_fd);
        return 1;
    }

    proxy_log("INFO", "NetFast async HTTP proxy listening on 0.0.0.0:%u",
              PROXY_PORT);
    while (!g_stop) {
        net_async_req *completed[64];
        int count = net_async_wait(cq_fd, completed, 1, 64, 1000);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            proxy_log("ERROR", "async wait failed: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < count; ++i)
            dispatch_completion(cq_fd, completed[i]);
    }

    proxy_log("INFO", "proxy shutting down");
    (void)net_async_close(cq_fd);
    (void)net_close(listen_fd);
    return 0;
}
