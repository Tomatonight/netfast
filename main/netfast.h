#ifndef NETFAST_H
#define NETFAST_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Socket Socket;

typedef uint32_t net_event_mask;

#define NET_EVENT_READ      (UINT32_C(1) << 0)
#define NET_EVENT_WRITE     (UINT32_C(1) << 1)
#define NET_EVENT_CONNECT   (UINT32_C(1) << 2)
#define NET_EVENT_ACCEPT    (UINT32_C(1) << 3)
#define NET_EVENT_FIN       (UINT32_C(1) << 4)
#define NET_EVENT_ERROR     (UINT32_C(1) << 5)

/* Called on the worker that owns sock.  Synchronous net_* calls made from this
 * callback execute inline with non-blocking semantics; an operation that would
 * wait returns EAGAIN or EINPROGRESS. */
typedef void (*net_callback)(Socket *sock, net_event_mask events, void *arg);

/* ── socket API ── */
int net_socket(int family, int type, int protocol);
int net_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int net_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int net_listen(int sockfd, int backlog);
int net_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int net_write(int sockfd, const void *buf, uint32_t len);
int net_read(int sockfd, void *buf, uint32_t len);
int net_sendto(int sockfd, const void *buf, uint32_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen);
int net_recvfrom(int sockfd, void *buf, uint32_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen);
int net_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int net_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int net_setsockopt(int sockfd, int level, int optname,
                   const void *optval, socklen_t optlen);
int net_getsockopt(int sockfd, int level, int optname,
                   void *optval, socklen_t *optlen);
int net_fcntl(int sockfd, int cmd, ...);
int net_close(int fd);
int net_shutdown(int sockfd, int how);

int net_set_callback(int sockfd, net_event_mask events,
                     net_callback cb, void *arg);
int net_clear_callback(int sockfd);

/* ── asynchronous request API ──
 * A successful submit transfers request ownership to the completion queue.
 * net_async_wait() returns ownership to the caller; then call
 * net_async_result() and either resubmit or destroy the request.  A completed
 * result is non-negative on success and -errno on failure.  All pointed-to
 * buffers must remain valid until completion. */
typedef enum req_type {
    REQ_SOCKET = 1,
    REQ_BIND,
    REQ_CONNECT,
    REQ_LISTEN,
    REQ_ACCEPT,
    REQ_WRITE,
    REQ_READ,
    REQ_SENDTO,
    REQ_RECVFROM,
    REQ_GETSOCKNAME,
    REQ_GETPEERNAME,
    REQ_CLOSE,
    REQ_SHUTDOWN,
    REQ_SETSOCKOPT,
    REQ_GETSOCKOPT,
    REQ_FCNTL,
    REQ_WORKER_REQ,
} req_type;

typedef struct req req;

/* Arguments retained by a request.  Pointer arguments keep referring to the
 * caller-owned objects supplied to net_async_req_create(), so those objects
 * must remain valid until the request completes. */
typedef union req_argv {
    struct {
        int family;
        int type;
        int protocol;
    } Socket;
    struct {
        struct sockaddr_storage addr;
        socklen_t addrlen;
    } bind;
    struct {
        struct sockaddr_storage addr;
        socklen_t addrlen;
    } connect;
    struct {
        const void *buf;
        uint32_t len;
    } write;
    struct {
        void *buf;
        uint32_t len;
    } read;
    struct {
        const void *buf;
        uint32_t len;
        int flags;
        struct sockaddr_storage dest_addr;
        socklen_t addrlen;
        uint32_t has_dest_addr;
    } sendto;
    struct {
        void *buf;
        uint32_t len;
        int flags;
        struct sockaddr *src_addr;
        socklen_t *addrlen;
    } recvfrom;
    struct {
        int backlog;
    } listen;
    struct {
        struct sockaddr *addr;
        socklen_t *addrlen;
    } accept;
    struct {
        struct sockaddr *addr;
        socklen_t *addrlen;
    } getsockname;
    struct {
        struct sockaddr *addr;
        socklen_t *addrlen;
    } getpeername;
    struct {
        int how;
    } shutdown;
    struct {
        int level;
        int optname;
        const void *optval;
        socklen_t optlen;
    } setsockopt;
    struct {
        int level;
        int optname;
        void *optval;
        socklen_t *optlen;
    } getsockopt;
    struct {
        int cmd;
        int arg;
    } fcntl;
    struct {
        void *argv;
        int (*cb)(void *);
    } worker_req;
} req_argv;

int net_async_create(void);
req *net_async_req_create(int fd, req_type type, ...);
void net_async_req_destroy(req *request);
int net_async_submit(int cq_fd, req *request);

int net_async_result(const req *request, req_type *type);
req_argv *net_async_argv(req *request);
int net_async_wait(int cq_fd, req **requests,
                       uint32_t min_complete, uint32_t max_complete,
                       int total_timeout_ms);
int net_async_close(int cq_fd);

#ifdef __cplusplus
}
#endif

#endif /* NETFAST_H */
