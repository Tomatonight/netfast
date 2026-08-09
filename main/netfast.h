#ifndef NETFAST_H
#define NETFAST_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── socket API ── */
int net_socket(int family, int type, int protocol);
int net_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int net_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int net_write(int sockfd, const void *buf, uint32_t len);
int net_read(int sockfd, void *buf, uint32_t len);
int net_sendto(int sockfd, const void *buf, uint32_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen);
int net_recvfrom(int sockfd, void *buf, uint32_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen);
int net_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int net_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int net_close(int fd);
int net_setsockopt(int sockfd, int level, int optname,
                   const void *optval, socklen_t optlen);
int net_getsockopt(int sockfd, int level, int optname,
                   void *optval, socklen_t *optlen);
int net_fcntl(int sockfd, int cmd, ...);
int net_shutdown(int sockfd, int how);
int net_listen(int sockfd, int backlog);
int net_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/* ── epoll API ── */
int net_epoll_create(void);
int net_epoll_ctl(int epfd, int op, int sockfd, struct epoll_event *event);
int net_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                   int timeout_ms);

/* ── asynchronous request API ──
 * A successful submit transfers request ownership to the completion queue.
 * net_async_wait() returns ownership to the caller; then inspect the result
 * and call net_async_req_destroy().  All pointed-to buffers must remain valid
 * until completion. */
typedef struct req net_async_req;

typedef enum net_async_op {
    NET_ASYNC_SOCKET = 1,
    NET_ASYNC_BIND,
    NET_ASYNC_CONNECT,
    NET_ASYNC_LISTEN,
    NET_ASYNC_ACCEPT,
    NET_ASYNC_WRITE,
    NET_ASYNC_READ,
    NET_ASYNC_SENDTO,
    NET_ASYNC_RECVFROM,
    NET_ASYNC_GETSOCKNAME,
    NET_ASYNC_GETPEERNAME,
    NET_ASYNC_CLOSE,
    NET_ASYNC_SHUTDOWN,
    NET_ASYNC_SETSOCKOPT,
    NET_ASYNC_GETSOCKOPT,
    NET_ASYNC_FCNTL,
} net_async_op;

net_async_req *net_async_req_create(int fd, int operation, ...);
void net_async_req_destroy(net_async_req *request);
int net_async_req_result(const net_async_req *request, int *saved_errno);
int net_async_create(void);
int net_async_submit(int cq_fd, net_async_req *request);
/* Submit requests in array order.  On success, returns the number submitted
 * and transfers ownership of requests[0..return_value) to the CQ.  A short
 * positive return means the first unsubmitted request failed validation;
 * requests at and after that index remain owned by the caller. */
int net_async_submit_batch(int cq_fd, net_async_req **requests,
                           uint32_t count);
/* Wait for min_complete requests and return as many immediately available
 * completions as possible, up to max_complete.  On total timeout, a partial
 * batch is returned.  A negative total_timeout_ms waits indefinitely.
 * Multiple threads may wait on the same CQ; each completion is returned to
 * exactly one waiter. */
int net_async_wait(int cq_fd, net_async_req **requests,
	                   uint32_t min_complete, uint32_t max_complete,
	                   int total_timeout_ms);
int net_async_close(int cq_fd);

	#ifdef __cplusplus
	}
#endif

#endif /* NETFAST_H */
