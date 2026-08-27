#ifndef REQ_H
#define REQ_H
#include <limits.h>
#include <stddef.h> 
#include <sys/types.h> 
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "fd_entry.h"
#include "if.h"
#include "queue.h"
#include "thread.h"
#include "list.h"
#include "netfast.h"

#define REQ_PENDING INT_MIN

typedef struct Socket Socket;
typedef struct worker worker;
typedef struct async_cq async_cq;

typedef enum req_status {
    REQ_IN_PROGRESS     = 0,
    REQ_WAITING_READ    = (1 << 0),
    REQ_WAITING_WRITE   = (1 << 1),
    REQ_WAITING_CONNECT = (1 << 2),
    REQ_WAITING_ACCEPT  = (1 << 3),
    REQ_WAITING_CLOSE   = (1 << 4),
    REQ_COMPLETED       = (1 << 5),
} req_status;

#define REQ_STATUS_ALL  ((req_status)0xFFFFFFFF)

struct req {
    mpscq_node node;
    worker* worker;
    fd_entry* entry;

    req_type type;
    int ret;
    req_status status;
    pending_node pn;          /* for socket->pending attachment */

    Socket* wait_sock;
    task *timeout_task;

    struct {
        list_node submit_node;
        mpscq_node completion_node;
        async_cq* cq;
    }async;

    struct {
        uint32_t no_wait     : 1;  /* 1=push 方不阻塞等待结果 */
        uint32_t notify_free : 1;  /* 1=req_notify 负责 destroy cv/mtx + free(r) */
        uint32_t async_cancel : 1;
    } flag;
    spinlock_t done_mtx;
    pthread_mutex_t done_wait_mtx;
    pthread_cond_t done_cv;
    int done;
    req_argv argv;
};


/* Map notify_event bitmask to req_status bitmask for req-based waiters.
 * With bit flags, a single notification can wake multiple req types. */
static inline req_status notify_event_to_status(enum notify_event e)
{
    if (e & notify_err)            return REQ_STATUS_ALL;

    req_status s = REQ_IN_PROGRESS;  /* 0 */
    if (e & notify_data_read)      s |= REQ_WAITING_READ;
    if (e & notify_recv_fin)       s |= REQ_WAITING_READ;
    if (e & notify_data_write)     s |= REQ_WAITING_WRITE | REQ_WAITING_CONNECT;
    if (e & notify_new_connection) s |= REQ_WAITING_ACCEPT;
    return s ? s : REQ_STATUS_ALL;
}

void req_notify(req* r, int ret);
req* req_create(void);
void req_init(req* r);
int  req_push_wait(worker* w, req* r);

/* Fill a stack-allocated req with type and argv fields in one line:
 *   req_fill(&r, REQ_ACCEPT, accept, .addr = a, .addrlen = al);
 * The member name is the lowercase suffix of the REQ_ type (REQ_ACCEPT →
 * accept, REQ_SOCKET → Socket).                                       */
#define req_fill(r, type_, member_, ...)                          \
    do {                                                          \
        (r)->type = (type_);                                      \
        (r)->argv.member_ = (typeof((r)->argv.member_)){ __VA_ARGS__ }; \
    } while(0)

int net_socket(int family, int type, int protocol);
int net_bind(int fd, const struct sockaddr* addr, socklen_t addrlen);
int net_connect(int fd, const struct sockaddr* addr, socklen_t addrlen);
int net_listen(int fd, int backlog);
int net_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int net_write(int fd, const void* buf, uint32_t len);
int net_read(int fd, void* buf, uint32_t len);
int net_sendto(int fd, const void* buf, uint32_t len, int flags,
                   const struct sockaddr* dest_addr, socklen_t addrlen);
int net_recvfrom(int fd, void* buf, uint32_t len, int flags,
                     struct sockaddr* src_addr, socklen_t* addrlen);
int net_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int net_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);
int net_setsockopt(int fd, int level, int optname,
                   const void* optval, socklen_t optlen);
int net_getsockopt(int fd, int level, int optname,
                   void* optval, socklen_t* optlen);
int net_fcntl(int fd, int cmd, ...);
int net_close(int fd);
int net_shutdown(int fd, int how);
#endif
