#ifndef REQ_H
#define REQ_H
#include <limits.h>
#include <stddef.h> 
#include <sys/types.h> 
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include "fd_entry.h"
#include "if.h"
#include "queue.h"
#include "thread.h"
#include "list.h"

#define REQ_PENDING INT_MIN

typedef struct Socket Socket;
typedef struct worker worker;
typedef struct async_cq async_cq;

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

    REQ_POLL,

#ifdef TEST_EPOLL
    REQ_EPOLL_CTL,
#endif
    REQ_WORKER_REQ,

} req_type;

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

typedef struct req {
    mpscq_node node;
    worker* worker;

    req_type type;
    req_status status;
    pending_node pn;          /* for socket->pending attachment */

    Socket* wait_sock;
    task *timeout_task;

    struct {
        list_node submit_node;
        mpscq_node completion_node;
        async_cq* cq;
        fd_entry* entry;
    }async;

    int async_fd;
    int ret;                    /* success value or negative errno */

    struct {
        uint32_t no_wait     : 1;  /* 1=push 方不阻塞等待结果 */
        uint32_t notify_free : 1;  /* 1=req_notify 负责 destroy cv/mtx + free(r) */
        uint32_t async_cancel : 1;
    } flag;
    spinlock_t done_mtx;
    pthread_mutex_t done_wait_mtx;
    pthread_cond_t done_cv;
    int done;
    union {
        struct {
            int family;
            int type;
            int protocol;
        } Socket;
        struct {
            fd_entry* entry;
            struct sockaddr_storage addr;
            socklen_t addrlen;
        } bind;

        struct {
            fd_entry* entry;
            struct sockaddr_storage addr;
            socklen_t addrlen;
        } connect;

        struct {
            fd_entry* entry;
            const void *buf;
            uint32_t len;
        } write;

        struct {
            fd_entry* entry;
            void *buf;
            uint32_t len;
        } read;

        struct {
            fd_entry* entry;
            const void *buf;
            uint32_t len;
            int flags;
            struct sockaddr_storage dest_addr;
            socklen_t addrlen;
            /* Distinguish a NULL destination (valid for connected UDP)
             * from an all-zero sockaddr copied into dest_addr. */
            uint32_t has_dest_addr;
        } sendto;

        struct {
            fd_entry* entry;
            void *buf;
            uint32_t len;
            int flags;
            struct sockaddr *src_addr;
            socklen_t *addrlen;
        } recvfrom;

        struct {
            fd_entry* entry;
            int backlog;
        } listen;

        struct {
            fd_entry* entry;
            struct sockaddr *addr;
            socklen_t *addrlen;
        } accept;

        struct {
            fd_entry* entry;
            struct sockaddr *addr;
            socklen_t *addrlen;
        } getsockname;

        struct {
            fd_entry* entry;
            struct sockaddr *addr;
            socklen_t *addrlen;
        } getpeername;

        struct {
            fd_entry* entry;
        } close;

        struct {
            fd_entry* entry;
            int how;
        } shutdown;

        struct {
            fd_entry* entry;
            int level;
            int optname;
            const void* optval;
            socklen_t optlen;
        } setsockopt;

        struct {
            fd_entry* entry;
            int level;
            int optname;
            void* optval;
            socklen_t* optlen;
        } getsockopt;

        struct {
            fd_entry* entry;
            void (*poll_cb)(Socket* sock, uint32_t event, void* argv);
            void* cb_argv;
        } poll;

#ifdef TEST_EPOLL
        struct {
            fd_entry* entry;       /* socket fd_entry (for worker routing) */
            fd_entry* ep_entry;    /* epoll fd_entry */
            int       op;
            struct epoll_event event;
        } epoll_ctl;
#endif

        struct {
            fd_entry* entry;
            int cmd;
            int arg;
        } fcntl;

        struct {
            void* argv;
            int (*cb)(void*);
        } worker_req;

    } argv;
} req;


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
 *   req_fill(&r, REQ_ACCEPT, accept, .entry = e, .addr = a, .addrlen = al);
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
int net_write(int fd, const void* buf, uint32_t len);
int net_read(int fd, void* buf, uint32_t len);
int net_setsockopt(int fd, int level, int optname,
                   const void* optval, socklen_t optlen);
int net_getsockopt(int fd, int level, int optname,
                   void* optval, socklen_t* optlen);
int net_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int net_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);
int net_fcntl(int fd, int cmd, ...);
int net_sendto(int fd, const void* buf, uint32_t len, int flags,
                   const struct sockaddr* dest_addr, socklen_t addrlen);
int net_recvfrom(int fd, void* buf, uint32_t len, int flags,
                     struct sockaddr* src_addr, socklen_t* addrlen);
int net_close(int fd);
int net_shutdown(int fd, int how);
int net_listen(int fd, int backlog);
int net_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
#endif
