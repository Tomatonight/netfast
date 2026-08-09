#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "req.h"
#include "req_async.h"
#include "req_epoll.h"
#include "req_socket.h"
#include "fd_entry.h"
#include "log.h"
#include "worker.h"

req* req_create(void)
{
    req* r = calloc(1, sizeof(req));
    if (!r) return NULL;
    spin_lock_init(&r->done_mtx);
    pthread_mutex_init(&r->done_wait_mtx, NULL);
    pthread_cond_init(&r->done_cv, NULL);
    r->status = REQ_IN_PROGRESS;
    r->saved_errno = 0;
    return r;
}

void req_init(req* r)
{
    memset(r, 0, sizeof(req));
    spin_lock_init(&r->done_mtx);
    pthread_mutex_init(&r->done_wait_mtx, NULL);
    pthread_cond_init(&r->done_cv, NULL);
    r->status = REQ_IN_PROGRESS;

}

int req_push_wait(worker* w, req* r)
{
    if (!w) {
        errno = EBADF;
        if (r)
            r->saved_errno = EBADF;
        return -1;
    }

    bool no_wait = r->flag.no_wait;
    r->worker = w;

    if (!no_wait)
        pthread_mutex_lock(&r->done_wait_mtx);
    notify_queue_push(&w->stack.req_msg, &r->node);
    if (!no_wait) {
        while (!r->done)
            pthread_cond_wait(&r->done_cv, &r->done_wait_mtx);
        pthread_mutex_unlock(&r->done_wait_mtx);
        pthread_cond_destroy(&r->done_cv);
        pthread_mutex_destroy(&r->done_wait_mtx);
        (void)pthread_spin_destroy(&r->done_mtx);
    }

    /* An asynchronous request may already have been completed and freed by
     * its worker.  Do not dereference it after publishing the queue node. */
    if (no_wait)
        return 0;

    if (r->saved_errno != 0) {
        errno = r->saved_errno;
    } else if (r->ret == -1) {
        /* Never expose a stale errno when a worker forgot to provide one. */
        errno = EIO;
    }

    return r->ret;
}

/* net_* wrappers dispatch virtual descriptors through fd_entry_ops. */

int net_socket(int family, int type, int protocol)
{
    return socket_req(family, type, protocol);
}

int net_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->bind) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->bind(entry, addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->connect) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->connect(entry, addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_write(int fd, const void *buf, uint32_t len)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->write) {
        errno = entry ? EINVAL : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->write(entry, buf, len);
    PUT_REF(entry);
    return ret;
}

int net_read(int fd, void *buf, uint32_t len)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->read) {
        errno = entry ? EINVAL : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->read(entry, buf, len);
    PUT_REF(entry);
    return ret;
}

int net_sendto(int fd, const void *buf, uint32_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->sendto) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->sendto(entry, buf, len, flags,
                                     dest_addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_recvfrom(int fd, void *buf, uint32_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->recvfrom) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->recvfrom(entry, buf, len, flags,
                                       src_addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->getsockname) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->getsockname(entry, addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->getpeername) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->getpeername(entry, addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_setsockopt(int fd, int level, int optname,
                   const void *optval, socklen_t optlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->setsockopt) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->setsockopt(entry, level, optname, optval, optlen);
    PUT_REF(entry);
    return ret;
}

int net_getsockopt(int fd, int level, int optname,
                   void *optval, socklen_t *optlen)
{
    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->getsockopt) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->getsockopt(entry, level, optname, optval, optlen);
    PUT_REF(entry);
    return ret;
}

int net_fcntl(int fd, int cmd, ...)
{

    int arg = 0;
    if (cmd == F_SETFL || cmd == F_SETFD) {
        va_list ap;
        va_start(ap, cmd);
        arg = va_arg(ap, int);
        va_end(ap);
    }

    fd_entry *entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->fcntl) {
        errno = entry ? EINVAL : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->fcntl(entry, cmd, arg);
    PUT_REF(entry);
    return ret;
}

int net_close(int fd)
{
    fd_entry* entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->close) {
        PUT_REF(entry);
        errno = EBADF;
        return -1;
    }
    int ret = entry->ops->close(entry);
    PUT_REF(entry);
    return ret;
}

int net_shutdown(int fd, int how)
{
    fd_entry* entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->shutdown) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->shutdown(entry, how);
    PUT_REF(entry);
    return ret;
}

int net_listen(int fd, int backlog)
{
    fd_entry* entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->listen) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->listen(entry, backlog);
    PUT_REF(entry);
    return ret;
}

int net_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    fd_entry* entry = hold_fd_entry(fd);
    if (!entry || !entry->ops->accept) {
        errno = entry ? ENOTSOCK : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->accept(entry, addr, addrlen);
    PUT_REF(entry);
    return ret;
}

int net_epoll_create(void)
{
    return req_epoll_create();
}

int net_epoll_ctl(int epfd, int op, int sockfd, struct epoll_event *event)
{
    fd_entry *entry = hold_fd_entry(epfd);
    if (!entry || !entry->ops->epoll_ctl) {
        errno = entry ? EINVAL : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->epoll_ctl(entry, op, sockfd, event);
    PUT_REF(entry);
    return ret;
}

int net_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                   int timeout_ms)
{
    fd_entry *entry = hold_fd_entry(epfd);
    if (!entry || !entry->ops->epoll_wait) {
        errno = entry ? EINVAL : EBADF;
        PUT_REF(entry);
        return -1;
    }
    int ret = entry->ops->epoll_wait(entry, events, maxevents, timeout_ms);
    PUT_REF(entry);
    return ret;
}

void req_notify(req* r, int ret)
{
    bool notify_free;
    bool async;
    bool wake_waiter = !r->flag.no_wait;
    async_cq* cq = NULL;
    fd_entry* async_entry = NULL;

    if (wake_waiter)
        pthread_mutex_lock(&r->done_wait_mtx);
    spin_lock(&r->done_mtx);
    if (r->done) {
        spin_unlock(&r->done_mtx);
        if (wake_waiter)
            pthread_mutex_unlock(&r->done_wait_mtx);
        return;
    }
    r->ret = ret;
    if (LIST_ATTACHED(&r->pn.node))
        remove_list_node(&r->pn.node);
    destroy_task(r->timeout_task);
    r->timeout_task = NULL;
    r->status = REQ_COMPLETED;
    r->done = 1;
    notify_free = r->flag.notify_free;
    async = r->async.cq != NULL;
    if (async) {
        cq = r->async.cq;
        async_entry = r->async.entry;
        r->async.entry = NULL;
    }
    if (wake_waiter)
        pthread_cond_signal(&r->done_cv);
    spin_unlock(&r->done_mtx);
    if (wake_waiter)
        pthread_mutex_unlock(&r->done_wait_mtx);

    /* async path: push to completion queue instead of signalling cv */
    if (async) {
        /* The worker is finished with the target object.  Drop the request's
         * fd_entry hold before publishing the CQ node; after mpscq_push(), a
         * consumer may immediately dequeue and destroy the request. */
        PUT_REF(async_entry);

        /* Publish all metadata before the node.  Once mpscq_push() returns,
         * a waiter may dequeue and destroy r immediately. */
        /* Reserve the count before publishing the node so a consumer can
         * never dequeue it before complete_count accounts for it. */
        unsigned int queued = atomic_fetch_add_explicit(
            &cq->complete_count, 1, memory_order_seq_cst) + 1;
        mpscq_push(&cq->completions.q, &r->async.completion_node);

        unsigned int need = atomic_load_explicit(&cq->wait_need,
                                                  memory_order_acquire);
        if (need != UINT_MAX && queued >= need)
            notify_queue_notify(&cq->completions);
        return;
    }

    if (notify_free) {
        pthread_cond_destroy(&r->done_cv);
        pthread_mutex_destroy(&r->done_wait_mtx);
        (void)pthread_spin_destroy(&r->done_mtx);
        free(r);
    }
}
