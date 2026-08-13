#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "req_async.h"
#include "fd_entry.h"
#include "stack.h"
#include "worker.h"
#include "netfast.h"

_Static_assert((int)NET_ASYNC_SOCKET == (int)REQ_SOCKET &&
               (int)NET_ASYNC_FCNTL == (int)REQ_FCNTL,
               "public async operations must match internal request types");

typedef struct async_waiter {
    struct async_waiter* next;
    uint32_t need;
} async_waiter;

static void async_waiter_add(async_cq* cq, async_waiter* waiter)
{
    waiter->next = cq->waiters;
    cq->waiters = waiter;

    unsigned int need = atomic_load_explicit(&cq->wait_need,
                                              memory_order_relaxed);
    if (waiter->need < need)
        atomic_store_explicit(&cq->wait_need, waiter->need,
                              memory_order_release);
}

static void async_waiter_remove(async_cq* cq, async_waiter* waiter)
{
    async_waiter** link = &cq->waiters;
    while (*link != waiter) {
        assert(*link);
        link = &(*link)->next;
    }
    *link = waiter->next;
    waiter->next = NULL;

    unsigned int need = UINT_MAX;
    for (async_waiter* it = cq->waiters; it; it = it->next)
        need = min(need, it->need);
    atomic_store_explicit(&cq->wait_need, need, memory_order_release);
}

static void async_notify_ready_waiters(async_cq* cq)
{
    unsigned int need = atomic_load_explicit(&cq->wait_need,
                                              memory_order_acquire);
    if (need != UINT_MAX &&
        atomic_load_explicit(&cq->complete_count,
                             memory_order_acquire) >= need)
        notify_queue_notify(&cq->completions);
}

static void async_req_free(req* r)
{
    assert(!r->async.entry);
    pthread_cond_destroy(&r->done_cv);
    pthread_mutex_destroy(&r->done_wait_mtx);
    (void)pthread_spin_destroy(&r->done_mtx);
    free(r);
}

static void destroy_async_cq(async_cq* cq)
{
    assert(!cq->waiters);
    notify_queue_close(&cq->completions);
    mutex_destroy(&cq->waiters_mtx);
    free(cq);
}

static req* async_cq_pop(async_cq* cq)
{
    mpscq_node* node = notify_queue_pop(&cq->completions);
    if (!node)
        return NULL;

    unsigned int old = atomic_fetch_sub_explicit(&cq->complete_count, 1,
                                                  memory_order_seq_cst);
    (void)old;
    assert(old != 0);

    req* r = (req*)((uint8_t*)node - offsetof(req, async.completion_node));
    assert(LIST_ATTACHED(&r->async.submit_node));
    remove_list_node(&r->async.submit_node);

    spin_lock(&r->done_mtx);
    r->async.cq = NULL;
    spin_unlock(&r->done_mtx);
    return r;
}

static int async_submit_batch(fd_entry* entry, req** reqs, uint32_t count);
static int async_wait(fd_entry* entry, req** reqs, uint32_t min,
                      uint32_t max, int total_timeout_ms);
static int async_close(fd_entry* entry);

static const fd_entry_ops async_fd_ops = {
    .close = async_close,
};

int net_async_create(void)
{
    CREATE_REF(async_cq, cq, destroy_async_cq);
    if (!cq) {
        errno = ENOMEM;
        return -1;
    }

    cq->completions.efd = -1;
    atomic_init(&cq->complete_count, 0);
    atomic_init(&cq->wait_need, UINT_MAX);
    mutex_init(&cq->waiters_mtx);
    if (notify_queue_init(&cq->completions) < 0) {
        if (errno == 0)
            errno = EIO;
        PUT_REF(cq);
        return -1;
    }

    fd_entry* entry = alloc_fd_entry_with_worker(cq, &async_fd_ops, NULL);
    if (!entry) {
        errno = EMFILE;
        PUT_REF(cq);
        return -1;
    }
    return entry->fd;
}

static int async_submit_one(async_cq* cq, req* r, uint64_t* worker_mask)
{
    if (!r) {
        errno = EINVAL;
        return -1;
    }

    spin_lock(&r->done_mtx);
    if (r->done || r->async.cq) {
        spin_unlock(&r->done_mtx);
        errno = EBUSY;
        return -1;
    }

    worker* aim_worker;
    if (r->type == REQ_SOCKET) {
        aim_worker = random_worker();
    } else if (r->async.entry) {
        aim_worker = fd_entry_get_worker(r->async.entry);
    } else {
        aim_worker = NULL;
    }
    if (!aim_worker) {
        spin_unlock(&r->done_mtx);
        errno = EBADF;
        return -1;
    }

    assert(!LIST_ATTACHED(&r->async.submit_node));
    add_list_node(&cq->submit_reqs, &r->async.submit_node);
    r->flag.no_wait = 1;
    r->async.cq = cq;
    r->worker = aim_worker;
    mpscq_push(&aim_worker->stack.req_msg.q, &r->node);
    *worker_mask |= UINT64_C(1) << (uint32_t)(aim_worker - g_workers);
    spin_unlock(&r->done_mtx);
    return 0;
}

static int async_submit_batch(fd_entry* entry, req** reqs, uint32_t count)
{
    if (!reqs || count == 0 || count > INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    mutex_lock(&entry->mtx);
    async_cq* cq = (async_cq*)entry->value;
    if (!cq) {
        mutex_unlock(&entry->mtx);
        errno = EBADF;
        return -1;
    }

    uint64_t worker_mask = 0;
    uint32_t submitted = 0;
    while (submitted < count &&
           async_submit_one(cq, reqs[submitted], &worker_mask) == 0) {
        submitted++;
    }

    for (int i = 0; i < g_worker_num; i++) {
        if (worker_mask & (UINT64_C(1) << (uint32_t)i))
            notify_queue_notify(&g_workers[i].stack.req_msg);
    }
    mutex_unlock(&entry->mtx);
    return submitted ? (int)submitted : -1;
}

static uint64_t async_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
           (uint64_t)ts.tv_nsec;
}

static uint64_t async_add_ns(uint64_t now, uint64_t delta)
{
    return UINT64_MAX - now < delta ? UINT64_MAX : now + delta;
}

static int async_wait(fd_entry* entry, req** reqs, uint32_t min,
                      uint32_t max, int total_timeout_ms)
{
    if (!reqs || min == 0 || max < min || max > INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    int count = 0;
    int saved_errno = 0;
    uint64_t now = async_now_ns();
    uint64_t total_deadline = total_timeout_ms >= 0
        ? async_add_ns(now, (uint64_t)total_timeout_ms * UINT64_C(1000000))
        : UINT64_MAX;

    mutex_lock(&entry->mtx);
    async_cq* cq = (async_cq*)entry->value;
    if (!cq) {
        mutex_unlock(&entry->mtx);
        errno = EBADF;
        return -1;
    }

    INC_REF(cq);
    for (;;) {
        while ((uint32_t)count < max) {
            req* r = async_cq_pop(cq);
            if (!r)
                break;
            reqs[count++] = r;
        }

        if ((uint32_t)count >= min)
            break;

        now = async_now_ns();
        if (now >= total_deadline)
            break;

        async_waiter waiter = {
            .need = min - (uint32_t)count,
        };
        mutex_lock(&cq->waiters_mtx);
        async_waiter_add(cq, &waiter);

        /* The producer increments complete_count before publishing its queue
         * node.  Recheck after arming so a completion cannot fall between the
         * empty check and poll(). */
        if (atomic_load_explicit(&cq->complete_count,
                                 memory_order_acquire) >= waiter.need) {
            async_waiter_remove(cq, &waiter);
            mutex_unlock(&cq->waiters_mtx);
            continue;
        }
        mutex_unlock(&cq->waiters_mtx);

        struct timespec timeout;
        struct timespec* timeout_ptr = NULL;
        if (total_deadline != UINT64_MAX) {
            now = async_now_ns();
            uint64_t remaining = total_deadline > now
                ? total_deadline - now : 0;
            timeout.tv_sec = (time_t)(remaining / UINT64_C(1000000000));
            timeout.tv_nsec = (long)(remaining % UINT64_C(1000000000));
            timeout_ptr = &timeout;
        }

        struct pollfd pfd = {
            .fd = cq->completions.efd,
            .events = POLLIN | POLLERR | POLLHUP,
            .revents = 0,
        };
        mutex_unlock(&entry->mtx);
        int poll_ret = ppoll(&pfd, 1, timeout_ptr, NULL);
        int poll_errno = errno;
        mutex_lock(&entry->mtx);

        if (poll_ret > 0)
            notify_queue_drain(&cq->completions);
        mutex_lock(&cq->waiters_mtx);
        async_waiter_remove(cq, &waiter);
        mutex_unlock(&cq->waiters_mtx);
        async_notify_ready_waiters(cq);

        if (entry->value != cq) {
            if (count == 0) {
                count = -1;
                saved_errno = EBADF;
            }
            break;
        }
        if (poll_ret < 0) {
            saved_errno = poll_errno;
            if (count == 0)
                count = -1;
            break;
        }
    }

    mutex_unlock(&entry->mtx);
    PUT_REF(cq); /* wait reference: keeps eventfd alive across poll() */
    if (count < 0)
        errno = saved_errno ? saved_errno : EIO;
    return count;
}

static int cancel_worker_reqs(void* argv)
{
    async_cq* cq = (async_cq*)argv;
    req* r;

    FOR_EACH_LIST_OFFSET(&cq->submit_reqs, r, req, async.submit_node) {
        if (r->worker != get_current_worker())
            continue;

        spin_lock(&r->done_mtx);
        bool cancel = !r->done;
        if (cancel)
            r->flag.async_cancel = 1;
        spin_unlock(&r->done_mtx);

        if (cancel)
            process_request(r);
    }
    return 0;
}

static int async_close(fd_entry* entry)
{
    mutex_lock(&entry->mtx);
    async_cq* cq = (async_cq*)entry->value;
    if (!cq) {
        mutex_unlock(&entry->mtx);
        errno = EBADF;
        return -1;
    }

    entry->value = NULL;
    notify_queue_notify(&cq->completions);

    /* Each socket request is owned by exactly one worker.  Synchronously
     * enqueue cancellation behind its current work, so it cannot race that
     * worker's request/timer processing. */
    bool all_done;
    do {
        for (int i = 0; i < g_worker_num; i++)
            submit_req_2_worker(&g_workers[i], cq, cancel_worker_reqs, true);

        /* A request can migrate from a worker visited later in this pass to
         * one visited earlier.  In that case the next pass orders a cancel
         * callback behind it on its new owner. */
        all_done = true;
        req* pending;
        FOR_EACH_LIST_OFFSET(&cq->submit_reqs, pending, req,
                             async.submit_node) {
            spin_lock(&pending->done_mtx);
            bool done = pending->done;
            spin_unlock(&pending->done_mtx);
            if (!done) {
                all_done = false;
                break;
            }
        }
    } while (!all_done);

    req* r;
    while ((r = async_cq_pop(cq)) != NULL)
        async_req_free(r);

    assert(cq->submit_reqs.next == NULL);
    DESTROY_REF(cq); /* release fd entry ownership; wait refs may remain */
    mutex_unlock(&entry->mtx);
    PUT_REF(entry); /* release the fd table's ownership */
    return 0;
}

/* ---- request construction ---- */

static int copy_sockaddr(struct sockaddr_storage* dst,
                         const struct sockaddr* src, socklen_t len)
{
    if (!src) {
        errno = EFAULT;
        return -1;
    }
    if (len < (socklen_t)sizeof(sa_family_t) || len > sizeof(*dst)) {
        errno = EINVAL;
        return -1;
    }
    memset(dst, 0, sizeof(*dst));
    memcpy(dst, src, len);
    return 0;
}

static req* create_async_req_va(int fd, req_type type, va_list ap)
{
    fd_entry* entry = NULL;
    if (type != REQ_SOCKET) {
        entry = hold_fd_entry(fd);
        if (!entry) {
            errno = EBADF;
            return NULL;
        }
    }

    req* r = req_create();
    if (!r) {
        PUT_REF(entry);
        return NULL;
    }
    r->type = type;
    r->async.entry = entry;
    r->async_fd = fd;

    bool valid = true;
    switch (type) {
    case REQ_SOCKET:
        r->argv.Socket.family = va_arg(ap, int);
        r->argv.Socket.type = va_arg(ap, int);
        r->argv.Socket.protocol = va_arg(ap, int);
        break;
    case REQ_BIND: {
        const struct sockaddr* addr = va_arg(ap, const struct sockaddr*);
        socklen_t len = va_arg(ap, socklen_t);
        r->argv.bind.entry = entry;
        r->argv.bind.addrlen = len;
        valid = copy_sockaddr(&r->argv.bind.addr, addr, len) == 0;
        break;
    }
    case REQ_CONNECT: {
        const struct sockaddr* addr = va_arg(ap, const struct sockaddr*);
        socklen_t len = va_arg(ap, socklen_t);
        r->argv.connect.entry = entry;
        r->argv.connect.addrlen = len;
        valid = copy_sockaddr(&r->argv.connect.addr, addr, len) == 0;
        break;
    }
    case REQ_LISTEN:
        r->argv.listen = (typeof(r->argv.listen)){
            .entry = entry, .backlog = va_arg(ap, int)};
        break;
    case REQ_ACCEPT:
        r->argv.accept = (typeof(r->argv.accept)){
            .entry = entry,
            .addr = va_arg(ap, struct sockaddr*),
            .addrlen = va_arg(ap, socklen_t*)};
        break;
    case REQ_WRITE:
        r->argv.write = (typeof(r->argv.write)){
            .entry = entry,
            .buf = va_arg(ap, const void*),
            .len = va_arg(ap, uint32_t)};
        break;
    case REQ_READ:
        r->argv.read = (typeof(r->argv.read)){
            .entry = entry,
            .buf = va_arg(ap, void*),
            .len = va_arg(ap, uint32_t)};
        break;
    case REQ_SENDTO: {
        r->argv.sendto.entry = entry;
        r->argv.sendto.buf = va_arg(ap, const void*);
        r->argv.sendto.len = va_arg(ap, uint32_t);
        r->argv.sendto.flags = va_arg(ap, int);
        const struct sockaddr* addr = va_arg(ap, const struct sockaddr*);
        socklen_t len = va_arg(ap, socklen_t);
        r->argv.sendto.addrlen = len;
        if (addr) {
            r->argv.sendto.has_dest_addr = 1;
            valid = copy_sockaddr(&r->argv.sendto.dest_addr, addr, len) == 0;
        } else if (len != 0) {
            errno = EINVAL;
            valid = false;
        }
        break;
    }
    case REQ_RECVFROM:
        r->argv.recvfrom = (typeof(r->argv.recvfrom)){
            .entry = entry,
            .buf = va_arg(ap, void*),
            .len = va_arg(ap, uint32_t),
            .flags = va_arg(ap, int),
            .src_addr = va_arg(ap, struct sockaddr*),
            .addrlen = va_arg(ap, socklen_t*)};
        break;
    case REQ_GETSOCKNAME:
        r->argv.getsockname = (typeof(r->argv.getsockname)){
            .entry = entry,
            .addr = va_arg(ap, struct sockaddr*),
            .addrlen = va_arg(ap, socklen_t*)};
        break;
    case REQ_GETPEERNAME:
        r->argv.getpeername = (typeof(r->argv.getpeername)){
            .entry = entry,
            .addr = va_arg(ap, struct sockaddr*),
            .addrlen = va_arg(ap, socklen_t*)};
        break;
    case REQ_CLOSE:
        r->argv.close.entry = entry;
        break;
    case REQ_SHUTDOWN:
        r->argv.shutdown = (typeof(r->argv.shutdown)){
            .entry = entry, .how = va_arg(ap, int)};
        break;
    case REQ_SETSOCKOPT:
        r->argv.setsockopt = (typeof(r->argv.setsockopt)){
            .entry = entry,
            .level = va_arg(ap, int),
            .optname = va_arg(ap, int),
            .optval = va_arg(ap, const void*),
            .optlen = va_arg(ap, socklen_t)};
        break;
    case REQ_GETSOCKOPT:
        r->argv.getsockopt = (typeof(r->argv.getsockopt)){
            .entry = entry,
            .level = va_arg(ap, int),
            .optname = va_arg(ap, int),
            .optval = va_arg(ap, void*),
            .optlen = va_arg(ap, socklen_t*)};
        break;
    case REQ_FCNTL:
        r->argv.fcntl = (typeof(r->argv.fcntl)){
            .entry = entry,
            .cmd = va_arg(ap, int),
            .arg = va_arg(ap, int)};
        break;
    case REQ_POLL:
        r->argv.poll.entry = entry;
        r->argv.poll.poll_cb =
            va_arg(ap, void (*)(Socket*, uint32_t, void*));
        r->argv.poll.cb_argv = va_arg(ap, void*);
        break;
    default:
        errno = EINVAL;
        valid = false;
        break;
    }
    if (!valid) {
        int saved_errno = errno;
        net_async_req_destroy(r);
        errno = saved_errno;
        return NULL;
    }
    return r;
}

req* net_async_req_create(int fd, int operation, ...)
{
    va_list ap;
    va_start(ap, operation);
    req* r = create_async_req_va(fd, (req_type)operation, ap);
    va_end(ap);
    return r;
}

void net_async_req_destroy(req* r)
{
    if (!r)
        return;

    spin_lock(&r->done_mtx);
    if (r->async.cq) {
        spin_unlock(&r->done_mtx);
        errno = EBUSY;
        return;
    }
    fd_entry* entry = r->async.entry;
    r->async.entry = NULL;
    spin_unlock(&r->done_mtx);

    PUT_REF(entry); /* release net_async_req_create()'s hold */
    async_req_free(r);
}

int net_async_req_result(const req* r)
{
    if (!r)
        return -EINVAL;

    req* mutable_r = (req*)r;
    spin_lock(&mutable_r->done_mtx);
    bool completed = mutable_r->done && !mutable_r->async.cq;
    int ret = mutable_r->ret;
    spin_unlock(&mutable_r->done_mtx);
    return completed ? ret : -EINVAL;
}

/* ---- public fd-based wrappers ---- */

static fd_entry* hold_async_entry(int fd)
{
    fd_entry* entry = hold_fd_entry(fd);
    if (entry && entry->ops == &async_fd_ops)
        return entry;

    PUT_REF(entry);
    errno = EBADF;
    return NULL;
}

int net_async_submit(int cq_fd, req* r)
{
    fd_entry* entry = hold_async_entry(cq_fd);
    if (!entry)
        return -1;
    int ret = async_submit_batch(entry, &r, 1);
    PUT_REF(entry);
    return ret == 1 ? 0 : -1;
}

int net_async_submit_batch(int cq_fd, req** reqs, uint32_t count)
{
    fd_entry* entry = hold_async_entry(cq_fd);
    if (!entry)
        return -1;
    int ret = async_submit_batch(entry, reqs, count);
    PUT_REF(entry);
    return ret;
}

int net_async_wait(int cq_fd, req** reqs, uint32_t min,
                   uint32_t max, int total_timeout_ms)
{
    fd_entry* entry = hold_async_entry(cq_fd);
    if (!entry)
        return -1;
    int ret = async_wait(entry, reqs, min, max, total_timeout_ms);
    PUT_REF(entry);
    return ret;
}

int net_async_close(int cq_fd)
{
    fd_entry* entry = hold_async_entry(cq_fd);
    if (!entry)
        return -1;
    int ret = async_close(entry);
    PUT_REF(entry);
    return ret;
}
