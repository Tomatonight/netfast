#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "base.h"
#include "queue.h"
#include "hash.h"
#include "fd_entry.h"
#include "req_epoll.h"
#include "req.h"
#include "req_socket.h"
#include "socket.h"

#ifdef TEST_EPOLL

static void destroy_net_epoll(net_epoll* ep);

static void destroy_net_epoll_item(net_epoll_item* item)
{
    net_epoll* ep = item->ep;
    assert(!LIST_ATTACHED(&item->ready_list));
    item->ep = NULL;
    free(item);
    PUT_REF(ep);
}

static inline uint32_t epoll_interest(uint32_t watched)
{
    /* Linux reports EPOLLERR/EPOLLHUP even when they were not requested. */
    return watched | EPOLLERR | EPOLLHUP;
}

/* ready_lock must be held.  Returns true when a waiter should be woken. */
static bool epoll_update_ready_locked(net_epoll_item* item, uint32_t events,
                                      bool merge)
{
    net_epoll* ep = item->ep;
    uint32_t old = item->ready_events.events;
    uint32_t ready = events & epoll_interest(item->watching_events.events);
    if (merge)
        ready |= old;
    item->ready_events.events = ready;

    if (ready) {
        bool attached = LIST_ATTACHED(&item->ready_list);
        if (!attached)
            add_list_node(&ep->ready_items, &item->ready_list);
        return !attached || ready != old;
    }

    if (LIST_ATTACHED(&item->ready_list))
        remove_list_node(&item->ready_list);

    return false;
}

static void epoll_update_ready(net_epoll_item* item, uint32_t events,
                               bool merge)
{
    net_epoll* ep = item->ep;
    spin_lock(&ep->ready_lock);
    bool wake = epoll_update_ready_locked(item, events, merge);
    spin_unlock(&ep->ready_lock);

    if (wake)
        notify_queue_notify(&ep->ready_q);
}

void epoll_item_unregister(net_epoll_item* item)
{
    net_epoll* ep = item->ep;
    spin_lock(&ep->ready_lock);
    atomic_store_explicit(&item->ref.useful, false, memory_order_release);
    (void)epoll_update_ready_locked(item, 0, false);
    spin_unlock(&ep->ready_lock);
    PUT_REF(item);
}

void epoll_poll_complete(Socket* sock, uint32_t event, void* argv)
{
    (void)sock;
    net_epoll_item* item = (net_epoll_item*)argv;
    net_epoll* ep = item->ep;

    spin_lock(&ep->ready_lock);
    uint32_t ready = (item->watching_events.events & EPOLLET) ? 0 : event;
    bool wake = epoll_update_ready_locked(item, ready, false);
    spin_unlock(&ep->ready_lock);

    if (wake)
        notify_queue_notify(&ep->ready_q);
}

static uint32_t epoll_notify_hint(enum notify_event event)
{
    uint32_t hint = 0;
    if (event & notify_data_read)      hint |= EPOLLIN;
    if (event & notify_data_write)     hint |= EPOLLOUT;
    if (event & notify_new_connection) hint |= EPOLLIN;
    if (event & notify_err)            hint |= EPOLLERR | EPOLLHUP;
    if (event & notify_recv_fin)       hint |= EPOLLIN | EPOLLRDHUP | EPOLLHUP;
    return hint;
}

void epoll_pending_cb(Socket* sock, void* value, enum notify_event event)
{
    net_epoll_item* item = (net_epoll_item*)value;
    uint32_t ready = epoll_notify_hint(event) & sock->protocol_ops->poll(sock);
    epoll_update_ready(item, ready, true);
}

/* ── epoll fd_entry_ops ── */
const fd_entry_ops epoll_fd_ops = {
    .epoll_create = req_epoll_create,
    .epoll_ctl    = req_epoll_ctl,
    .epoll_wait   = req_epoll_wait,
    .close        = req_epoll_close,
};

int req_epoll_create(void)
{
    CREATE_REF(net_epoll, ep, destroy_net_epoll);
    if (!ep) {
        errno = ENOMEM;
        return -1;
    }
    ep->ready_q.efd = -1;
    spin_lock_init(&ep->ready_lock);

    ep->registered_sockfds = hash_create_safe(1024,
        HASH_KEY_OFFSET(net_epoll_item, hash_node, sockfd), sizeof(int));
    if (!ep->registered_sockfds) {
        errno = ENOMEM;
        PUT_REF(ep);
        return -1;
    }

    if (notify_queue_init(&ep->ready_q) < 0) {
        if (errno == 0)
            errno = EIO;
        PUT_REF(ep);
        return -1;
    }

    fd_entry* entry = alloc_fd_entry_with_worker(ep, &epoll_fd_ops, NULL);
    if (!entry) {
        errno = EMFILE;
        PUT_REF(ep);
        return -1;
    }
    return entry->fd;
}

int req_epoll_close(fd_entry* entry)
{
    int ret = -1;
    int* sockfds = NULL;
    uint32_t sockfd_count = 0;

    mutex_lock(&entry->mtx);
    net_epoll* ep = (net_epoll*)entry->value;
    if (!ep) {
        errno = EBADF;
        mutex_unlock(&entry->mtx);
        return -1;
    }
    hash* h = ep->registered_sockfds;
    if (!h) {
        errno = EIO;
        goto exit;
    }
    for (uint32_t i = 0; i < h->size; i++) {
        HASH_BUCKET_RDLOCK(h, i);
        for (hash_node* node = h->buckets[i]; node; node = node->next)
            sockfd_count++;
        HASH_BUCKET_UNLOCK(h, i);
    }

    if (sockfd_count) {
        sockfds = (int*)calloc(sockfd_count, sizeof(*sockfds));
        if (!sockfds) {
            errno = ENOMEM;
            goto exit;
        }

        uint32_t n = 0;
        for (uint32_t i = 0; i < h->size && n < sockfd_count; i++) {
            HASH_BUCKET_RDLOCK(h, i);
            for (hash_node* node = h->buckets[i];
                 node && n < sockfd_count; node = node->next) {
                net_epoll_item* item = HASH_CONTAINER_OF(
                    node, net_epoll_item, hash_node);
                sockfds[n++] = item->sockfd;
            }
            HASH_BUCKET_UNLOCK(h, i);
        }
        sockfd_count = n;
    }

    for (uint32_t i = 0; i < sockfd_count; i++) {
        int sockfd = sockfds[i];

        fd_entry* se = hold_fd_entry(sockfd);
        if (se && se->value) {
            worker* w = fd_entry_get_worker(se);
            if (w) {
                req r;
                req_init(&r);
                req_fill(&r, REQ_EPOLL_CTL, epoll_ctl,
                    .entry = se, .ep_entry = entry,
                    .op = EPOLL_CTL_DEL);
                req_push_wait(w, &r);
            }
        }
        PUT_REF(se);
    }

    entry->value = NULL;
    notify_queue_notify(&ep->ready_q);

    ret = 0;
    PUT_REF(ep);

exit:
    free(sockfds);
    mutex_unlock(&entry->mtx);
    if (ret == 0)
        PUT_REF(entry); /* release the fd table's ownership */
    return ret;
}

int req_epoll_ctl(fd_entry* entry, int op, int sockfd, struct epoll_event* event)
{
    fd_entry* se = NULL;
    worker* w;
    int ret = -1;

    if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD && op != EPOLL_CTL_DEL) {
        errno = EINVAL;
        return -1;
    }

    if (sockfd < 0) {
        errno = EBADF;
        return -1;
    }

    if (op != EPOLL_CTL_DEL) {
        if (!event) {
            errno = EFAULT;
            return -1;
        }
        if (event->events & (EPOLLONESHOT | EPOLLEXCLUSIVE)) {
            errno = EOPNOTSUPP;
            return -1;
        }
    }
    if (entry->fd == sockfd) {
        errno = EINVAL;
        return -1;
    }

    mutex_lock(&entry->mtx);
    net_epoll* ep = (net_epoll*)entry->value;
    if (!ep) {
        errno = EBADF;
        goto exit;
    }

    se = hold_fd_entry(sockfd);
    if (!se) {
        errno = EBADF;
        goto exit;
    }
    if (se->ops != &socket_fd_ops || !se->value) {
        errno = EPERM;
        goto exit;
    }
    w = fd_entry_get_worker(se);
    if (!w) {
        errno = EBADF;
        goto exit;
    }

    req r;
    req_init(&r);
    req_fill(&r, REQ_EPOLL_CTL, epoll_ctl,
        .entry = se, .ep_entry = entry, .op = op);
    if (event)
        r.argv.epoll_ctl.event = *event;

    ret = req_push_wait(w, &r);

exit:
    PUT_REF(se);
    mutex_unlock(&entry->mtx);
    return ret;
}

static int epoll_ctl_add(Socket* sock, net_epoll* ep, int sockfd,
                         const struct epoll_event* event)
{
    CREATE_REF(net_epoll_item, item, destroy_net_epoll_item);
    if (!item)
        return ENOMEM;

    item->ep = ep;
    INC_REF(ep);
    item->sockfd = sockfd;
    item->watching_events = *event;
    item->node.value = item;
    item->node.cb = epoll_pending_cb;

    if (!hash_add_node(ep->registered_sockfds, &item->hash_node)) {
        DESTROY_REF(item);
        return EEXIST;
    }

    add_list_node(&sock->pending, &item->node.node);
    epoll_update_ready(item, sock->protocol_ops->poll(sock), false);
    return 0;
}

static net_epoll_item* epoll_find_item(net_epoll* ep, int sockfd)
{
    hash* h = ep->registered_sockfds;
    uint32_t value = general_hash_algorithm((const uint8_t*)&sockfd,
                                            h->key_len);
    uint32_t index = hash_bucket_index(h, value);

    HASH_BUCKET_RDLOCK(h, index);
    hash_node* node = hash_find_node_locked(h, index, &sockfd, value);
    net_epoll_item* item = node
        ? HASH_CONTAINER_OF(node, net_epoll_item, hash_node) : NULL;
    if (item)
        INC_REF(item);
    HASH_BUCKET_UNLOCK(h, index);
    return item;
}

static int epoll_ctl_mod(Socket* sock, net_epoll* ep, int sockfd,
                         const struct epoll_event* event)
{
    net_epoll_item* item = epoll_find_item(ep, sockfd);
    if (!item)
        return ENOENT;

    spin_lock(&ep->ready_lock);
    item->watching_events = *event;
    uint32_t interest = epoll_interest(event->events);
    spin_unlock(&ep->ready_lock);

    uint32_t ready = sock->protocol_ops->poll(sock);
    /* Do not let a stale zero result erase a concurrent ready notification. */
    if (ready & interest)
        epoll_update_ready(item, ready, false);

    PUT_REF(item);
    return 0;
}

static int epoll_ctl_del(net_epoll* ep, int sockfd)
{
    hash_node* node = hash_del_key(ep->registered_sockfds, &sockfd);
    net_epoll_item* item = node
        ? HASH_CONTAINER_OF(node, net_epoll_item, hash_node) : NULL;
    if (!item)
        return ENOENT;

    remove_list_node(&item->node.node);
    epoll_item_unregister(item);
    return 0;
}

/* ── worker-side handler for REQ_EPOLL_CTL ── */
void _epoll_ctl(req* r)
{
    fd_entry* se = r->argv.epoll_ctl.entry;
    net_epoll* ep = (net_epoll*)r->argv.epoll_ctl.ep_entry->value;
    Socket* sock = (Socket*)se->value;
    int error;

    if (!sock || !ep) {
        error = EBADF;
    } else {
        switch (r->argv.epoll_ctl.op) {
        case EPOLL_CTL_ADD:
            error = epoll_ctl_add(sock, ep, se->fd,
                                  &r->argv.epoll_ctl.event);
            break;
        case EPOLL_CTL_MOD:
            error = epoll_ctl_mod(sock, ep, se->fd,
                                  &r->argv.epoll_ctl.event);
            break;
        case EPOLL_CTL_DEL:
            error = epoll_ctl_del(ep, se->fd);
            break;
        default:
            error = EINVAL;
            break;
        }
    }

    req_notify(r, -error);
}

typedef struct epoll_snapshot {
    int sockfd;
    net_epoll_item* item;
    struct epoll_event watched;
    uint32_t queued_events;
} epoll_snapshot;

static int epoll_take_snapshot(net_epoll* ep, epoll_snapshot** snapshots,
                               size_t* capacity, size_t* count)
{
    size_t ready_count = 0;

    spin_lock(&ep->ready_lock);
    for (list_node* node = ep->ready_items.next; node; node = node->next)
        ready_count++;
    spin_unlock(&ep->ready_lock);

    if (ready_count > *capacity) {
        if (ready_count > SIZE_MAX / sizeof(**snapshots)) {
            errno = ENOMEM;
            return -1;
        }
        void* resized = realloc(*snapshots, ready_count * sizeof(**snapshots));
        if (!resized) {
            errno = ENOMEM;
            return -1;
        }
        *snapshots = (epoll_snapshot*)resized;
        *capacity = ready_count;
    }

    *count = 0;
    if (!*capacity)
        return 0;

    spin_lock(&ep->ready_lock);
    net_epoll_item* item;
    list_node* next;
    FOR_EACH_LIST_SAFE_OFFSET(&ep->ready_items, item, next,
                              net_epoll_item, ready_list) {
        if (*count == *capacity)
            break;
        INC_REF(item);
        epoll_snapshot* snapshot = &(*snapshots)[(*count)++];
        snapshot->sockfd = item->sockfd;
        snapshot->item = item;
        snapshot->watched = item->watching_events;
        snapshot->queued_events = item->ready_events.events;
        item->ready_events.events = 0;
        remove_list_node(&item->ready_list);
    }
    spin_unlock(&ep->ready_lock);
    return 0;
}

static void epoll_restore_snapshot(net_epoll* ep, epoll_snapshot* snapshots,
                                   size_t first, size_t count)
{
    if (first == count)
        return;

    bool wake = false;
    spin_lock(&ep->ready_lock);
    for (size_t i = count; i-- > first;) {
        net_epoll_item* item = snapshots[i].item;
        if (!REF_USABLE(item))
            continue;

        item->ready_events.events |= snapshots[i].queued_events;
        if (item->ready_events.events &&
            !LIST_ATTACHED(&item->ready_list)) {
            add_list_node(&ep->ready_items, &item->ready_list);
            wake = true;
        }
    }
    spin_unlock(&ep->ready_lock);

    for (size_t i = first; i < count; i++) {
        PUT_REF(snapshots[i].item);
        snapshots[i].item = NULL;
    }

    if (wake)
        notify_queue_notify(&ep->ready_q);
}

int req_epoll_wait(fd_entry* entry, struct epoll_event* events, int maxevents,
                   int timeout_ms)
{
    int ret = -1;
    int saved_errno;
    epoll_snapshot* snapshots = NULL;
    size_t snap_capacity = 0;
    bool finite_timeout = timeout_ms >= 0;
    uint64_t deadline = 0;
    int poll_timeout = timeout_ms;

    if (!events) {
        errno = EFAULT;
        return -1;
    }
    if (maxevents <= 0) {
        errno = EINVAL;
        return -1;
    }

    if (finite_timeout) {
        uint64_t now = read_now_ms();
        deadline = now + (uint64_t)timeout_ms;
        if (deadline < now)
            deadline = UINT64_MAX;
    }

    mutex_lock(&entry->mtx);

    net_epoll* ep = (net_epoll*)entry->value;
    if (!ep) {
        errno = EBADF;
        mutex_unlock(&entry->mtx);
        return -1;
    }
    /* req_epoll_close() may run while wait sleeps with entry->mtx released.
     * Keep the epoll object, and especially ready_q.efd, alive until wait has
     * reacquired the mutex and observed whether the fd was closed. */
    INC_REF(ep);

    int count = 0;

    for (;;) {
        size_t snap_count = 0;
        if (epoll_take_snapshot(ep, &snapshots, &snap_capacity,
                                &snap_count) < 0)
            goto exit;

        size_t processed = 0;
        for (; processed < snap_count && count < maxevents; processed++) {
            epoll_snapshot* snapshot = &snapshots[processed];
            net_epoll_item* item = snapshot->item;
            fd_entry* se = hold_fd_entry(snapshot->sockfd);
            worker* w = NULL;
            if (se && se->ops == &socket_fd_ops && REF_USABLE(item))
                w = fd_entry_get_worker(se);

            uint32_t mask = 0;
            if (w) {
                req poll_req;
                req_init(&poll_req);
                req_fill(&poll_req, REQ_POLL, poll,
                    .entry = se, .poll_cb = epoll_poll_complete,
                    .cb_argv = item);
                int poll_ret = req_push_wait(w, &poll_req);
                if (poll_ret > 0)
                    mask = (uint32_t)poll_ret &
                           epoll_interest(snapshot->watched.events);
            }
            PUT_REF(se);

            if (mask) {
                events[count].events = mask;
                events[count].data = snapshot->watched.data;
                count++;
            }

            PUT_REF(item);
            snapshot->item = NULL;
        }

        /* Candidates beyond maxevents were detached with the snapshot.  Put
         * them back in reverse snapshot order so the next call starts after
         * the item just delivered (Linux-style round-robin fairness). */
        epoll_restore_snapshot(ep, snapshots, processed, snap_count);

        if (count > 0) {
            ret = count;
            goto exit;
        }

        struct pollfd pfd;
        pfd.fd = ep->ready_q.efd;
        pfd.events = POLLIN | POLLERR | POLLHUP;
        pfd.revents = 0;

        if (finite_timeout) {
            uint64_t now = read_now_ms();
            if (now >= deadline) {
                ret = 0;
                goto exit;
            }
            uint64_t remaining = deadline - now;
            poll_timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        }

        mutex_unlock(&entry->mtx);
        ret = poll(&pfd, 1, poll_timeout);
        mutex_lock(&entry->mtx);

        if (entry->value != ep) {
            errno = EBADF;
            ret = -1;
            goto exit;
        }
        if (ret <= 0)
            goto exit;

        notify_queue_drain(&ep->ready_q);
    }

exit:
    saved_errno = errno;
    free(snapshots);
    mutex_unlock(&entry->mtx);
    PUT_REF(ep);
    errno = saved_errno;
    return ret;
}

static void destroy_net_epoll(net_epoll* ep)
{
    assert(hash_is_empty(ep->registered_sockfds));
    assert(ep->ready_items.next == NULL);

    hash_destroy(ep->registered_sockfds);
    notify_queue_close(&ep->ready_q);
    (void)pthread_spin_destroy(&ep->ready_lock);

    free(ep);
}

#endif /* TEST_EPOLL */
