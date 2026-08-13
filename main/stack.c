#include "stack.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "worker.h"
#include "req.h"
#include "socket.h"
#ifdef TEST_EPOLL
#include "req_epoll.h"
#endif
#include "udp.h"
#include "xdp.h"
#include "fd_entry.h"
#include "base.h"
#include "ip_frag.h"
#include "ipv6_frag.h"
#include "log.h"
#include "skbuff.h"

stack_maps* g_stack_maps;

void process_request(req *r)
{
    if(r->flag.async_cancel){
        req_notify(r, -ECANCELED);
        return;
    }
    fd_entry* sock_entry=get_sock_entry_by_req(r);
    if(sock_entry){
        worker* entry_worker = fd_entry_get_worker(sock_entry);
        if (!entry_worker) {
            req_notify(r, -EBADF);
            return;
        }
        if(entry_worker != get_current_worker()){
            change_req_worker(r, entry_worker);
            return;
        }
    }
    switch (r->type)
    {
    case REQ_SOCKET:
        _socket(r);
        break;
    case REQ_BIND:
        _bind(r);
        break;
    case REQ_CONNECT:
        _connect(r);
        break;
    case REQ_LISTEN:
        _listen(r);
        break;
    case REQ_ACCEPT:
        _accept(r);
        break;
    case REQ_WRITE:
        _write(r);
        break;
    case REQ_READ:
        _read(r);
        break;
    case REQ_SENDTO:
        _sendto(r);
        break;
    case REQ_RECVFROM:
        _recvfrom(r);
        break;
    case REQ_GETSOCKNAME:
        _getsockname(r);
        break;
    case REQ_GETPEERNAME:
        _getpeername(r);
        break;
    case REQ_CLOSE:
        _close(r);
        break;
    case REQ_SHUTDOWN:
        _shutdown(r);
        break;
    case REQ_SETSOCKOPT:
        _setsockopt(r);
        break;
    case REQ_GETSOCKOPT:
        _getsockopt(r);
        break;
    case REQ_FCNTL:
        _fcntl(r);
        break;
    case REQ_POLL:
        _poll(r);
        break;
#ifdef TEST_EPOLL
    case REQ_EPOLL_CTL:
        _epoll_ctl(r);
        break;
#endif
    case REQ_WORKER_REQ:
        process_submit_req(r);
        break;
    default:
        req_notify(r, -EINVAL);
        break;
    }
}

#define REQ_TASK_BUDGET 128u

static void req_task_cb(task *t)
{
    stack_instance *s = (stack_instance *)t->argv;
    notify_queue_drain(&s->req_msg);

    for (uint32_t budget = 0; budget < REQ_TASK_BUDGET; budget++) {
        mpscq_node *n = notify_queue_pop(&s->req_msg);
        if (!n)
            break;

        req *r = (req *)n;
        process_request(r);
    }
    if (!notify_queue_is_empty(&s->req_msg)) {
        t->parent_thread->work_pending = 1;
        notify_queue_notify(&s->req_msg);
    }
}

#define PKT_TASK_BUDGET 1024u
#define TUPLE_BUCKET_COUNT (128U * 1024U)

static void time_task_cb(task* t)
{
    (void)t;
    current_time_ms = read_now_ms();
}

static void pkt_task_cb(task *t)
{
    stack_instance *s = (stack_instance *)t->argv;

    notify_queue_drain(&s->pkt_msg);

    for (uint32_t budget = 0; budget < PKT_TASK_BUDGET; budget++) {
        mpscq_node *n = notify_queue_pop(&s->pkt_msg);
        if (!n)
            break;

        skbuff* skb = (skbuff*)n;
        skb->process(skb);
        PUT_REF(skb);
    }
    if (!notify_queue_is_empty(&s->pkt_msg)) {
        t->parent_thread->work_pending = 1;
        notify_queue_notify(&s->pkt_msg);
    }
}


static int stack_maps_init(void)
{
    stack_maps* maps = calloc(1, sizeof(*maps));
    if (!maps)
        return -1;

    maps->udp.bound_table4 = bind_table_create();
    maps->udp.bound_table6 = bind_table_create();
    maps->udp.tuple_hash4 = tuple_hash_create(TUPLE_BUCKET_COUNT, AF_INET);
    maps->udp.tuple_hash6 = tuple_hash_create(TUPLE_BUCKET_COUNT, AF_INET6);
    maps->tcp.bound_table4 = bind_table_create();
    maps->tcp.bound_table6 = bind_table_create();
    maps->tcp.tuple_hash4 = tuple_hash_create(TUPLE_BUCKET_COUNT, AF_INET);
    maps->tcp.tuple_hash6 = tuple_hash_create(TUPLE_BUCKET_COUNT, AF_INET6);

    if (!maps->udp.bound_table4 || !maps->udp.bound_table6 ||
        !maps->udp.tuple_hash4 || !maps->udp.tuple_hash6 ||
        !maps->tcp.bound_table4 || !maps->tcp.bound_table6 ||
        !maps->tcp.tuple_hash4 || !maps->tcp.tuple_hash6)
        goto fail;

    g_stack_maps = maps;
    return 0;

fail:
    if (maps->udp.bound_table4) bind_table_destroy(maps->udp.bound_table4);
    if (maps->udp.bound_table6) bind_table_destroy(maps->udp.bound_table6);
    hash_destroy(maps->udp.tuple_hash4);
    hash_destroy(maps->udp.tuple_hash6);
    if (maps->tcp.bound_table4) bind_table_destroy(maps->tcp.bound_table4);
    if (maps->tcp.bound_table6) bind_table_destroy(maps->tcp.bound_table6);
    hash_destroy(maps->tcp.tuple_hash4);
    hash_destroy(maps->tcp.tuple_hash6);
    free(maps);
    errno = ENOMEM;
    return -1;
}

static void stack_instance_cleanup_failed_init(stack_instance* s)
{
    destroy_task(s->pkt_task);
    destroy_task(s->req_task);
    destroy_task(s->ipq6_timer_task);
    destroy_task(s->ipq_timer_task);
    destroy_task(s->time_task);
    notify_queue_close(&s->pkt_msg);
    notify_queue_close(&s->req_msg);
    hash_destroy(s->ipq6_hash);
    hash_destroy(s->ipq_hash);
    memset(s, 0, sizeof(*s));
    s->netlink_fd = -1;
    s->req_msg.efd = -1;
    s->pkt_msg.efd = -1;
}


int stack_instance_init(stack_instance *s, thread *master)
{
    if (!s || !master) {
        errno = EINVAL;
        return -1;
    }

    memset(s, 0, sizeof(*s));
    s->netlink_fd = -1;
    s->req_msg.efd = -1;
    s->pkt_msg.efd = -1;
    if(!g_stack_maps){
        if (stack_maps_init() < 0)
            return -1;
    }

    s->time_task = create_task(TASK_TYPE_LOOP);
    if (!s->time_task)
        goto fail;
    s->time_task->cb_loop = time_task_cb;
    if (register_task(master, s->time_task) < 0)
        goto fail;

    s->ipq_hash = hash_create(1024,
        HASH_KEY_OFFSET(ipq, hash_node, key), sizeof(ipq_key));
    if (!s->ipq_hash)
        goto fail;

    s->ipq_timer_task = create_task(TASK_TYPE_TIMER);
    if (!s->ipq_timer_task)
        goto fail;
    s->ipq_timer_task->cb_timer = ipq_timer;
    s->ipq_timer_task->timeout = get_current_time_ms() + IPQ_TIMER_INTERVAL;
    s->ipq_timer_task->argv = (uint64_t)s;
    if (register_task(master, s->ipq_timer_task) < 0)
        goto fail;

    s->ipq6_hash = hash_create(1024,
        HASH_KEY_OFFSET(ipq6, hash_node, key), sizeof(ipq6_key));
    if (!s->ipq6_hash)
        goto fail;

    s->ipq6_timer_task = create_task(TASK_TYPE_TIMER);
    if (!s->ipq6_timer_task)
        goto fail;
    s->ipq6_timer_task->cb_timer = ipq6_timer;
    s->ipq6_timer_task->timeout = get_current_time_ms() + IPQ6_TIMER_INTERVAL;
    s->ipq6_timer_task->argv = (uint64_t)s;
    if (register_task(master, s->ipq6_timer_task) < 0)
        goto fail;

    if (notify_queue_init(&s->req_msg) < 0)
        goto fail;
    s->req_task = create_task(TASK_TYPE_FD_READ);
    if (!s->req_task)
        goto fail;
    s->req_task->fd = s->req_msg.efd;
    s->req_task->cb_read = req_task_cb;
    s->req_task->argv = (uint64_t)s;
    if (register_task(master, s->req_task) < 0)
        goto fail;

    /* packet notify queue (recv/send) */
    if (notify_queue_init(&s->pkt_msg) < 0)
        goto fail;
    s->pkt_task = create_task(TASK_TYPE_FD_READ);
    if (!s->pkt_task)
        goto fail;
    s->pkt_task->fd = s->pkt_msg.efd;
    s->pkt_task->cb_read = pkt_task_cb;
    s->pkt_task->argv = (uint64_t)s;
    if (register_task(master, s->pkt_task) < 0)
        goto fail;

    return 0;

fail:
    if (errno == 0)
        errno = ENOMEM;
    stack_instance_cleanup_failed_init(s);
    return -1;
}

/* req_pending_cb: callback installed in req->pn, invoked by socket_notify_event.
 * With bit flags, checks if any of the events intersect the req's wait mask. */
void req_pending_cb(Socket* sock, void* value, enum notify_event event)
{
    (void)sock;
    req* r = (req*)value;
    if (r->status == REQ_WAITING_CLOSE)
        return;
    req_status expected = notify_event_to_status(event);
    if (expected != REQ_STATUS_ALL && !(r->status & expected))
        return;
    /* Remove from pending list before processing to avoid re-entry */
    remove_list_node(&r->pn.node);
    process_request(r);
}

void wait(Socket *sock, req *r, req_status status)
{
	r->status = status;
	r->wait_sock = sock;
	if (!LIST_ATTACHED(&r->pn.node)) {
		r->pn.value = r;
		r->pn.cb    = req_pending_cb;
		add_list_node(&sock->pending, &r->pn.node);
	}
}

void wait_timeout_cb(task *tk)
{
	req *r = (req *)tk->argv;
	process_request(r);
}

void wait_until(Socket *sock, req *r, req_status status, uint64_t expire)
{
	r->status = status;
	r->wait_sock = sock;

	if (!r->timeout_task) {
		r->timeout_task = create_task(TASK_TYPE_TIMER);
        if (!r->timeout_task) {
            req_notify(r, -ENOMEM);
            return;
        }
    }
	r->timeout_task->cb_timer = wait_timeout_cb;
	r->timeout_task->argv = (uint64_t)r;
	r->timeout_task->timeout = expire;

	if (!r->worker || register_task(r->worker->master, r->timeout_task) < 0) {
        destroy_task(r->timeout_task);
        r->timeout_task = NULL;
        req_notify(r, -EIO);
        return;
    }

	if (!LIST_ATTACHED(&r->pn.node)) {
		r->pn.node.next = NULL;
		r->pn.value = r;
		r->pn.cb    = req_pending_cb;
		add_list_node(&sock->pending, &r->pn.node);
	}
}

static void socket_pending_task_cb(task* tk)
{
    Socket* sock = (Socket*)tk->argv;
    unregister_task(sock->pending_task);

    /* Snapshot + clear accumulated events before firing callbacks.
     * All operations on sock->pending are serialized on this worker thread. */
    uint32_t events = sock->notified_events;
    sock->notified_events = 0;

    /* Callbacks remove themselves only when the event satisfies their wait.
     * Leaving unmatched waiters attached prevents an unrelated notification
     * (for example EPOLLOUT) from losing a pending read request. */
    pending_node* pn;
    list_node* tmp;
    FOR_EACH_LIST_SAFE_OFFSET(&sock->pending, pn, tmp, pending_node, node) {
        if (pn->cb)
            pn->cb(sock, pn->value, (enum notify_event)events);
    }
}

void socket_notify_event(Socket* sock, enum notify_event event)
{
	worker *owner = sock->owner;
	uint32_t old_events = sock->notified_events;

	sock->notified_events |= (uint32_t)event;

	/* No read/epoll waiter can consume this notification yet.  Keep the
	 * readiness bits, but avoid allocating and scheduling a timer task. */
	if (!sock->pending.next)
		return;
	if (!owner || !owner->master)
		return;

	/* The same event is already queued for the pending waiters. */
	if ((old_events & (uint32_t)event) && sock->pending_task &&
	    sock->pending_task->registered)
		return;

	if (!sock->pending_task) {
		sock->pending_task = create_task(TASK_TYPE_TIMER);
		if (!sock->pending_task)
			return;
		sock->pending_task->cb_timer = socket_pending_task_cb;
		sock->pending_task->argv = (uint64_t)sock;
		
	}

	if (!sock->pending_task->registered) {
		/* Coalesce notifications while the pending callback is already
		 * scheduled.  notified_events is a bitmask, so repeated timer-wheel
		 * remove/insert operations are unnecessary. */
		sock->pending_task->timeout = get_current_time_ms();
		if (register_task(owner->master, sock->pending_task) < 0) {
            destroy_task(sock->pending_task);
            sock->pending_task = NULL;
        }
	}
}
