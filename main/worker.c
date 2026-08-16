#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sched.h>
#include "worker.h"
#include "log.h"
#include "socket.h"
#include "xdp.h"
#include "route_arp_ndp.h"
#include "ip.h"
#include "udp.h"
#include "netlink.h"
#include "loopback.h"
#include "tcp.h"
#include "netfast.h"

worker *main_worker = NULL;
worker *g_workers = NULL;
int g_worker_num = 0;

static long get_ncpu(void)
{
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? count : 1;
}

int worker_bind_cpu(pthread_t tid, int cpu)
{
    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return pthread_setaffinity_np(tid, sizeof(set), &set);
}

static void* worker_loop(void* arg)
{
    worker* w = arg;
    int idx = (int)(w - g_workers);
    int n_cpus = get_ncpu();
    worker_bind_cpu(pthread_self(), idx % n_cpus);

    set_current_worker(w);

    int error = 0;
    if (w == main_worker) {
        if (netlink_init(w) < 0) {
            error = errno ? errno : EIO;
            ERR_LOG("lib_init: netlink_init failed: %s", strerror(error));
        } else if (loopback_init() < 0) {
            error = errno ? errno : EIO;
            ERR_LOG("lib_init: loopback_init failed: %s", strerror(error));
        }
    }

    if (error) {
        atomic_store_explicit(&w->loop_success, false, memory_order_relaxed);
        atomic_store_explicit(&w->loop_started, true, memory_order_release);
        return NULL;
    }
    atomic_store_explicit(&w->loop_success, true, memory_order_relaxed);
    atomic_store_explicit(&w->loop_started, true, memory_order_release);
    thread_loop(w->master);
    return NULL;
}

static int worker_wait_init(worker* w)
{
    while (!atomic_load_explicit(&w->loop_started, memory_order_acquire))
        sched_yield();
    if (!atomic_load_explicit(&w->loop_success, memory_order_relaxed)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

int worker_detach_all()
{
    for (int i = 1; i < g_worker_num; i++) {
        if (worker_detach(&g_workers[i]) < 0)
            return -1;
    }
    for (int i = 1; i < g_worker_num; i++) {
        if (worker_wait_init(&g_workers[i]) < 0)
            return -1;
    }

    if (worker_detach(main_worker) < 0)
        return -1;
    return worker_wait_init(main_worker);
}

int worker_init(worker *w)
{
    atomic_init(&w->loop_started, false);
    atomic_init(&w->loop_success, false);
    w->master = create_thread();
    if (!w->master)
    {
        return -1;
    }
    if (stack_instance_init(&w->stack, w->master) < 0)
    {
        destroy_thread(w->master);
        w->master = NULL;
        return -1;
    }
    return 0;
}

int worker_detach(worker *w)
{
    int error = pthread_create(&w->master_tid, NULL, worker_loop, w);
    if (error != 0)
    {
        ERR_LOG("Failed to create detached worker thread");
        return -1;
    }

    error = pthread_detach(w->master_tid);
    if (error != 0)
    {
        ERR_LOG("Failed to detach worker thread");
        return -1;
    }

    return 0;
}

static __thread worker *current_worker = NULL;

worker *get_current_worker(void)
{
    return current_worker;
}

void set_current_worker(worker *w)
{
    current_worker = w;
}
worker *random_worker(void)
{
    uint32_t state = get_current_time_ms();
    return &g_workers[state % (uint32_t)g_worker_num];
}

void change_req_worker(req *req, worker *new_worker)
{
    req->worker = new_worker;

    if (LIST_ATTACHED(&req->pn.node))
        remove_list_node(&req->pn.node);

    destroy_task(req->timeout_task);
    req->timeout_task = NULL;

    notify_queue_push(&new_worker->stack.req_msg, &req->node);
}
void transmit_skb_2_worker(worker* w,skbuff* skb,int (*skb_process)(skbuff* skb)){
	INC_REF(skb);
	skb->process=skb_process;
	notify_queue_push(&w->stack.pkt_msg, &skb->node);

}
void submit_req_2_worker(worker *w, void *argv, int (*cb)(void *), bool wait)
{
    if (wait) {
        req r;
        req_init(&r);

        r.type = REQ_WORKER_REQ;
        r.argv.worker_req = (typeof(r.argv.worker_req)){ .argv = argv, .cb = cb };

        req_push_wait(w, &r);
    } else {
        req* r = req_create();
        if (!r)
            return;

        r->type = REQ_WORKER_REQ;
        r->argv.worker_req.argv = argv;
        r->argv.worker_req.cb   = cb;
        r->flag.no_wait     = 1;
        r->flag.notify_free = 1;

        req_push_wait(w, r);
    }
}

void process_submit_req(req* r)
{
    int (*cb)(void*)  = r->argv.worker_req.cb;
    int ret = 0;

    if (cb)
        ret = cb(r->argv.worker_req.argv);

    req_notify(r, ret);
}
