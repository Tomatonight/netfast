#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/socket.h>

#include "req.h"
#include "stack.h"

typedef enum worker_startup_state {
    WORKER_STARTUP_PENDING = 0,
    WORKER_STARTUP_READY,
    WORKER_STARTUP_FAILED,
} worker_startup_state;

typedef struct worker {
    thread* master;
    pthread_t master_tid;
    stack_instance stack;
    /* 单个原子状态同时发布启动完成与启动结果。 */
    _Atomic worker_startup_state startup_state;
} worker;

typedef struct worker_req {
    void* argv;
    int (*cb)(void*);
} worker_req;

extern worker* main_worker;
extern worker* g_workers;
extern int g_worker_num;

/* 当前线程所属的 worker；由 worker 线程入口设置。 */
worker* get_current_worker(void);
void set_current_worker(worker* w);

/* 尽力将 worker 线程绑定到指定 CPU。 */
int worker_bind_cpu(pthread_t tid, int cpu);
int worker_init(worker* w);
int worker_start_all(void);

worker* worker_select_random(void);

void worker_move_request(req* req, worker* new_worker);

void worker_enqueue_skb(worker* w, skbuff* skb,
                        int (*skb_process)(skbuff* skb));
void submit_req_2_worker(worker* w, void* argv, int (*cb)(void*), bool wait);
void worker_process_submitted_request(req* r);

#endif
