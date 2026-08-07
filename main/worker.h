#ifndef WORKER_H
#define WORKER_H
#include"queue.h"
#include"req.h"
#include"stack.h"
#include"base.h"
#include"rss.h"
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/socket.h>

typedef struct worker{
	thread* master;
	pthread_t master_tid;
	stack_instance stack;
	/* loop_started publishes that startup finished; loop_success is result. */
	atomic_bool loop_started;
	atomic_bool loop_success;
} worker;
typedef struct worker_req{
	void* argv;
	int (*cb)(void*);
}worker_req;

extern worker* main_worker;
extern worker* g_workers;
extern int g_worker_num;

/* TLS current worker (set in worker thread entry) */
worker* get_current_worker(void);
void set_current_worker(worker* w);

int worker_detach_all(void);

/* bind worker thread to cpu core (best effort) */
int worker_bind_cpu(pthread_t tid, int cpu);

int worker_init(worker* w);
int worker_detach(worker* w);

worker* random_worker(void);

void change_req_worker(req* req, worker* new_worker);

void transmit_skb_2_worker(struct worker* w, skbuff* skb, int (*skb_process)(skbuff* skb));


void submit_req_2_worker(struct worker* w, void* argv, int (*cb)(void*), bool wait);
void process_submit_req(req* r);
#endif
