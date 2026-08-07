#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>
#include <stdint.h>
#include <sys/epoll.h>

#include "frame_cache.h"
#include "list.h"

#define TASK_TYPE_FD_READ 1
#define TASK_TYPE_FD_WRITE 2
#define TASK_TYPE_FD_RW 3
#define TASK_TYPE_TIMER 4
#define TASK_TYPE_LOOP 5

#define MAX_EPOLL_EVENTS 256u

#define WHEEL_0_SIZE 100u
#define WHEEL_0_TICK_MS 1u             /* 1 ms timer granularity */

#define WHEEL_1_SIZE 100u
#define WHEEL_1_TICK_MS (WHEEL_0_TICK_MS * WHEEL_0_SIZE)

#define THREAD_EPOLL_WAIT_TIME 1      /* ms, low-load sleep timeout */

struct thread;
typedef struct thread thread;

typedef struct task {
	int task_type;
	int reg_task_type;        /* currently registered epoll event type */
	thread* parent_thread;

	int fd;                
	uint64_t timeout;

	void (*cb_timer)(struct task*);
	void (*cb_read)(struct task*);
	void (*cb_write)(struct task*);
	void (*cb_err)(struct task*);
	void (*cb_loop)(struct task*);

	uint64_t argv;
	list_node timer_list;
	list_node loop_list;
	uint32_t registered : 1;
} task;

struct thread {
	int epoll_fd;
	struct epoll_event events[MAX_EPOLL_EVENTS];

	/* hierarchical time wheel (2-level) */
	list_node wheel0_list[WHEEL_0_SIZE];
	list_node wheel1_list[WHEEL_1_SIZE];
	uint32_t wheel0_cursor;       /* current L0 slot index */
	uint32_t wheel1_cursor;       /* current L1 slot index */
	uint64_t last_timer_check_ms;

	pthread_spinlock_t wheel_lock;  /* protects wheel_*_list / cursors */
	list_node loop_tasks;
	uint32_t work_pending : 1;      /* a callback left immediately runnable work */
	frame_cache frame_cache;

};

task* create_task(int type);
void destroy_task(task* t);

thread* create_thread(void);
/* The caller must stop the loop and destroy/unregister all tasks first. */
void destroy_thread(thread* t);
int register_task(thread* t, task* tk);
void unregister_task(task* tk);

static inline int update_task_timer(task* tk, uint64_t timeout)
{
	tk->timeout = timeout;
	return register_task(tk->parent_thread, tk);
}

/* One non-blocking step: process loop tasks, ready fds, and due timers. */
int thread_step(thread* t);

/* Loop forever; mainly for real runtime, not unit tests */
void thread_loop(thread* t);


int set_fd_nonblock(int fd);

#endif
