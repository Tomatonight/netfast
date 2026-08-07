#include "thread.h"

#include "base.h"
#include "log.h"
#include "worker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>




int set_fd_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		ERR_LOG("fcntl F_GETFL failed");
		return -1;
	}

	if (flags & O_NONBLOCK)
		return 0;

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		ERR_LOG("fcntl F_SETFL O_NONBLOCK failed");
		return -1;
	}

	return 0;
}

task* create_task(int type)
{
	if (type < TASK_TYPE_FD_READ || type > TASK_TYPE_LOOP) {
		ERR_LOG("unknown task type %d", type);
		return NULL;
	}

	task* t = calloc(1, sizeof(*t));
	if (!t) {
		ERR_LOG("create task: out of memory");
		return NULL;
	}

	t->task_type = type;
	return t;
}

void destroy_task(task* t)
{
	unregister_task(t);
	free(t);
}

static inline list_node* wheel_timer_slot(thread* t, const task* tk,
										  uint64_t now_ms)
{
	if (tk->timeout <= now_ms)
		return &t->wheel0_list[t->wheel0_cursor];

	uint64_t delta_ms = tk->timeout - now_ms;
	uint32_t l0_ticks = (uint32_t)((delta_ms + WHEEL_0_TICK_MS - 1) /
										 WHEEL_0_TICK_MS);
	if (l0_ticks < WHEEL_0_SIZE) {
		uint32_t slot = (t->wheel0_cursor + l0_ticks) % WHEEL_0_SIZE;
		return &t->wheel0_list[slot];
	}

	uint32_t l1_ticks = (uint32_t)(delta_ms / (uint64_t)WHEEL_1_TICK_MS);
	if (l1_ticks >= WHEEL_1_SIZE)
		l1_ticks = WHEEL_1_SIZE - 1;
	uint32_t slot = (t->wheel1_cursor + l1_ticks) % WHEEL_1_SIZE;
	return &t->wheel1_list[slot];
}

static inline void wheel_add_timer_at_locked(thread* t, task* tk,
											  uint64_t now_ms)
{
	add_list_node(wheel_timer_slot(t, tk, now_ms), &tk->timer_list);
}

static inline void wheel_requeue_timer_locked(thread* t, task* tk,
											   uint64_t now_ms)
{
	list_node* tail = wheel_timer_slot(t, tk, now_ms);
	while (tail->next)
		tail = tail->next;
	add_list_node(tail, &tk->timer_list);
}

static inline void wheel_cascade_l1(thread* t)
{
	list_node* l1_slot = &t->wheel1_list[t->wheel1_cursor];
	uint64_t now_ms = get_current_time_ms();
	task* tk;
	list_node* tmp;
	FOR_EACH_LIST_SAFE_OFFSET(l1_slot, tk, tmp, task, timer_list) {
		remove_list_node(&tk->timer_list);
		wheel_add_timer_at_locked(t, tk, now_ms);
	}
}

static inline void wheel_add_timer_locked(thread* t, task* tk)
{
	wheel_add_timer_at_locked(t, tk, get_current_time_ms());
}

static inline void wheel_add_timer(thread* t, task* tk)
{
	pthread_spin_lock(&t->wheel_lock);
	if (tk->registered)
		wheel_add_timer_locked(t, tk);
	pthread_spin_unlock(&t->wheel_lock);
}

static inline void wheel_remove_timer_locked(task* tk)
{
	if (LIST_ATTACHED(&tk->timer_list))
		remove_list_node(&tk->timer_list);
}

static inline void wheel_remove_timer(thread* t, task* tk)
{
	pthread_spin_lock(&t->wheel_lock);
	wheel_remove_timer_locked(tk);
	pthread_spin_unlock(&t->wheel_lock);
}

static inline void wheel_advance(thread* t)
{
	pthread_spin_lock(&t->wheel_lock);
	t->wheel0_cursor = (t->wheel0_cursor + 1) % WHEEL_0_SIZE;
	if (t->wheel0_cursor == 0) {
		t->wheel1_cursor = (t->wheel1_cursor + 1) % WHEEL_1_SIZE;
		wheel_cascade_l1(t);
	}
	pthread_spin_unlock(&t->wheel_lock);
}


thread* create_thread(void)
{
	thread* t = calloc(1, sizeof(*t));
	if (!t)
		return NULL;

	t->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (t->epoll_fd < 0) {
		ERR_LOG("create thread failed: epoll_create1");
		free(t);
		return NULL;
	}
	if (pthread_spin_init(&t->wheel_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
		ERR_LOG("create thread failed: pthread_spin_init");
		close(t->epoll_fd);
		free(t);
		return NULL;
	}
	current_time_ms = read_now_ms();
	t->last_timer_check_ms = get_current_time_ms();
	frame_cache_init(&t->frame_cache);

	return t;
}

void destroy_thread(thread* t)
{
	if (!t)
		return;
	if (t->epoll_fd >= 0)
		close(t->epoll_fd);
	pthread_spin_destroy(&t->wheel_lock);
	frame_cache_reset(&t->frame_cache);
	free(t);
}

static void unregister_loop_task(task* tk)
{
	thread* t = tk->parent_thread;
	if (!t)
		return;

	if (LIST_ATTACHED(&tk->loop_list)) {
		remove_list_node(&tk->loop_list);
	}
	tk->registered = 0;
	tk->parent_thread = NULL;
}

int register_task(thread* t, task* tk)
{
	if (!t || !tk) {
		ERR_LOG("register task failed: invalid argument");
		return -1;
	}
	if (tk->task_type == TASK_TYPE_LOOP) {
		if (tk->registered) {
			if (tk->parent_thread == t)
				return 0;
			unregister_loop_task(tk);
		}

		tk->parent_thread = t;
		tk->registered = 1;
		add_list_node(&t->loop_tasks, &tk->loop_list);
		return 0;
	}

	if (tk->registered && tk->task_type != TASK_TYPE_TIMER) {
		/* Already registered: update epoll events only if type changed */
		if (tk->reg_task_type == tk->task_type && tk->parent_thread == t)
			return 0;

		struct epoll_event ev;
		memset(&ev, 0, sizeof(ev));
		ev.data.ptr = tk;

		switch (tk->task_type) {
		case TASK_TYPE_FD_READ:
			ev.events = EPOLLIN;
			break;
		case TASK_TYPE_FD_WRITE:
			ev.events = EPOLLOUT;
			break;
		case TASK_TYPE_FD_RW:
			ev.events = EPOLLIN | EPOLLOUT;
			break;
		default:
			ERR_LOG("unknown task type %d", tk->task_type);
			return -1;
		}

		int op = (tk->parent_thread == t) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
		if (tk->parent_thread != t) {
			/* thread changed: del from old, add to new */
			(void)epoll_ctl(tk->parent_thread->epoll_fd,
			                EPOLL_CTL_DEL, tk->fd, NULL);
		}
		if (epoll_ctl(t->epoll_fd, op, tk->fd, &ev) < 0) {
			ERR_LOG("epoll ctl %d failed", tk->fd);
			return -1;
		}
		tk->reg_task_type = tk->task_type;
		tk->parent_thread = t;
		return 0;
	}

	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));

	switch (tk->task_type) {
		case TASK_TYPE_FD_READ:
			ev.events = EPOLLIN;
			break;
		case TASK_TYPE_FD_WRITE:
			ev.events = EPOLLOUT;
			break;
		case TASK_TYPE_FD_RW:
			ev.events = EPOLLIN | EPOLLOUT;
			break;
		case TASK_TYPE_TIMER:
		case TASK_TYPE_LOOP:
			break;
		default:
			ERR_LOG("unknown task type %d", tk->task_type);
			return -1;
	}

	if (tk->task_type == TASK_TYPE_TIMER) {
		/* Phase 1: remove from old wheel */
		if (tk->registered)
			wheel_remove_timer(tk->parent_thread, tk);

		/* Phase 2: mark as registered */
		tk->registered = 1;
		tk->parent_thread = t;

		/* Phase 3: insert into new wheel (checks registered under lock) */
		wheel_add_timer(t, tk);
		return 0;
	}

	if (ev.events) {
		if (set_fd_nonblock(tk->fd) < 0) {
			ERR_LOG("set fd %d nonblock failed", tk->fd);
			return -1;
		}
		ev.data.ptr = tk;
		if (epoll_ctl(t->epoll_fd, EPOLL_CTL_ADD, tk->fd, &ev) < 0) {
			ERR_LOG("epoll add %d failed", tk->fd);
			return -1;
		}

	}

	tk->registered = 1;
	tk->reg_task_type = tk->task_type;
	tk->parent_thread = t;

	return 0;
}

void unregister_task(task* tk)
{
	if (!tk->registered)
		return;

	thread* t = tk->parent_thread;
	if (tk->task_type == TASK_TYPE_LOOP) {
		unregister_loop_task(tk);
		return;
	}
	if (tk->task_type == TASK_TYPE_TIMER) {
		if (t)
			wheel_remove_timer(t, tk);
	} else {
		(void)epoll_ctl(t->epoll_fd, EPOLL_CTL_DEL, tk->fd, NULL);
	}

	tk->registered = 0;
	tk->parent_thread = NULL;
}

static int do_loop_tasks(thread* t)
{
	int do_sum = 0;
	task* tk;
	list_node* next;

	FOR_EACH_LIST_SAFE_OFFSET(&t->loop_tasks, tk, next, task, loop_list) {
		if (tk->cb_loop) {
			tk->cb_loop(tk);
			do_sum++;
		}
	}

	return do_sum;
}

static int do_fd_tasks(thread* t, int timeout_ms)
{
	int ready_num = epoll_wait(t->epoll_fd, t->events, MAX_EPOLL_EVENTS, timeout_ms);
	if (ready_num < 0) {
		if (errno == EINTR)
			return 0;
		ERR_LOG("epoll_wait failed");
		return -1;
	}
	if (ready_num == 0)
		return 0;

	int do_sum = 0;
	for (int i = 0; i < ready_num; i++) {
		task* tk = (task*)t->events[i].data.ptr;
		if (!tk)
			continue;

		uint32_t events = t->events[i].events;
		if ((events & EPOLLIN) && tk->cb_read) {
			tk->cb_read(tk);
			do_sum++;
		}
		if ((events & EPOLLOUT) && tk->cb_write) {
			tk->cb_write(tk);
			do_sum++;
		}
		if ((events & (EPOLLERR | EPOLLHUP)) && tk->cb_err) {
			tk->cb_err(tk);
			do_sum++;
		}
	}

	return do_sum;
}

static int fire_timer_task(task* tk, uint64_t now_ms)
{
	if (tk->timeout > now_ms)
		return 0;

	tk->registered = 0;
	if (!tk->cb_timer)
		return 0;

	tk->cb_timer(tk);
	return 1;
}

static int process_current_timer_slot(thread* t, uint64_t now_ms)
{
	int do_sum = 0;

	for (;;) {
		pthread_spin_lock(&t->wheel_lock);
		list_node* node = t->wheel0_list[t->wheel0_cursor].next;
		if (!node) {
			pthread_spin_unlock(&t->wheel_lock);
			break;
		}

		task* tk = (task*)((uint8_t*)node - offsetof(task, timer_list));
		remove_list_node(&tk->timer_list);
		if (tk->timeout > now_ms) {
			/* A coarse clock can expose a slot just before its deadline. */
			wheel_requeue_timer_locked(t, tk, now_ms);
			pthread_spin_unlock(&t->wheel_lock);
			continue;
		}
		pthread_spin_unlock(&t->wheel_lock);

		/* The callback may unregister, migrate, or destroy other timers.
		 * Pop one timer at a time from the real wheel so those operations
		 * never see nodes linked to a stack-local temporary list. */
		do_sum += fire_timer_task(tk, now_ms);
	}

	return do_sum;
}

static int do_timer_tasks(thread* t)
{
    int do_sum = 0;
	    uint64_t now_ms = get_current_time_ms();
    uint64_t elapsed_ms = now_ms - t->last_timer_check_ms;
    uint64_t elapsed_ticks = elapsed_ms / WHEEL_0_TICK_MS;

    do_sum += process_current_timer_slot(t, now_ms);
    for (uint64_t i = 0; i < elapsed_ticks; i++) {
        wheel_advance(t);
        do_sum += process_current_timer_slot(t, now_ms);
    }

    /* Keep the sub-tick remainder so wheel slots advance at 10 ms, not 1 ms. */
    t->last_timer_check_ms += elapsed_ticks * WHEEL_0_TICK_MS;

    return do_sum;
}

int thread_step(thread* t)
{
	current_time_ms = read_now_ms();
	int do_sum = do_loop_tasks(t) + do_timer_tasks(t);
	int fd_sum = do_fd_tasks(t, THREAD_EPOLL_WAIT_TIME);
	if (fd_sum > 0)
		do_sum += fd_sum;

	return do_sum;
}

void thread_loop(thread* t)
{
	for (;;) {
		/* Only skip sleeping when the previous pass explicitly left runnable
		 * work behind.  A normal fd event alone is not a reason to issue a
		 * fixed series of empty epoll_wait(0) calls. */
		int timeout_ms = t->work_pending ? 0 : THREAD_EPOLL_WAIT_TIME;
		t->work_pending = 0;

		(void)do_loop_tasks(t);
		(void)do_timer_tasks(t);
		(void)do_fd_tasks(t, timeout_ms);
	}
}
