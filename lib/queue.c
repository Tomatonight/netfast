#include "queue.h"

#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>

void add_queue(queue* q, list_node* node)
{
	add_list_node_pre(&q->last, node);
	q->element_number++;
}

list_node* get_queue_first(queue* q)
{
	if (!q->element_number)
		return NULL;
	return q->first.next;
}

list_node* get_queue_last(queue* q)
{
	if (!q->element_number)
		return NULL;
	return q->last.pre;
}

list_node* pop_queue(queue* q)
{
	if (!q->element_number)
		return NULL;
	list_node* node = q->first.next;
	remove_list_node(node);
	q->element_number--;
	return node;
}

void add_queue_first(queue* q, list_node* node)
{
	add_list_node(&q->first, node);
	q->element_number++;
}

list_node* pop_queue_last(queue* q)
{
	if (!q->element_number)
		return NULL;
	list_node* node = q->last.pre;
	remove_list_node(node);
	q->element_number--;
	return node;
}

void init_queue(queue* q)
{
	q->first.next = &q->last;
	q->first.pre = NULL;
	q->last.pre = &q->first;
	q->last.next = NULL;
	q->element_number = 0;
}

bool queue_exist(queue* q, uint64_t element)
{
	QUEUE_FOR_EACH(q, node) {
		if (node->element == element)
			return true;
	}
	return false;
}

void mpscq_node_init(mpscq_node* n)
{
	atomic_store_explicit(&n->next, NULL, memory_order_relaxed);
}

void mpscq_init(mpsc_queue* q)
{
	mpscq_node_init(&q->stub);
	atomic_init(&q->head, &q->stub);
	q->tail = &q->stub;
}

void mpscq_push(mpsc_queue* q, mpscq_node* n)
{
	mpscq_node_init(n);
	mpscq_node* prev = atomic_exchange_explicit(&q->head, n, memory_order_acq_rel);
	atomic_store_explicit(&prev->next, n, memory_order_release);
}

mpscq_node* mpscq_pop(mpsc_queue* q)
{
	mpscq_node* tail = q->tail;
	mpscq_node* next = atomic_load_explicit(&tail->next, memory_order_acquire);

	if (tail == &q->stub) {
		if (next == NULL) {
			return NULL;
		}
		q->tail = next;
		tail = next;
		next = atomic_load_explicit(&tail->next, memory_order_acquire);
	}

	if (next != NULL) {
		q->tail = next;
		return tail;
	}

	mpscq_node* head = atomic_load_explicit(&q->head, memory_order_acquire);
	if (tail != head) {
		return NULL;
	}

	mpscq_push(q, &q->stub);

	next = atomic_load_explicit(&tail->next, memory_order_acquire);
	if (next != NULL) {
		q->tail = next;
		return tail;
	}

	return NULL;
}

bool mpscq_is_empty(mpsc_queue* q)
{
	mpscq_node* tail = q->tail;
	if (tail != &q->stub)
		return false;
	mpscq_node* next = atomic_load_explicit(&tail->next, memory_order_acquire);
	return next == NULL;
}

int notify_queue_init(notify_queue* nq)
{
	mpscq_init(&nq->q);
	nq->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	atomic_init(&nq->pending, 0);
	return nq->efd >= 0 ? 0 : -1;
}

void notify_queue_close(notify_queue* nq)
{
	if (nq->efd >= 0)
		close(nq->efd);
	nq->efd = -1;
	atomic_store_explicit(&nq->pending, 0, memory_order_relaxed);
}

void notify_queue_drain(notify_queue* nq)
{
	eventfd_t value;
	while (eventfd_read(nq->efd, &value) != 0 && errno == EINTR) {}
	atomic_store_explicit(&nq->pending, 0, memory_order_release);
}

void notify_queue_notify(notify_queue* nq)
{


	unsigned int expect = 0;
	if (!atomic_compare_exchange_strong_explicit(&nq->pending,
										&expect, 1,
										memory_order_acq_rel,
										memory_order_relaxed)) {
		return;
	}

	if (eventfd_write(nq->efd, 1) != 0) {
		atomic_store_explicit(&nq->pending, 0, memory_order_release);
	}
}

void notify_queue_push(notify_queue* nq, mpscq_node* node)
{
	mpscq_push(&nq->q, node);
	notify_queue_notify(nq);
}

mpscq_node* notify_queue_pop(notify_queue* nq)
{
	return mpscq_pop(&nq->q);
}

bool notify_queue_is_empty(notify_queue* nq)
{
	return mpscq_is_empty(&nq->q);
}
