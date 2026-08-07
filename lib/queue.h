#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include "list.h"

typedef struct queue {
	list_node last;
	list_node first;
	int element_number;
} queue;

void init_queue(queue* q);
void add_queue(queue* q, list_node* node);
void add_queue_first(queue* q, list_node* node);
list_node* pop_queue(queue* q);
list_node* pop_queue_last(queue* q);
bool queue_exist(queue* q, uint64_t element);
list_node* get_queue_first(queue* q);
list_node* get_queue_last(queue* q);

#define QUEUE_EMPTY(q) ((q)->element_number == 0)

#define QUEUE_FOR_EACH(q, node)                                                \
    for (list_node* node = (q)->first.next;                                    \
         node != &(q)->last;                                                   \
         node = node->next)

#define QUEUE_FOR_EACH_SAFE(q, node, tmp)                                      \
    for (list_node* node = (q)->first.next,                                   \
                  * tmp = (node ? node->next : NULL);                          \
         node != &(q)->last;                                                   \
         node = tmp, tmp = (node ? node->next : NULL))


typedef struct mpscq_node {
    _Atomic(struct mpscq_node*) next;
} mpscq_node;

typedef struct mpsc_queue {
    _Atomic(mpscq_node*) head;
    mpscq_node* tail;
    mpscq_node stub;
} mpsc_queue;

typedef struct notify_queue {
    mpsc_queue q;
    int efd;
    atomic_uint pending;
} notify_queue;
 


void mpscq_node_init(mpscq_node* node);
void mpscq_init(mpsc_queue* q);
void mpscq_push(mpsc_queue* q, mpscq_node* node);
mpscq_node* mpscq_pop(mpsc_queue* q);
bool mpscq_is_empty(mpsc_queue* q);

int notify_queue_init(notify_queue* nq);
void notify_queue_close(notify_queue* nq);
void notify_queue_drain(notify_queue* nq);
void notify_queue_notify(notify_queue* nq);
void notify_queue_push(notify_queue* nq, mpscq_node* node);
mpscq_node* notify_queue_pop(notify_queue* nq);
bool notify_queue_is_empty(notify_queue* nq);

#endif /* QUEUE_H */
