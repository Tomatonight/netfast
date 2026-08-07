#ifndef STACK_H
#define STACK_H

#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "list.h"
#include "thread.h"
#include "base.h" /* get_current_time_ms */
#include "hash.h"
#include "queue.h" /* notify_queue (mpsc_queue + eventfd wakeup) */
#include "req.h"
#include "socket.h"

/* forward decl */
typedef struct worker worker;

/* forward decls */
typedef struct Socket Socket;
typedef struct req req;
typedef enum req_status req_status;

typedef struct protocol_map{
    bind_table* bound_table4; // IPv4 addr_key -> atomic bind count
    bind_table* bound_table6; // IPv6 addr_key -> atomic bind count
    hash* tuple_hash4; // IPv4 addr_tuple -> sock_group*
    hash* tuple_hash6; // IPv6 addr_tuple -> sock_group*
} protocol_map;

typedef struct stack_maps {
    protocol_map udp;
    protocol_map tcp;
} stack_maps;

extern stack_maps* g_stack_maps;

/* ── per-family accessors ── */
static inline bind_table* udp_bound_table(int family)
{
    return family == AF_INET6
        ? g_stack_maps->udp.bound_table6
        : g_stack_maps->udp.bound_table4;
}
static inline hash* udp_tuple_hash(int family)
{
    return family == AF_INET6
        ? g_stack_maps->udp.tuple_hash6
        : g_stack_maps->udp.tuple_hash4;
}
static inline bind_table* tcp_bound_table(int family)
{
    return family == AF_INET6
        ? g_stack_maps->tcp.bound_table6
        : g_stack_maps->tcp.bound_table4;
}
static inline hash* tcp_tuple_hash(int family)
{
    return family == AF_INET6
        ? g_stack_maps->tcp.tuple_hash6
        : g_stack_maps->tcp.tuple_hash4;
}


/* per-stack data structures */
typedef struct stack_instance{
    int netlink_fd;
    task* time_task;
    notify_queue req_msg;
    task* req_task;

    notify_queue pkt_msg;
    task* pkt_task;

    hash* ipq_hash;
    task* ipq_timer_task;

    hash* ipq6_hash;
    task* ipq6_timer_task;

} stack_instance;

void process_request(req *r);
int stack_instance_init(stack_instance* s, thread* master);
/* Only call after the worker has stopped (or before it has started). */


void wait(Socket* sock, req* req, req_status status);
void wait_timeout_cb(task* tk);
void wait_until(Socket* sock, req* req, req_status status, uint64_t expire);

void req_pending_cb(Socket* sock, void* value, enum notify_event event);
#endif
