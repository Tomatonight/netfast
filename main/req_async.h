#ifndef REQ_ASYNC_H
#define REQ_ASYNC_H

#include <stddef.h>
#include <stdint.h>

#include "req.h"

struct async_waiter;

typedef struct async_cq {
    ref_info        ref;
    list_node       submit_reqs;
    notify_queue    completions;
    atomic_uint     complete_count;
    atomic_uint     wait_need;
    mutex_t         waiters_mtx;
    struct async_waiter *waiters;
} async_cq;


int net_async_create(void);

req *net_async_req_create(int fd, req_type type, ...);
/* Destroy an unsubmitted request, or one returned by net_async_wait(). */
void net_async_req_destroy(req *request);

int net_async_submit(int cq_fd, req *request);
int net_async_result(const req *request, req_type *type);
req_argv *net_async_argv(req *request);
int net_async_wait(int cq_fd, req ** requests, uint32_t min,
                   uint32_t max, int total_timeout_ms);
int net_async_close(int cq_fd);

#endif /* REQ_ASYNC_H */
