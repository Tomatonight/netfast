#ifndef REQ_ASYNC_H
#define REQ_ASYNC_H
#include <stddef.h>
#include <stdint.h>
#include "req.h"

typedef struct async_cq {
    ref_info       ref;
    list_node submit_reqs;
    notify_queue   completions;
} async_cq;


req* net_async_req_create(int fd, int operation, ...);

/* Destroy an unsubmitted request, or one returned by net_async_wait(). */
void net_async_req_destroy(req* r);
int net_async_req_result(const req* r, int* saved_errno);


/* ── public API (fd-based) ── */
int net_async_create(void);
int net_async_submit(int cq_fd, req* r);
int net_async_submit_batch(int cq_fd, req** reqs, uint32_t count);
int net_async_wait(int cq_fd, req** reqs, uint32_t min,
                   uint32_t max, int timeout_ms);
int net_async_close(int cq_fd);

#endif
