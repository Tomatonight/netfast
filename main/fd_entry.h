#ifndef FD_ENTRY_H
#define FD_ENTRY_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include "list.h"
#include "base.h"

typedef struct worker worker;
typedef struct fd_entry fd_entry;
typedef struct req req;
typedef struct Socket Socket;

enum notify_event {
    notify_data_read       = (1 << 0),
    notify_data_write      = (1 << 1),
    notify_new_connection  = (1 << 2),
    notify_err             = (1 << 3),
    notify_recv_fin        = (1 << 4),
};

typedef struct pending_node {
    list_node node;
    void* value;
    void (*cb)(Socket* sock, void* value, enum notify_event event);
} pending_node;

typedef struct fd_entry_ops {
    /* socket operations */
    int (*bind)(fd_entry* entry, const struct sockaddr *addr, socklen_t addrlen);
    int (*connect)(fd_entry* entry, const struct sockaddr *addr, socklen_t addrlen);
    int (*listen)(fd_entry* entry, int backlog);
    int (*accept)(fd_entry* entry, struct sockaddr *addr, socklen_t *addrlen);
    int (*write)(fd_entry* entry, const void *buf, uint32_t len);
    int (*read)(fd_entry* entry, void *buf, uint32_t len);
    int (*sendto)(fd_entry* entry, const void *buf, uint32_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen);
    int (*recvfrom)(fd_entry* entry, void *buf, uint32_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen);
    int (*getsockname)(fd_entry* entry, struct sockaddr *addr, socklen_t *addrlen);
    int (*getpeername)(fd_entry* entry, struct sockaddr *addr, socklen_t *addrlen);
    int (*setsockopt)(fd_entry* entry, int level, int optname,
                      const void *optval, socklen_t optlen);
    int (*getsockopt)(fd_entry* entry, int level, int optname,
                      void *optval, socklen_t *optlen);
    int (*fcntl)(fd_entry* entry, int cmd, int arg);

#ifdef TEST_EPOLL
    int (*epoll_create)(void);
    int (*epoll_ctl)(fd_entry* entry, int op, int sockfd,
                     struct epoll_event *event);
    int (*epoll_wait)(fd_entry* entry, struct epoll_event *events,
                      int maxevents, int timeout_ms);
#endif

    int (*close)(fd_entry* entry);
    int (*shutdown)(fd_entry* entry, int how);

} fd_entry_ops;

typedef struct fd_entry {
    int fd;
    void* value;
    const fd_entry_ops* ops;
    ref_info ref;
    mutex_t mtx;
    atomic_uintptr_t w;
}fd_entry;

static inline worker* fd_entry_get_worker(const fd_entry* entry)
{
    return (worker*)(uintptr_t)atomic_load_explicit(
        &entry->w, memory_order_acquire);
}

static inline void fd_entry_set_worker(fd_entry* entry, worker* w)
{
    atomic_store_explicit(&entry->w, (uintptr_t)w, memory_order_release);
}

fd_entry* alloc_fd_entry_with_worker(void* value, const fd_entry_ops* ops,
                                     worker* w);
fd_entry* hold_fd_entry(int fd);

fd_entry* get_sock_entry_by_req(const req* r);

int fd_table_init(void);
#endif /* FD_ENTRY_H */
