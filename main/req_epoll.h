#ifndef REQ_EPOLL_H
#define REQ_EPOLL_H

#include <stdint.h>
#include <sys/epoll.h>
#include <pthread.h>

#include "queue.h"
#include "hash.h"
#include "base.h"
#include "fd_entry.h"

typedef struct Socket Socket;
typedef struct req req;

typedef struct epoll_event epoll_event;
typedef struct net_epoll net_epoll;

typedef struct net_epoll_item{
    ref_info ref;
    pending_node node;
    list_node ready_list;        /* on ep->ready_items, protected by ep->ready_lock */
    epoll_event ready_events;    /* protected by ep->ready_lock */
    epoll_event watching_events; /* protected by ep->ready_lock */
    int sockfd;
    net_epoll* ep;               /* item owns one ep reference */
} net_epoll_item;

struct net_epoll {
    ref_info ref;
    notify_queue ready_q;        /* eventfd wakeup */
    list_node ready_items;       /* protected by ready_lock */
    spinlock_t ready_lock;
    hash* registered_sockfds;
};

/* Forward declarations for callback functions defined in socket.c */
void epoll_pending_cb(Socket* sock, void* value, enum notify_event event);
void epoll_poll_complete(Socket* sock, uint32_t event, void* argv);
void epoll_item_unregister(net_epoll_item* item);

extern const fd_entry_ops epoll_fd_ops;


int req_epoll_create(void);
int req_epoll_ctl(fd_entry* entry, int op, int sockfd, struct epoll_event* event);
int req_epoll_wait(fd_entry* entry, struct epoll_event* events,
                   int maxevents, int timeout_ms);
int req_epoll_close(fd_entry* entry);

/* worker-side handler for REQ_EPOLL_CTL */
void _epoll_ctl(req* r);

#endif
