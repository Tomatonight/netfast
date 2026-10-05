#ifndef SOCKET_H
#define SOCKET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "base.h"
#include "fd_entry.h"
#include "hash.h"
#include "list.h"
#include "queue.h"
#include "req.h"
#include "route_arp_ndp.h"
#include "skbuff.h"

typedef struct bind_slot bind_slot;
typedef struct bind_table bind_table;
typedef struct tuple_entry tuple_entry;
typedef struct icmp_error_info icmp_error_info;
typedef struct ip_metrics ip_metrics;
struct thread;

#define SOCKET_USEABLE_RECV_BUFF_SIZE(sock) \
    ((sock)->recv_buffer_len_max > (sock)->recv_buffer_len ? \
        (sock)->recv_buffer_len_max - (sock)->recv_buffer_len : 0)
#define SOCKET_USEABLE_SEND_BUFF_SIZE(sock) \
    ((sock)->send_buffer_len_max > (sock)->send_buffer_len ? \
        (sock)->send_buffer_len_max - (sock)->send_buffer_len : 0)

typedef struct addr_key {
    union {
        uint32_t addr;
        uint8_t addr6[16];
    };
    uint16_t port;
    uint16_t family; /* AF_INET or AF_INET6 */
    uint32_t scope_id;
} addr_key;

typedef struct protocol_ops {
    int protocol;
    int (*pcb_init)(struct Socket *sock);
    int (*icmp_process)(struct Socket *sock, const icmp_error_info *info,
                        int err);
    /* A NULL req means a worker-local, non-blocking attempt.  Protocol
     * implementations must return -EAGAIN instead of attaching a waiter. */
    int (*read)(struct Socket *sock, req *req, void *buf, uint32_t len);
    int (*write)(struct Socket *sock, req *req, const void *buf, uint32_t len);
    int (*recvfrom)(struct Socket *sock, req *req, void *buf, uint32_t len, int flags, sockaddr_in *addr, socklen_t *addrlen);
    int (*sendto)(struct Socket *sock, req *req, const void *buf, uint32_t len, int flags, sockaddr_in *addr, socklen_t addrlen);

    int (*release)(struct Socket *sock, req *req);
    int (*connect)(struct Socket *sock, req *req, const struct sockaddr_in *addr, socklen_t addrlen);
    int (*bind)(struct Socket *sock, req *req, const struct sockaddr_in *addr, socklen_t addrlen);
    int (*listen)(struct Socket *sock, req *req, int backlog);
    int (*accept)(struct Socket *sock, req *req, struct sockaddr_in *addr, socklen_t *addrlen);
    int (*getsockname)(struct Socket *sock, req *req, struct sockaddr_in *addr, socklen_t *addrlen);
    int (*getpeername)(struct Socket *sock, req *req, struct sockaddr_in *addr, socklen_t *addrlen);
    int (*setsockopt)(struct Socket *sock, req *req, int level, int optname, const void *optval, socklen_t optlen);
    int (*getsockopt)(struct Socket *sock, req *req, int level, int optname, void *optval, socklen_t *optlen);
    int (*shutdown)(struct Socket *sock, req *req, int how);
} protocol_ops;

typedef struct Socket {
    worker *owner;
    fd_entry *fd_entry;
    int family;
    int type;
    int protocol;

    int file_flags;

    struct {
        uint32_t reuseaddr : 1;
        uint32_t reuseport : 1;
        uint32_t keepalive : 1;
        uint32_t broadcast : 1;
        uint32_t send_timeout : 1;
        uint32_t recv_timeout : 1;
        uint32_t linger:1;
    } options;
    struct timeval send_timeout;
    struct timeval recv_timeout;
    int linger_seconds;

    union {
        uint32_t sip;
        uint8_t  sip6[16];
    };
    uint32_t sip6_scope_id;
    uint16_t sport;
    union {
        uint32_t dip;
        uint8_t  dip6[16];
    };
    uint32_t dip6_scope_id;
    uint16_t dport;

    struct {
        uint32_t close_recv : 1;
        uint32_t close_send : 1;
        uint32_t is_bound : 1;
        uint32_t is_hash : 1;
        uint32_t is_connected : 1;
    } flag;

    queue recv_queue;
    uint32_t recv_buffer_len; /* bytes currently readable by the application */
    uint32_t recv_buffer_len_max;
    queue send_queue;
    uint32_t send_buffer_len;
    uint32_t send_buffer_len_max;

    route_info *route;
    ip_metrics *metrics;
    uint64_t route_generation;
    uint8_t route_dest[16];
    uint32_t route_scope_id;
    protocol_ops *protocol_ops;
    void *pcb;

    int error;

    list_node tuple_node;
    tuple_entry *tuple_entry;
    bind_slot *bind_reservation;

    list_node timer_migrate_node;


    list_node pending;
    task *pending_task;

    uint32_t notified_events;

    net_event_mask callback_events;
    net_callback callback;
    void *callback_arg;
} Socket;

void socket_notify_event(Socket *sock, enum notify_event event);
int socket_set_callback(Socket *sock, net_event_mask events,
                        net_callback cb, void *arg);

Socket *create_socket(int family, int type, int protocol);
void set_socket_worker(Socket *sock, worker *w);
void destroy_socket(Socket *sock);
void socket_detach_with_fd_entry(Socket *sock);
void socket_process_timer_migrations(task *tk);

void socket_process_create_request(req *req);
void socket_process_bind_request(req *req);
void socket_process_listen_request(req *req);
void socket_process_accept_request(req *req);
void socket_process_connect_request(req *req);
void socket_process_read_request(req *req);
void socket_process_write_request(req *req);
void socket_process_sendto_request(req *req);
void socket_process_recvfrom_request(req *req);
void socket_process_getsockname_request(req *req);
void socket_process_getpeername_request(req *req);
void socket_process_close_request(req *req);
void socket_process_shutdown_request(req *req);
void socket_process_setsockopt_request(req *req);
void socket_process_getsockopt_request(req *req);
void socket_process_fcntl_request(req *req);

int socket_setsockopt(struct Socket *sock, int level, int optname, const void *optval, socklen_t optlen);
int socket_getsockopt(struct Socket *sock, int level, int optname, void *optval, socklen_t *optlen);

Socket *search_socket_by_tuple(uint32_t saddr, uint16_t sport, uint32_t daddr,
                               uint16_t dport, hash *table,
                               worker ** socket_worker);
Socket *search_socket_by_tuple6(const uint8_t saddr[16], uint16_t sport,
                                const uint8_t daddr[16], uint16_t dport,
                                hash *table, worker ** socket_worker);
hash *tuple_hash_create(uint32_t size, int family);
bool install_tuple(Socket *sock, hash *table);
bool uninstall_tuple(Socket *sock, hash *table);
bind_table *bind_table_create(void);
void bind_table_destroy(bind_table *table);
bool bind_saddr(Socket *sock, const addr_key *key, bind_table *bound_table);
int socket_bind_local(Socket *sock, const struct sockaddr_in *addr,
                      socklen_t addrlen, bind_table *bound_table);
bool unbind_saddr(Socket *sock, bind_table *bound_table);
bool bind_exist(const addr_key *key, const bind_table *bound_table);

void set_skb_by_socket(skbuff *skb, Socket *sock);
bool socket_route_is_valid(const Socket *sock, const uint8_t *dest_ip,
                           uint32_t scope_id);
int set_socket_route(Socket *sock, const uint8_t *dest_ip, uint32_t scope_id);

int socket_auto_bind(Socket *sock, bind_table *bound_table,
                     const addr_key *local_key, const uint8_t *dest_ip,
                     uint16_t dest_port, uint32_t scope_id);

Socket *socket_select(Socket *sock, uint32_t rss);

#endif /* SOCKET_H */
