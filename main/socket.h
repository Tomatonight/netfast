#ifndef SOCKET_H
#define SOCKET_H
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "skbuff.h"
#include "base.h"
#include "hash.h"
#include "queue.h"
#include "fd_entry.h"
#include "route_arp_ndp.h"
#include "req.h"
#include "list.h"

#define REQ_PENDING (-2)

typedef struct bind_slot bind_slot;
typedef struct bind_table bind_table;
typedef struct icmp_error_info icmp_error_info;

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

typedef struct addr_tuple {
    addr_key s_key;
    addr_key d_key;
} addr_tuple;

typedef struct protocol_ops {
    int protocol;
    int (*pcb_init)(struct Socket* sock);
    int (*icmp_process)(struct Socket* sock, const icmp_error_info* info,
                        int err);
    int (*read)(struct Socket* sock, req* req, void* buf, uint32_t len);
    int (*write)(struct Socket* sock, req* req, const void* buf, uint32_t len);
    int (*recvfrom)(struct Socket* sock, req* req, void* buf, uint32_t len, int flags, sockaddr_in* addr, socklen_t* addrlen);
    int (*sendto)(struct Socket* sock, req* req, const void* buf, uint32_t len, int flags, sockaddr_in* addr, socklen_t addrlen);
    int (*release)(struct Socket* sock, req* req);
    int (*connect)(struct Socket* sock, req* req, const struct sockaddr_in* addr, socklen_t addrlen);
    int (*bind)(struct Socket* sock, req* req, const struct sockaddr_in* addr, socklen_t addrlen);
    int (*listen)(struct Socket* sock, req* req, int backlog);
    int (*accept)(struct Socket* sock, req* req, struct sockaddr_in* addr, socklen_t* addrlen);
    int (*getsockname)(struct Socket* sock, req* req, struct sockaddr_in* addr, socklen_t* addrlen);
    int (*getpeername)(struct Socket* sock, req* req, struct sockaddr_in* addr, socklen_t* addrlen);
    int (*setsockopt)(struct Socket* sock, req* req, int level, int optname, const void* optval, socklen_t optlen);
    int (*getsockopt)(struct Socket* sock, req* req, int level, int optname, void* optval, socklen_t* optlen);
    uint32_t (*poll)(struct Socket* sock);
    int (*shutdown)(struct Socket* sock, req* req, int how);
} protocol_ops;

typedef struct Socket {
    worker* owner;
    fd_entry* fd_entry;
    int family;
    int type;
    int protocol;

    /* fcntl(F_GETFL/F_SETFL) emulation: only a subset (e.g. O_NONBLOCK). */
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
    uint32_t recv_buffer_len;
    uint32_t recv_buffer_len_max;
    queue send_queue;
    uint32_t send_buffer_len;
    uint32_t send_buffer_len_max;

    route_info* route;
    protocol_ops* protocol_ops;
    void* pcb;

    int error;

    list_node tuple_node;
    bind_slot* bind_reservation;


	list_node pending;
	task* pending_task;

	uint32_t notified_events;
} Socket;

void socket_notify_event(Socket* sock, enum notify_event event);
Socket* create_socket(int family, int type, int protocol);

void _socket(req* req);
void _read(req* req);
void _write(req* req);
void _close(req* req);
void _shutdown(req* req);
void _connect(req* req);
void _bind(req* req);
void _listen(req* req);
void _accept(req* req);
void _sendto(req* req);
void _recvfrom(req* req);
void _getsockname(req* req);
void _getpeername(req* req);
void _setsockopt(req* req);
void _getsockopt(req* req);
void _fcntl(req* req);
void _poll(req* req);

int socket_setsockopt(struct Socket* sock, int level, int optname, const void* optval, socklen_t optlen);
int socket_getsockopt(struct Socket* sock, int level, int optname, void* optval, socklen_t* optlen);

Socket* search_socket_by_tuple(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, hash* h, worker** socket_worker);
Socket* search_socket_by_tuple6(const uint8_t saddr[16], uint16_t sport,
                                const uint8_t daddr[16], uint16_t dport,
                                hash* h, worker** socket_worker);
bool install_tuple(Socket* sock, hash* tuple_hash);
bool uninstall_tuple(Socket* sock, hash* tuple_hash);
bind_table* bind_table_create(void);
void bind_table_destroy(bind_table* table);
bool bind_saddr(Socket* sock, const addr_key* key, bind_table* bound_table);
bool unbind_saddr(Socket* sock, bind_table* bound_table);
bool bind_exist(const addr_key* key, const bind_table* bound_table);

void set_skb_by_socket(skbuff* skb, Socket* sock);
int set_socket_route(Socket* sock, const uint8_t* dest_ip, uint32_t scope_id);
void destroy_socket(Socket* sock);

int socket_auto_bind(Socket* sock, bind_table* bound_table,
                      const uint8_t* dest_ip, uint16_t dest_port,
                      uint32_t scope_id);

Socket* socket_select(Socket* sock, uint32_t rss);
void set_socket_worker(Socket* sock, worker* w);
void socket_detach_with_fd_entry(Socket* sock);

#endif
