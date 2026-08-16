#include <errno.h>
#include <assert.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "socket.h"
#include "log.h"
#include "udp.h"
#include "queue.h"
#include "tcp.h"
#include "ip.h"
#include "if.h"
#include "fd_entry.h"
#ifdef TEST_EPOLL
#include "req_epoll.h"
#endif
#include "req_socket.h"
#include "worker.h"

/* Default buffer sizes are page-aligned (4 KB × N) for efficient memory
 * allocation and zero-copy page-flipping. */
#define SOCKET_DEFAULT_RECV_SIZE (4096 * 64)   /* 256 KB, 64 pages */
#define SOCKET_DEFAULT_SEND_SIZE (4096 * 64)   /* 256 KB, 64 pages */

#define BIND_BUCKET_COUNT 16384u
#define BIND_PORT_COUNT 65536u
#define BIND_SPECIFIC_ONE 1ULL
#define BIND_ANY_ONE (1ULL << 32)

#define EPHEMERAL_PORT_FIRST 1024u
#define EPHEMERAL_PORT_COUNT (65536u - EPHEMERAL_PORT_FIRST)

typedef struct tuple_key4 {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
} tuple_key4;

typedef struct tuple_key6 {
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint16_t sport;
    uint16_t dport;
} tuple_key6;

typedef union tuple_key {
    tuple_key6 key6;
    tuple_key4 key4;
} tuple_key;

struct tuple_entry {
    hash_node hash_node;
    list_node* sockets;
    tuple_key key;
};

_Static_assert(sizeof(tuple_key4) == 12, "IPv4 tuple key must stay compact");
_Static_assert(sizeof(tuple_key6) == 36,
               "IPv6 tuple key must stay compact");

static uint32_t tuple_hash_value(const void* key, uint32_t key_len)
{
    const uint8_t* bytes = key;
    uint32_t hash = 0x9747b28cu ^ key_len;

    for (uint32_t offset = 0; offset < key_len; offset += sizeof(uint32_t)) {
        uint32_t word;
        memcpy(&word, bytes + offset, sizeof(word));
        word *= 0xcc9e2d51u;
        word = (word << 15) | (word >> 17);
        word *= 0x1b873593u;
        hash ^= word;
        hash = (hash << 13) | (hash >> 19);
        hash = hash * 5u + 0xe6546b64u;
    }

    hash ^= key_len;
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;
    return hash;
}

hash* tuple_hash_create(uint32_t size, int family)
{
    if (family != AF_INET && family != AF_INET6)
        return NULL;
    uint32_t key_len = family == AF_INET ? sizeof(tuple_key4)
                                         : sizeof(tuple_key6);
    return hash_create_safe(size,
        HASH_KEY_OFFSET(tuple_entry, hash_node, key), key_len);
}

static uint32_t tuple_key_from_socket(const Socket* sock, tuple_key* key)
{
    if (sock->family == AF_INET6) {
        tuple_key6* key6 = &key->key6;
        memcpy(key6->saddr, sock->sip6, sizeof(key6->saddr));
        memcpy(key6->daddr, sock->dip6, sizeof(key6->daddr));
        key6->sport = sock->sport;
        key6->dport = sock->dport;
        return sizeof(*key6);
    }

    tuple_key4* key4 = &key->key4;
    key4->saddr = sock->sip;
    key4->daddr = sock->dip;
    key4->sport = sock->sport;
    key4->dport = sock->dport;
    return sizeof(*key4);
}

struct bind_slot {
    addr_key key;
    _Atomic uint32_t count;
    _Atomic(struct bind_slot*) next;
};

struct bind_table {
    _Atomic(struct bind_slot*) buckets[BIND_BUCKET_COUNT];
    /* High 32 bits: wildcard binds. Low 32 bits: specific-address binds. */
    _Atomic uint64_t ports[BIND_PORT_COUNT];
};

static void bind_hash_add(uint32_t* hash, const void* data, size_t len)
{
    const uint8_t* bytes = data;

    for (size_t i = 0; i < len; i++) {
        *hash ^= bytes[i];
        *hash *= 16777619u;
    }
}

static uint32_t bind_key_hash(const addr_key* key)
{
    uint32_t hash = 2166136261u;

    bind_hash_add(&hash, &key->family, sizeof(key->family));
    bind_hash_add(&hash, &key->port, sizeof(key->port));
    if (key->family == AF_INET6) {
        bind_hash_add(&hash, key->addr6, sizeof(key->addr6));
        bind_hash_add(&hash, &key->scope_id, sizeof(key->scope_id));
    } else {
        bind_hash_add(&hash, &key->addr, sizeof(key->addr));
    }
    return hash;
}

static bool bind_key_equal(const addr_key* a, const addr_key* b)
{
    if (a->family != b->family || a->port != b->port)
        return false;
    return a->family == AF_INET6
        ? a->scope_id == b->scope_id &&
          memcmp(a->addr6, b->addr6, sizeof(a->addr6)) == 0
        : a->addr == b->addr;
}

static bool bind_key_is_any(const addr_key* key)
{
    static const uint8_t zero[16];

    return key->family == AF_INET6
        ? memcmp(key->addr6, zero, sizeof(zero)) == 0
        : key->addr == INADDR_ANY;
}

static bind_slot* bind_find(const bind_table* table, const addr_key* key)
{
    bind_slot* slot = atomic_load_explicit(
        &table->buckets[bind_key_hash(key) % BIND_BUCKET_COUNT],
        memory_order_acquire);

    while (slot && !bind_key_equal(&slot->key, key))
        slot = atomic_load_explicit(&slot->next, memory_order_acquire);
    return slot;
}

static bool bind_port_reserve(bind_table* table, const addr_key* key,
                              bool reuse)
{
    bool any = bind_key_is_any(key);
    uint64_t add = any ? BIND_ANY_ONE : BIND_SPECIFIC_ONE;
    _Atomic uint64_t* state = &table->ports[ntohs(key->port)];
    uint64_t old = atomic_load_explicit(state, memory_order_relaxed);

    do {
        if (!reuse && (any ? old != 0 : (uint32_t)(old >> 32) != 0))
            return false;
    } while (!atomic_compare_exchange_weak_explicit(
        state, &old, old + add, memory_order_acq_rel, memory_order_relaxed));
    return true;
}

static void bind_port_release(bind_table* table, const addr_key* key)
{
    uint64_t sub = bind_key_is_any(key) ? BIND_ANY_ONE : BIND_SPECIFIC_ONE;
    uint64_t old = atomic_fetch_sub_explicit(
        &table->ports[ntohs(key->port)], sub, memory_order_acq_rel);

    assert((sub == BIND_ANY_ONE ? old >> 32 : (uint32_t)old) != 0);
    (void)old;
}

static bind_slot* bind_reserve(bind_table* table, const addr_key* key,
                               bool reuse)
{
    if (!bind_port_reserve(table, key, reuse))
        return NULL;

    uint32_t bucket = bind_key_hash(key) % BIND_BUCKET_COUNT;
    for (;;) {
        bind_slot* slot = bind_find(table, key);
        if (slot) {
            uint32_t count = atomic_load_explicit(&slot->count,
                                                  memory_order_relaxed);
            do {
                if (count && !reuse) {
                    bind_port_release(table, key);
                    return NULL;
                }
            } while (!atomic_compare_exchange_weak_explicit(
                &slot->count, &count, count + 1,
                memory_order_acq_rel, memory_order_relaxed));
            return slot;
        }

        slot = calloc(1, sizeof(*slot));
        if (!slot) {
            bind_port_release(table, key);
            return NULL;
        }
        slot->key = *key;
        atomic_init(&slot->count, 1);
        bind_slot* head = atomic_load_explicit(&table->buckets[bucket],
                                               memory_order_acquire);
        atomic_init(&slot->next, head);
        if (atomic_compare_exchange_strong_explicit(
                &table->buckets[bucket], &head, slot,
                memory_order_release, memory_order_acquire))
            return slot;
        free(slot);
    }
}

static void bind_release(bind_table* table, bind_slot* slot)
{
    uint32_t old = atomic_fetch_sub_explicit(&slot->count, 1,
                                             memory_order_acq_rel);
    assert(old != 0);
    (void)old;
    bind_port_release(table, &slot->key);
}

bind_table* bind_table_create(void)
{
    bind_table* table = calloc(1, sizeof(*table));
    if (!table)
        return NULL;
    for (uint32_t i = 0; i < BIND_BUCKET_COUNT; i++)
        atomic_init(&table->buckets[i], NULL);
    for (uint32_t i = 0; i < BIND_PORT_COUNT; i++)
        atomic_init(&table->ports[i], 0);
    return table;
}

void bind_table_destroy(bind_table* table)
{
    for (uint32_t i = 0; i < BIND_BUCKET_COUNT; i++) {
        bind_slot* slot = atomic_load_explicit(&table->buckets[i],
                                               memory_order_relaxed);
        while (slot) {
            bind_slot* next = atomic_load_explicit(&slot->next,
                                                   memory_order_relaxed);
            free(slot);
            slot = next;
        }
    }
    free(table);
}

typedef struct inet_ops{
    int family;
    int type;
    int protocol;
    protocol_ops* ops;
}inet_ops;

static inet_ops supported_inet_ops[] = {
    {AF_INET,  SOCK_DGRAM,  IPPROTO_UDP, &udp_protocol_ops},
    {AF_INET,  SOCK_DGRAM,  0,           &udp_protocol_ops},
    {AF_INET,  SOCK_STREAM, IPPROTO_TCP, &tcp_protocol_ops},
    {AF_INET,  SOCK_STREAM, 0,           &tcp_protocol_ops},
    {AF_INET6, SOCK_DGRAM,  IPPROTO_UDP, &udp_protocol_ops},
    {AF_INET6, SOCK_DGRAM,  0,           &udp_protocol_ops},
    {AF_INET6, SOCK_STREAM, IPPROTO_TCP, &tcp_protocol_ops},
    {AF_INET6, SOCK_STREAM, 0,           &tcp_protocol_ops},
};

static void req_fail(req *r, int error)
{
    req_notify(r, -error);
}

static protocol_ops* find_inet_ops(int family, int type, int *protocol){
    for(uint32_t i=0;i<sizeof(supported_inet_ops)/sizeof(inet_ops);i++){
        if(supported_inet_ops[i].family==family && supported_inet_ops[i].type==type
             && supported_inet_ops[i].protocol==*protocol){
            if(!supported_inet_ops[i].ops)
                return NULL;
            if(supported_inet_ops[i].protocol==0)
                *protocol = supported_inet_ops[i].ops->protocol;
            return supported_inet_ops[i].ops;
        }
    }
    return NULL;
}

void set_socket_worker(Socket* sock, worker* w)
{

    if (sock->fd_entry)
        fd_entry_set_worker(sock->fd_entry, w);

    sock->owner = w;

    if (sock->pending_task && sock->pending_task->parent_thread != w->master){
        unregister_task(sock->pending_task);
        register_task(w->master, sock->pending_task);
    }

    if (sock->protocol == IPPROTO_TCP && sock->pcb) {
        tcp_pcb* pcb = (tcp_pcb*)sock->pcb;

        if (pcb->timer_task && pcb->timer_task->parent_thread != w->master) {
            unregister_task(pcb->timer_task);
            register_task(w->master, pcb->timer_task);
        }

    }

}

static hash* select_tuple_hash_by_protocol(int protocol, int family)
{
    switch (protocol) {
    case IPPROTO_UDP:
        return udp_tuple_hash(family);
    case IPPROTO_TCP:
        return tcp_tuple_hash(family);
    default:
        return NULL;
    }
}

static bind_table* select_bound_table_by_protocol(int protocol, int family)
{
    switch (protocol) {
    case IPPROTO_UDP:
        return udp_bound_table(family);
    case IPPROTO_TCP:
        return tcp_bound_table(family);
    default:
        return NULL;
    }
}

Socket* create_socket(int family, int type, int protocol){
    protocol_ops* ops = find_inet_ops(family, type, &protocol);
    if(!ops){
        DEBUG_LOG("_socket: unsupported Socket type: family=%d, type=%d, protocol=%d", family, type, protocol);
        return NULL;
    }
    Socket* sock = calloc(1, sizeof(*sock));
    if(!sock){
        ERR_LOG("_socket: failed to allocate Socket");
        return NULL;
    }
    sock->family=family;
    sock->type=type;
    sock->protocol=protocol;
    sock->protocol_ops = ops;
    init_queue(&sock->recv_queue);
    init_queue(&sock->send_queue);
    sock->recv_buffer_len_max = SOCKET_DEFAULT_RECV_SIZE;
    sock->send_buffer_len_max = SOCKET_DEFAULT_SEND_SIZE;

    if(ops->pcb_init){
        int ret = ops->pcb_init(sock);
        if(ret<0){
            free(sock);
            return NULL;
        }
    }
    return sock;
}

void _socket(req* r)
{
    int family = r->argv.Socket.family;
    int type = r->argv.Socket.type;
    int protocol = r->argv.Socket.protocol;
    Socket* sock = NULL;

    protocol_ops* ops = find_inet_ops(family, type, &protocol);
    if(!ops){
        DEBUG_LOG("_socket: unsupported Socket type: family=%d, type=%d, protocol=%d", family, type, protocol);
        req_fail(r, EAFNOSUPPORT);
        return;
    }
    sock=create_socket(family, type, protocol);
    if(!sock){
        req_fail(r, ENOMEM);
        return;
    }

    worker* owner = get_current_worker();
    fd_entry* entry = alloc_fd_entry_with_worker(sock, &socket_fd_ops, owner);
    if(!entry){
        ERR_LOG("_socket: failed to allocate fd entry");
        goto fail;
    }
    sock->fd_entry = entry;
    set_socket_worker(sock, owner);

    req_notify(r, entry->fd);
    return;
fail:
    if (ops->release)
        ops->release(sock, NULL);
    else
        destroy_socket(sock);
    req_fail(r, EMFILE);
}

void _fcntl(req* r)
{
    fd_entry* entry = r->argv.fcntl.entry;
    int cmd = r->argv.fcntl.cmd;

    Socket* sock = (Socket*)entry->value;
    if (!sock) {
        req_fail(r, EBADF);
        return;
    }

    switch (cmd) {
    case F_GETFL:
        req_notify(r, sock->file_flags);
        return;
    case F_SETFL: {
        int flags = r->argv.fcntl.arg;
        sock->file_flags = (flags & O_NONBLOCK);
        req_notify(r, 0);
        return;
    }
    default:
        req_fail(r, EINVAL);
        return;
    }
}

void _read(req* r)
{
    fd_entry* entry = r->argv.read.entry;
    void *buf = r->argv.read.buf;
    uint32_t len = r->argv.read.len;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if (len == 0) {
        req_notify(r, 0);
        return;
    }
    if(buf==NULL){
        req_fail(r, EFAULT);
        return;
    }
    if(!sock->protocol_ops->read){
        req_fail(r, EOPNOTSUPP);
        return;
    }

    int ret = sock->protocol_ops->read(sock, r, buf, len);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _write(req* r)
{
    fd_entry* entry = r->argv.write.entry;
    const void *buf = r->argv.write.buf;
    uint32_t len = r->argv.write.len;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if (len == 0) {
        req_notify(r, 0);
        return;
    }
    if(buf==NULL){
        req_fail(r, EFAULT);
        return;
    }
    if (sock->flag.close_send) {
        req_fail(r, EPIPE);
        return;
    }
    if(!sock->protocol_ops->write){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int ret = sock->protocol_ops->write(sock, r, buf, len);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _bind(req* r)
{
    fd_entry* entry = r->argv.bind.entry;
    const struct sockaddr_in *addr = (const struct sockaddr_in*)&r->argv.bind.addr;
    socklen_t addrlen = r->argv.bind.addrlen;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if(!sock->protocol_ops->bind){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int ret = sock->protocol_ops->bind(sock, r, addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _listen(req* r)
{
    fd_entry* entry = r->argv.listen.entry;
    int backlog = r->argv.listen.backlog;

    Socket* sock = (Socket*)entry->value;
    if (!sock) {
        req_fail(r, EBADF);
        return;
    }
    if (!sock->protocol_ops->listen) {
        req_fail(r, EOPNOTSUPP);
        return;
    }

    int ret = sock->protocol_ops->listen(sock, r, backlog);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _accept(req* r)
{
    fd_entry* entry = r->argv.accept.entry;
    struct sockaddr_in* addr = (struct sockaddr_in*)r->argv.accept.addr;
    socklen_t* addrlen = r->argv.accept.addrlen;

    Socket* sock = (Socket*)entry->value;
    if (!sock) {
        req_fail(r, EBADF);
        return;
    }
    if (!sock->protocol_ops->accept) {
        req_fail(r, EOPNOTSUPP);
        return;
    }

    int ret = sock->protocol_ops->accept(sock, r, addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _connect(req* r)
{
    fd_entry* entry = r->argv.connect.entry;
    const struct sockaddr_in *addr = (const struct sockaddr_in*)&r->argv.connect.addr;
    socklen_t addrlen = r->argv.connect.addrlen;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if(!sock->protocol_ops->connect){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int ret = sock->protocol_ops->connect(sock, r, addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _sendto(req* r)
{
    fd_entry* entry = r->argv.sendto.entry;
    const void *buf = r->argv.sendto.buf;
    uint32_t len = r->argv.sendto.len;
    const struct sockaddr_in *dest_addr = r->argv.sendto.has_dest_addr
        ? (const struct sockaddr_in*)&r->argv.sendto.dest_addr : NULL;
    socklen_t addrlen = r->argv.sendto.addrlen;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if (len != 0 && buf == NULL) {
        req_fail(r, EFAULT);
        return;
    }

    if (sock->flag.close_send) {
        req_fail(r, EPIPE);
        return;
    }
    socklen_t required = sock->family == AF_INET6
        ? (socklen_t)sizeof(struct sockaddr_in6)
        : (socklen_t)sizeof(struct sockaddr_in);
    /* sendto on a connected socket accepts a NULL destination. */
    if (dest_addr && addrlen < required) {
        req_fail(r, EINVAL);
        return;
    }
    if (dest_addr && dest_addr->sin_family != sock->family) {
        req_fail(r, EAFNOSUPPORT);
        return;
    }
    if (!dest_addr && !sock->flag.is_connected) {
        req_fail(r, EDESTADDRREQ);
        return;
    }
    if(!sock->protocol_ops->sendto){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int flags = r->argv.sendto.flags;
    int ret = sock->protocol_ops->sendto(sock, r, buf, len, flags, (sockaddr_in*)dest_addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _recvfrom(req* r)
{
    fd_entry* entry = r->argv.recvfrom.entry;
    void *buf = r->argv.recvfrom.buf;
    uint32_t len = r->argv.recvfrom.len;
    sockaddr_in* addr = (sockaddr_in*)r->argv.recvfrom.src_addr;
    socklen_t* addrlen = r->argv.recvfrom.addrlen;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if(len != 0 && buf == NULL){
        req_fail(r, EFAULT);
        return;
    }
    if (sock->flag.close_recv) {
        req_notify(r, 0);
        return;
    }
    /* A NULL source-address pointer means the address length is ignored. */
    if(addr != NULL && addrlen == NULL){
        req_fail(r, EFAULT);
        return;
    }
    if(!sock->protocol_ops->recvfrom){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int flags = r->argv.recvfrom.flags;
    int ret = sock->protocol_ops->recvfrom(sock, r, buf, len, flags, addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _getsockname(req* r)
{
    fd_entry* entry = r->argv.getsockname.entry;
    struct sockaddr_in *addr = (struct sockaddr_in*)r->argv.getsockname.addr;
    socklen_t *addrlen = r->argv.getsockname.addrlen;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if(!addr || !addrlen){
        req_fail(r, EFAULT);
        return;
    }
    if(!sock->protocol_ops->getsockname){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int ret = sock->protocol_ops->getsockname(sock, r, addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _getpeername(req* r)
{
    fd_entry* entry = r->argv.getpeername.entry;
    struct sockaddr_in *addr = (struct sockaddr_in*)r->argv.getpeername.addr;
    socklen_t *addrlen = r->argv.getpeername.addrlen;

    Socket* sock = (Socket*)entry->value;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if(!addr || !addrlen){
        req_fail(r, EFAULT);
        return;
    }
    if(!sock->protocol_ops->getpeername){
        req_fail(r, EOPNOTSUPP);
        return;
    }
    int ret = sock->protocol_ops->getpeername(sock, r, addr, addrlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _close(req* r)
{
    fd_entry* entry = r->argv.close.entry;
    Socket* sock = (Socket*)entry->value;
    bool linger_retry = r->status == REQ_WAITING_CLOSE;

    if (!sock && linger_retry)
        sock = r->wait_sock;
    if(!sock){
        req_fail(r, EBADF);
        return;
    }

    if(!sock->protocol_ops->release){
        req_fail(r, EOPNOTSUPP);
        return;
    }

    if (!linger_retry) {
        socket_detach_with_fd_entry(sock);
        PUT_REF(entry); /* release the fd table's ownership */
    }
    int ret = sock->protocol_ops->release(sock, r);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _shutdown(req* r)
{
    fd_entry* entry = r->argv.shutdown.entry;
    int how = r->argv.shutdown.how;
    Socket* sock = (Socket*)entry->value;
    if (!sock) {
        req_fail(r, EBADF);
        return;
    }

    /* Protocol-specific shutdown (e.g. TCP sends FIN) */
    if (sock->protocol_ops && sock->protocol_ops->shutdown) {
        int ret = sock->protocol_ops->shutdown(sock, r, how);
        if (ret != REQ_PENDING)
            req_notify(r, ret);
        return;
    }

    /* Generic fallback for protocols without shutdown handling. */
    switch (how) {
    case SHUT_RD:
        sock->flag.close_recv = 1;
        break;
    case SHUT_WR:
        sock->flag.close_send = 1;
        break;
    case SHUT_RDWR:
        sock->flag.close_recv = 1;
        sock->flag.close_send = 1;
        break;
    default:
        req_fail(r, EINVAL);
        return;
    }

    req_notify(r, 0);
}

void _setsockopt(req* r)
{
    fd_entry* entry = r->argv.setsockopt.entry;
    int level = r->argv.setsockopt.level;
    int optname = r->argv.setsockopt.optname;
    const void* optval = r->argv.setsockopt.optval;
    socklen_t optlen = r->argv.setsockopt.optlen;

    Socket* sock = (Socket*)entry->value;
    if (!sock) {
        req_fail(r, EBADF);
        return;
    }

    if (optval == NULL) {
        req_fail(r, EFAULT);
        return;
    }
    if (optlen == 0) {
        req_fail(r, EINVAL);
        return;
    }

    if (!sock->protocol_ops || !sock->protocol_ops->setsockopt) {
        req_fail(r, ENOPROTOOPT);
        return;
    }

    int ret = sock->protocol_ops->setsockopt(sock, r, level, optname, optval, optlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}

void _getsockopt(req* r)
{
    fd_entry* entry = r->argv.getsockopt.entry;
    int level = r->argv.getsockopt.level;
    int optname = r->argv.getsockopt.optname;
    void* optval = r->argv.getsockopt.optval;
    socklen_t* optlen = r->argv.getsockopt.optlen;

    Socket* sock = (Socket*)entry->value;
    if (!sock) {
        req_fail(r, EBADF);
        return;
    }
    if (!optval || !optlen) {
        req_fail(r, EFAULT);
        return;
    }
    if (*optlen == 0) {
        req_fail(r, EINVAL);
        return;
    }

    if (!sock->protocol_ops || !sock->protocol_ops->getsockopt) {
        req_fail(r, ENOPROTOOPT);
        return;
    }

    int ret = sock->protocol_ops->getsockopt(sock, r, level, optname, optval, optlen);
    if (ret != REQ_PENDING) {
        req_notify(r, ret);
    }
}



void _poll(req* r)
{
    Socket* sock = (Socket*)r->argv.poll.entry->value;
    if (!sock || !sock->protocol_ops->poll) {
        req_fail(r, EBADF);
        return;
    }
    uint32_t mask = sock->protocol_ops->poll(sock);
    if (r->argv.poll.poll_cb)
        r->argv.poll.poll_cb(sock, mask, r->argv.poll.cb_argv);
    req_notify(r, (int)mask);
}

bool install_tuple(Socket* sock, hash* table)
{
    if (sock->flag.is_hash) {
        if (!uninstall_tuple(sock, table)) {
            ERR_LOG("install_tuple: failed to remove existing tuple for sock %p", sock);
            return false;
        }
    }

    tuple_key key = {0};
    uint32_t key_len = tuple_key_from_socket(sock, &key);
    if (!table || table->key_len != key_len)
        return false;

    uint32_t value = tuple_hash_value(&key, key_len);
    uint32_t index = hash_bucket_index(table, value);
    HASH_BUCKET_WRLOCK(table, index);

    hash_node* node = hash_find_node_locked(table, index, &key, value);
    tuple_entry* entry = node
        ? HASH_CONTAINER_OF(node, tuple_entry, hash_node) : NULL;
    list_node* head = entry ? entry->sockets : NULL;

    if (head) {
        static const uint8_t zero6[16];
        bool has_peer = sock->family == AF_INET6
            ? memcmp(sock->dip6, zero6, sizeof(zero6)) != 0
            : sock->dip != 0;
        if (has_peer) {
            HASH_BUCKET_UNLOCK(table, index);
            return false;
        }

        /* Duplicate listener/unconnected tuples form a receive-selection
         * group only when every member explicitly opted into REUSEPORT.
         * REUSEADDR affects the bind reservation, not packet demultiplexing. */
        if (!sock->options.reuseport) {
            HASH_BUCKET_UNLOCK(table, index);
            return false;
        }

        for (list_node* n = head; n; n = n->next) {
            Socket* member = (Socket*)((uint8_t*)n - offsetof(Socket, tuple_node));
            if (!member->options.reuseport) {
                HASH_BUCKET_UNLOCK(table, index);
                return false;
            }
            if (n == &sock->tuple_node) {
                /* 已经在链上：视为成功 */
                sock->tuple_entry = entry;
                sock->flag.is_hash = 1;
                HASH_BUCKET_UNLOCK(table, index);
                return true;
            }
        }

        add_list_node(head, &sock->tuple_node);
        sock->tuple_entry = entry;
        sock->flag.is_hash = 1;
        HASH_BUCKET_UNLOCK(table, index);
        return true;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        HASH_BUCKET_UNLOCK(table, index);
        return false;
    }
    memcpy(&entry->key, &key, key_len);
    entry->sockets = &sock->tuple_node;
    hash_link_node_locked(table, index, &entry->hash_node, value);
    sock->tuple_entry = entry;
    sock->flag.is_hash = 1;
    HASH_BUCKET_UNLOCK(table, index);
    return true;
}

bool uninstall_tuple(Socket* sock, hash* table)
{
    if (!sock->flag.is_hash)
        return true;
    tuple_entry* entry = sock->tuple_entry;
    if (!table || !entry) {
        ERR_LOG("uninstall_tuple: not found");
        return false;
    }

    uint32_t index = hash_bucket_index(table, entry->hash_node.hash);
    HASH_BUCKET_WRLOCK(table, index);

    list_node* head = entry->sockets;
    if (!entry->hash_node.pprev || !head) {
        ERR_LOG("uninstall_tuple: entry is not in the tuple table");
        HASH_BUCKET_UNLOCK(table, index);
        return false;
    }

    bool node_found = false;
    for (list_node* node = head; node; node = node->next) {
        if (node == &sock->tuple_node) {
            node_found = true;
            break;
        }
    }
    if (!node_found) {
        ERR_LOG("uninstall_tuple: socket node is not in the tuple group");
        HASH_BUCKET_UNLOCK(table, index);
        return false;
    }

    bool free_entry = false;
    if (head == &sock->tuple_node) {
        if (sock->tuple_node.next) {
            entry->sockets = sock->tuple_node.next;
            remove_list_node(&sock->tuple_node);
        } else {
            hash_unlink_node_locked(&entry->hash_node);
            free_entry = true;
        }
    } else {
        remove_list_node(&sock->tuple_node);
    }

    sock->tuple_entry = NULL;
    sock->flag.is_hash = 0;
    HASH_BUCKET_UNLOCK(table, index);
    if (free_entry)
        free(entry);
    return true;
}

static void socket_set_bind_reservation(Socket* sock, const addr_key* key,
                                        bind_slot* reservation)
{
    if (key->family == AF_INET6)
        memcpy(sock->sip6, key->addr6, 16);
    else
        sock->sip = key->addr;
    sock->sport = key->port;
    sock->sip6_scope_id = key->family == AF_INET6 ? key->scope_id : 0;
    sock->bind_reservation = reservation;
    sock->flag.is_bound = 1;
}

bool bind_saddr(Socket* sock, const addr_key* key, bind_table* bound_table)
{
    if (sock->bind_reservation)
        return false;

    bind_slot* reservation = bind_reserve(
        bound_table, key, sock->options.reuseaddr || sock->options.reuseport);
    if (!reservation)
        return false;

    socket_set_bind_reservation(sock, key, reservation);
    return true;
}

int socket_bind_local(Socket* sock, const struct sockaddr_in* addr,
                      socklen_t addrlen, bind_table* bound_table)
{
    if (!addr)
        return -EFAULT;
    if (sock->flag.is_bound)
        return -EINVAL;

    bool is_v6 = sock->family == AF_INET6;
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)addr;
    if (addrlen < (is_v6 ? sizeof(*addr6) : sizeof(*addr)))
        return -EINVAL;
    if (addr->sin_family != sock->family)
        return -EAFNOSUPPORT;

    const uint8_t* ip = is_v6 ? (const uint8_t*)&addr6->sin6_addr
                              : (const uint8_t*)&addr->sin_addr.s_addr;
    uint32_t scope_id = is_v6 ? addr6->sin6_scope_id : 0;
    if (is_v6 && IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) && !scope_id) {
        DEBUG_LOG("IPv6 link-local bind requires a scope ID (e.g. fe80::1%%eth0)");
        return -EINVAL;
    }

    static const uint8_t zero6[16];
    bool any = is_v6 ? memcmp(ip, zero6, sizeof(zero6)) == 0
                     : addr->sin_addr.s_addr == INADDR_ANY;
    if (!any && !search_addr_exist(sock->family, ip, scope_id)) {
        DEBUG_LOG("Bind address is not available for family=%d", sock->family);
        return -EADDRNOTAVAIL;
    }

    addr_key key = {
        .port = is_v6 ? addr6->sin6_port : addr->sin_port,
        .family = sock->family,
        .scope_id = scope_id,
    };
    if (is_v6)
        memcpy(key.addr6, ip, sizeof(key.addr6));
    else
        memcpy(&key.addr, ip, sizeof(key.addr));

    if (!key.port)
        return socket_auto_bind(sock, bound_table, &key, NULL, 0, 0);
    return bind_saddr(sock, &key, bound_table) ? 0 : -EADDRINUSE;
}

bool bind_exist(const addr_key* key, const bind_table* bound_table)
{
    bind_slot* slot = bind_find(bound_table, key);
    return slot && atomic_load_explicit(&slot->count,
                                        memory_order_acquire) != 0;
}
bool unbind_saddr(Socket* sock, bind_table* bound_table)
{
    if (!sock->bind_reservation)
        return false;

    bind_release(bound_table, sock->bind_reservation);
    sock->bind_reservation = NULL;
    sock->flag.is_bound = 0;
    memset(sock->sip6, 0, sizeof(sock->sip6));
    sock->sip6_scope_id = 0;
    sock->sport         = 0;
    return true;
}

Socket* search_socket_by_tuple(uint32_t saddr, uint16_t sport,
                               uint32_t daddr, uint16_t dport,
                               hash* table, worker** socket_worker)
{
    tuple_key4 key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
    };
    uint32_t value = tuple_hash_value(&key, sizeof(key));
    uint32_t index = hash_bucket_index(table, value);
    HASH_BUCKET_RDLOCK(table, index);

    hash_node* hash_entry = hash_find_node_locked(table, index, &key, value);
    tuple_entry* entry = hash_entry
        ? HASH_CONTAINER_OF(hash_entry, tuple_entry, hash_node) : NULL;
    list_node* socket_node = entry ? entry->sockets : NULL;
    Socket* sock = socket_node
        ? (Socket*)((uint8_t*)socket_node - offsetof(Socket, tuple_node)) : NULL;
    if (socket_worker)
        *socket_worker = sock ? sock->owner : NULL;

    HASH_BUCKET_UNLOCK(table, index);
    return sock;
}

Socket* search_socket_by_tuple6(const uint8_t saddr[16], uint16_t sport,
                                const uint8_t daddr[16], uint16_t dport,
                                hash* table, worker** socket_worker)
{
    tuple_key6 key = {
        .sport = sport,
        .dport = dport,
    };
    memcpy(key.saddr, saddr, sizeof(key.saddr));
    memcpy(key.daddr, daddr, sizeof(key.daddr));

    uint32_t value = tuple_hash_value(&key, sizeof(key));
    uint32_t index = hash_bucket_index(table, value);
    HASH_BUCKET_RDLOCK(table, index);

    hash_node* hash_entry = hash_find_node_locked(table, index, &key, value);
    tuple_entry* entry = hash_entry
        ? HASH_CONTAINER_OF(hash_entry, tuple_entry, hash_node) : NULL;
    list_node* socket_node = entry ? entry->sockets : NULL;
    Socket* sock = socket_node
        ? (Socket*)((uint8_t*)socket_node - offsetof(Socket, tuple_node)) : NULL;
    if (socket_worker)
        *socket_worker = sock ? sock->owner : NULL;

    HASH_BUCKET_UNLOCK(table, index);
    return sock;
}

int set_socket_route(Socket* sock, const uint8_t* dest_ip, uint32_t scope_id)
{
    if (sock->family == AF_INET6) {
        if (sock->route && route_info_check(sock->route))
            return 0;

        PUT_REF(sock->route);
        sock->route = NULL;
        route_key key = { .ip_family = AF_INET6 };
        key.ifindex = scope_id;
        memcpy(key.dip, dest_ip, 16);
        route_info* route = search_route_table(&key);
        MOVE_REF(sock->route, route);
        return sock->route ? 0 : -1;
    }

    /* IPv4 */
    if (sock->route && route_info_check(sock->route))
        return 0;
    PUT_REF(sock->route);
    route_key key = { .ip_family = AF_INET };
    memcpy(key.dip, dest_ip, 4);
    route_info* route = search_route_table(&key);
    MOVE_REF(sock->route, route);
    return sock->route != NULL ? 0 : -1;
}

static bool valid_timeval(const struct timeval* tv)
{
    return tv->tv_sec >= 0 && tv->tv_usec >= 0 && tv->tv_usec < 1000000;
}

int socket_setsockopt(struct Socket* sock, int level, int optname, const void* optval, socklen_t optlen){
    const int *ival = (const int *)optval;
    if(level!=SOL_SOCKET)
        return -ENOPROTOOPT;
    switch(optname){
        case SO_REUSEADDR: {
            if (optlen < (socklen_t)sizeof(int))
                return -EINVAL;
            sock->options.reuseaddr = (*ival != 0);
            return 0;
        }
        case SO_REUSEPORT: {
            if (optlen < (socklen_t)sizeof(int))
                return -EINVAL;
            sock->options.reuseport = (*ival != 0);
            return 0;
        }
        case SO_BROADCAST: {
            if (optlen < (socklen_t)sizeof(int))
                return -EINVAL;
            sock->options.broadcast = (*ival != 0);
            return 0;
        }
        case SO_RCVBUF: {
            if (optlen < (socklen_t)sizeof(int))
                return -EINVAL;
            int v = *ival;
            if (v < 0)
                return -EINVAL;
            sock->recv_buffer_len_max = (uint32_t)v;
            return 0;
        }
        case SO_SNDBUF: {
            if (optlen < (socklen_t)sizeof(int))
                return -EINVAL;
            int v = *ival;
            if (v < 0)
                return -EINVAL;
            sock->send_buffer_len_max = (uint32_t)v;
            return 0;
        }
        case SO_RCVTIMEO: {
            if (optlen < (socklen_t)sizeof(struct timeval))
                return -EINVAL;
            const struct timeval* tv = optval;
            if (!valid_timeval(tv))
                return -EINVAL;
            sock->recv_timeout = *tv;
            sock->options.recv_timeout = tv->tv_sec != 0 || tv->tv_usec != 0;
            return 0;
        }
        case SO_SNDTIMEO: {
            if (optlen < (socklen_t)sizeof(struct timeval))
                return -EINVAL;
            const struct timeval* tv = optval;
            if (!valid_timeval(tv))
                return -EINVAL;
            sock->send_timeout = *tv;
            sock->options.send_timeout = tv->tv_sec != 0 || tv->tv_usec != 0;
            return 0;
        }
        case SO_KEEPALIVE: {
            if (optlen < (socklen_t)sizeof(int))
                return -EINVAL;
            sock->options.keepalive = (*ival != 0);
            return 0;
        }
        case SO_LINGER: {
           
            if (optlen < (socklen_t)sizeof(struct linger))
                return -EINVAL;
            const struct linger* linger = optval;
            if (linger->l_linger < 0)
                return -EINVAL;
            sock->options.linger = linger->l_onoff != 0;
            sock->linger_seconds = linger->l_linger;
            return 0;
        }
        default:
            return -ENOPROTOOPT;
    }  
}

/* SOL_SOCKET getsockopt helper: return 0 on success, negative errno on failure.
 * Caller must pass in/out optlen like standard getsockopt.
 */
int socket_getsockopt(struct Socket* sock, int level, int optname, void* optval, socklen_t* optlen)
{
    if (!sock || !optval || !optlen)
        return -EFAULT;
    if (level != SOL_SOCKET)
        return -ENOPROTOOPT;
    if (*optlen == 0)
        return -EINVAL;

    socklen_t len = *optlen;
    switch (optname) {
    case SO_ERROR: {
        if (len < (socklen_t)sizeof(int)) return -EINVAL;
        int err = sock->error;
        sock->error = 0; /* consume */
        memcpy(optval, &err, sizeof(int));
        *optlen = (socklen_t)sizeof(int);
        return 0;
    }
    case SO_REUSEADDR:
    case SO_REUSEPORT:
    case SO_BROADCAST:
    case SO_KEEPALIVE: {
        if (len < (socklen_t)sizeof(int)) return -EINVAL;
        int v;
        switch (optname) {
        case SO_REUSEADDR: v = sock->options.reuseaddr; break;
        case SO_REUSEPORT: v = sock->options.reuseport; break;
        case SO_BROADCAST: v = sock->options.broadcast; break;
        default:           v = sock->options.keepalive; break;
        }
        memcpy(optval, &v, sizeof(int));
        *optlen = (socklen_t)sizeof(int);
        return 0;
    }
    case SO_RCVBUF: {
        if (len < (socklen_t)sizeof(int)) return -EINVAL;
        int v = (int)sock->recv_buffer_len_max;
        memcpy(optval, &v, sizeof(int));
        *optlen = (socklen_t)sizeof(int);
        return 0;
    }
    case SO_SNDBUF: {
        if (len < (socklen_t)sizeof(int)) return -EINVAL;
        int v = (int)sock->send_buffer_len_max;
        memcpy(optval, &v, sizeof(int));
        *optlen = (socklen_t)sizeof(int);
        return 0;
    }
    case SO_RCVTIMEO: {
        if (len < (socklen_t)sizeof(struct timeval)) return -EINVAL;
        memcpy(optval, &sock->recv_timeout, sizeof(struct timeval));
        *optlen = (socklen_t)sizeof(struct timeval);
        return 0;
    }
    case SO_SNDTIMEO: {
        if (len < (socklen_t)sizeof(struct timeval)) return -EINVAL;
        memcpy(optval, &sock->send_timeout, sizeof(struct timeval));
        *optlen = (socklen_t)sizeof(struct timeval);
        return 0;
    }
    case SO_LINGER: {
        if (len < (socklen_t)sizeof(struct linger)) return -EINVAL;
        struct linger l = {0};
        l.l_onoff = sock->options.linger ? 1 : 0;
        l.l_linger = sock->linger_seconds;
        memcpy(optval, &l, sizeof(l));
        *optlen = (socklen_t)sizeof(l);
        return 0;
    }
    default:
        return -ENOPROTOOPT;
    }
}

int socket_auto_bind(Socket* sock, bind_table* bound_table,
                     const addr_key* local_key, const uint8_t* dest_ip,
                     uint16_t dest_port, uint32_t scope_id)
{
    if (!sock || !bound_table || sock->bind_reservation ||
        (local_key && (local_key->port || local_key->family != sock->family)))
        return -EINVAL;

    addr_key key = {0};
    if (local_key) {
        key = *local_key;
    } else {
        if (!dest_ip || set_socket_route(sock, dest_ip, scope_id) < 0) {
            DEBUG_LOG("Failed to set Socket route for auto bind");
            return -EHOSTUNREACH;
        }
        key.family = sock->family;
        key.scope_id = scope_id;
        if (!if_search_best_saddr_by_daddr(sock->route->if_info, sock->family,
                                           dest_ip, key.addr6)) {
            DEBUG_LOG("Failed to find suitable source IP for destination");
            return -EADDRNOTAVAIL;
        }
    }

    bool reuse = !local_key &&
        (sock->options.reuseaddr || sock->options.reuseport);
    uint32_t first = get_current_time_ms() % EPHEMERAL_PORT_COUNT;
    for (uint32_t i = 0; i < EPHEMERAL_PORT_COUNT; i++) {
        uint32_t host_port = EPHEMERAL_PORT_FIRST +
            (first + i) % EPHEMERAL_PORT_COUNT;
        key.port = htons((uint16_t)host_port);

        if (dest_ip) {
            /* When the peer is known, keep the final tuple on this worker. */
            worker* tuple_worker = select_worker_by_tuple(sock->family,
                key.addr6, dest_ip, key.port, dest_port);
            if (tuple_worker != get_current_worker())
                continue;
        }

        bind_slot* reservation = bind_reserve(bound_table, &key, reuse);
        if (!reservation)
            continue;

        socket_set_bind_reservation(sock, &key, reservation);
        if (!local_key && sock->family == AF_INET6)
            sock->sip6_scope_id = scope_id ? scope_id : sock->route->ifindex;
        return 0;
    }
    return -EADDRINUSE;
}
void destroy_socket(Socket* sock){
    destroy_task(sock->pending_task);
    sock->pending_task = NULL;

    if (sock->flag.is_hash) {
        hash* tuple_hash = select_tuple_hash_by_protocol(
            sock->protocol, sock->family);
            uninstall_tuple(sock, tuple_hash);
    }
    if (sock->flag.is_bound) {
        bind_table* bound_table = select_bound_table_by_protocol(
            sock->protocol, sock->family);
            unbind_saddr(sock, bound_table);
    }

    skbuff* skb;
    while((skb=SKB_FROM_QUEUE_NODE(pop_queue(&sock->recv_queue)))!=NULL){
        PUT_REF(skb);
    }
    while((skb=SKB_FROM_QUEUE_NODE(pop_queue(&sock->send_queue)))!=NULL){
        PUT_REF(skb);
    }
    PUT_REF(sock->route);
    free(sock);
}

Socket* socket_select(Socket* first_sock, uint32_t hash){

    int sock_num = 1;
    list_node *n;
    for (n = first_sock->tuple_node.next; n; n = n->next) {
        sock_num++;
    }

    if (sock_num <= 1) {
        return first_sock;
    }

    int idx = (int)(hash % (uint32_t)sock_num);

    Socket *aim = first_sock;
    n = &first_sock->tuple_node;
    while (idx-- > 0 && n->next) {
        n = n->next;
        aim = (Socket *)((uint8_t *)n - offsetof(Socket, tuple_node));
    }

    return aim;
}
void set_skb_by_socket(skbuff* skb, Socket* sock){
    skb->sock = sock;
    skb->family = sock->family;
    skb->protocol = sock->protocol;
    PUT_REF(skb->route);
    GET_REF(skb->route, sock->route);
}
void socket_detach_with_fd_entry(Socket* sock){
    fd_entry* entry = sock->fd_entry;
    if(!entry){
        return;
    }
    entry->value = NULL;
    sock->fd_entry = NULL;

    pending_node* pn;
    list_node* t;
    FOR_EACH_LIST_SAFE_OFFSET(&sock->pending, pn, t, pending_node, node) {
        remove_list_node(&pn->node);
#ifdef TEST_EPOLL
        if (pn->cb == epoll_pending_cb) {
            net_epoll_item* it = (net_epoll_item*)pn->value;
            net_epoll* ep = it->ep;
            hash_del_node(ep->registered_sockfds, &it->hash_node);
            epoll_item_unregister(it);
        } else
#endif
        if (pn->cb == req_pending_cb) {
            /* Req waiter: notify failure */
            req* r = (req*)pn->value;
            req_fail(r, EBADF);
        }
    }
}

