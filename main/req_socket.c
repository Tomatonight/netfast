#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "req.h"
#include "fd_entry.h"
#include "req_socket.h"
#include "worker.h"

/* Copy an address supplied by the caller into a request-owned
 * sockaddr_storage.  Requests are processed asynchronously by the worker,
 * so retaining the caller's pointer (or silently dropping an oversized
 * address) is unsafe.  In particular, an IPv6 sockaddr_in6 is larger than
 * sockaddr_in and must be copied in full. */
static int req_copy_sockaddr(struct sockaddr_storage *dst,
                             const struct sockaddr *src,
                             socklen_t addrlen)
{
    /* The request entry points validate src and always provide dst. */
    if (addrlen < (socklen_t)sizeof(sa_family_t) ||
        addrlen > (socklen_t)sizeof(*dst)) {
        errno = EINVAL;
        return -1;
    }

    memset(dst, 0, sizeof(*dst));
    memcpy(dst, src, addrlen);
    return 0;
}

static int req_socket_bind(fd_entry* entry, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!addr) {
        errno = EFAULT;
        return -1;
    }
    if (addrlen == 0 || addrlen > sizeof(((req *)0)->argv.bind.addr)) {
        errno = EINVAL;
        return -1;
    }
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_BIND, bind, .addrlen = addrlen);
    if (req_copy_sockaddr(&r.argv.bind.addr, addr, addrlen) < 0)
        return -1;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_connect(fd_entry* entry, const struct sockaddr *addr,
                       socklen_t addrlen)
{
    if (!addr) {
        errno = EFAULT;
        return -1;
    }
    if (addrlen == 0 || addrlen > sizeof(((req *)0)->argv.connect.addr)) {
        errno = EINVAL;
        return -1;
    }
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_CONNECT, connect, .addrlen = addrlen);
    if (req_copy_sockaddr(&r.argv.connect.addr, addr, addrlen) < 0)
        return -1;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_listen(fd_entry* entry, int backlog)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_LISTEN, listen, .backlog = backlog);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_accept(fd_entry* entry, struct sockaddr *addr,
                             socklen_t *addrlen)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_ACCEPT, accept,
             .addr = addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_write(fd_entry* entry, const void *buf, uint32_t len)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_WRITE, write, .buf = buf, .len = len);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_read(fd_entry* entry, void *buf, uint32_t len)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_READ, read, .buf = buf, .len = len);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_sendto(fd_entry* entry, const void *buf, uint32_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
    /* A connected socket may pass a NULL destination (the kernel API permits
     * this); when a destination is supplied it must fit in the request copy. */
    if (dest_addr && (addrlen == 0 || addrlen > sizeof(((req *)0)->argv.sendto.dest_addr))) {
        errno = EINVAL;
        return -1;
    }
    if (!dest_addr && addrlen != 0) {
        errno = EINVAL;
        return -1;
    }
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_SENDTO, sendto,
        .buf = buf, .len = len, .flags = flags,
        .addrlen = addrlen, .has_dest_addr = dest_addr != NULL);
    if (dest_addr && req_copy_sockaddr(&r.argv.sendto.dest_addr,
                                       dest_addr, addrlen) < 0)
        return -1;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_recvfrom(fd_entry* entry, void *buf, uint32_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_RECVFROM, recvfrom,
        .buf = buf, .len = len, .flags = flags,
        .src_addr = src_addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_getsockname(fd_entry* entry, struct sockaddr *addr,
                           socklen_t *addrlen)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_GETSOCKNAME, getsockname, .addr = addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_getpeername(fd_entry* entry, struct sockaddr *addr,
                           socklen_t *addrlen)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_GETPEERNAME, getpeername, .addr = addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_setsockopt(fd_entry* entry, int level, int optname,
                          const void *optval, socklen_t optlen)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_SETSOCKOPT, setsockopt,
        .level = level, .optname = optname,
        .optval = optval, .optlen = optlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_getsockopt(fd_entry* entry, int level, int optname,
                          void *optval, socklen_t *optlen)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_GETSOCKOPT, getsockopt,
        .level = level, .optname = optname,
        .optval = optval, .optlen = optlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_fcntl(fd_entry* entry, int cmd, int arg)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_FCNTL, fcntl,
             .cmd = cmd, .arg = arg);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_close(fd_entry* entry)
{
    req r;
    req_init(&r);
    r.entry = entry;
    r.type = REQ_CLOSE;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int req_socket_shutdown(fd_entry* entry, int how)
{
    req r;
    req_init(&r);
    r.entry = entry;

    req_fill(&r, REQ_SHUTDOWN, shutdown, .how = how);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

int socket_req(int family, int type, int protocol)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_SOCKET, Socket,
             .family = family, .type = type, .protocol = protocol);

    return req_push_wait(worker_select_random(), &r);
}

const fd_entry_ops socket_fd_ops = {
    .bind        = req_socket_bind,
    .connect     = req_socket_connect,
    .listen      = req_socket_listen,
    .accept      = req_socket_accept,
    .write       = req_socket_write,
    .read        = req_socket_read,
    .sendto      = req_socket_sendto,
    .recvfrom    = req_socket_recvfrom,
    .getsockname = req_socket_getsockname,
    .getpeername = req_socket_getpeername,
    .setsockopt  = req_socket_setsockopt,
    .getsockopt  = req_socket_getsockopt,
    .fcntl       = req_socket_fcntl,
    .close       = req_socket_close,
    .shutdown    = req_socket_shutdown,
};
