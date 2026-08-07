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
    if (!dst || !src) {
        errno = EFAULT;
        return -1;
    }
    if (addrlen < (socklen_t)sizeof(sa_family_t) ||
        addrlen > (socklen_t)sizeof(*dst)) {
        errno = EINVAL;
        return -1;
    }

    memset(dst, 0, sizeof(*dst));
    memcpy(dst, src, addrlen);
    return 0;
}

static int fcntl_req(fd_entry* entry, int cmd, int arg)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_FCNTL, fcntl, .entry = entry, .cmd = cmd, .arg = arg);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

int socket_req(int family, int type, int protocol)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_SOCKET, Socket, .family = family, .type = type, .protocol = protocol);

    return req_push_wait(random_worker(), &r);
}

static int bind_req(fd_entry* entry, const struct sockaddr *addr, socklen_t addrlen)
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

    req_fill(&r, REQ_BIND, bind, .entry = entry, .addrlen = addrlen);
    if (req_copy_sockaddr(&r.argv.bind.addr, addr, addrlen) < 0)
        return -1;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int connect_req(fd_entry* entry, const struct sockaddr *addr,
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

    req_fill(&r, REQ_CONNECT, connect, .entry = entry, .addrlen = addrlen);
    if (req_copy_sockaddr(&r.argv.connect.addr, addr, addrlen) < 0)
        return -1;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int listen_req(fd_entry* entry, int backlog)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_LISTEN, listen, .entry = entry, .backlog = backlog);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int write_req(fd_entry* entry, const void *buf, uint32_t len)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_WRITE, write, .entry = entry, .buf = buf, .len = len);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int read_req(fd_entry* entry, void *buf, uint32_t len)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_READ, read, .entry = entry, .buf = buf, .len = len);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int sendto_req(fd_entry* entry, const void *buf, uint32_t len, int flags,
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

    req_fill(&r, REQ_SENDTO, sendto,
        .entry = entry, .buf = buf, .len = len, .flags = flags,
        .addrlen = addrlen, .has_dest_addr = dest_addr != NULL);
    if (dest_addr && req_copy_sockaddr(&r.argv.sendto.dest_addr,
                                       dest_addr, addrlen) < 0)
        return -1;

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int recvfrom_req(fd_entry* entry, void *buf, uint32_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_RECVFROM, recvfrom,
        .entry = entry, .buf = buf, .len = len, .flags = flags,
        .src_addr = src_addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int accept_req(fd_entry* entry, struct sockaddr *addr,
                      socklen_t *addrlen)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_ACCEPT, accept, .entry = entry, .addr = addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int getsockname_req(fd_entry* entry, struct sockaddr *addr,
                           socklen_t *addrlen)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_GETSOCKNAME, getsockname, .entry = entry, .addr = addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int getpeername_req(fd_entry* entry, struct sockaddr *addr,
                           socklen_t *addrlen)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_GETPEERNAME, getpeername, .entry = entry, .addr = addr, .addrlen = addrlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int setsockopt_req(fd_entry* entry, int level, int optname,
                          const void *optval, socklen_t optlen)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_SETSOCKOPT, setsockopt,
        .entry = entry, .level = level, .optname = optname,
        .optval = optval, .optlen = optlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int getsockopt_req(fd_entry* entry, int level, int optname,
                          void *optval, socklen_t *optlen)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_GETSOCKOPT, getsockopt,
        .entry = entry, .level = level, .optname = optname,
        .optval = optval, .optlen = optlen);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int close_req(fd_entry* entry)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_CLOSE, close, .entry = entry);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

static int shutdown_req(fd_entry* entry, int how)
{
    req r;
    req_init(&r);

    req_fill(&r, REQ_SHUTDOWN, shutdown, .entry = entry, .how = how);

    return req_push_wait(fd_entry_get_worker(entry), &r);
}

const fd_entry_ops socket_fd_ops = {
    .bind        = bind_req,
    .connect     = connect_req,
    .listen      = listen_req,
    .accept      = accept_req,
    .write       = write_req,
    .read        = read_req,
    .sendto      = sendto_req,
    .recvfrom    = recvfrom_req,
    .getsockname = getsockname_req,
    .getpeername = getpeername_req,
    .setsockopt  = setsockopt_req,
    .getsockopt  = getsockopt_req,
    .fcntl       = fcntl_req,
    .close       = close_req,
    .shutdown    = shutdown_req,
};
