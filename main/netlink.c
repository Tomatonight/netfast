#include "netlink.h"

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/netdev.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "route_arp_ndp.h"
#include "thread.h"
#include "worker.h"

#define NETLINK_BUFFER_SIZE 8192u
#define NETLINK_DUMP_TIMEOUT_MS 5000u
#define NETLINK_GENERIC_TIMEOUT_MS 1000u

static int netlink_attr_put(void* buffer, size_t capacity,
                            struct nlmsghdr* nlh, uint16_t type,
                            const void* data, size_t len)
{
    size_t offset = NLMSG_ALIGN(nlh->nlmsg_len);
    size_t attr_len = NLA_HDRLEN + len;
    size_t total = NLA_ALIGN(attr_len);

    if (offset + total > capacity)
        return -EMSGSIZE;

    struct nlattr* attr = (struct nlattr*)((uint8_t*)buffer + offset);
    attr->nla_type = type;
    attr->nla_len = (uint16_t)attr_len;
    memcpy((uint8_t*)attr + NLA_HDRLEN, data, len);
    if (total > attr_len)
        memset((uint8_t*)attr + attr_len, 0, total - attr_len);
    nlh->nlmsg_len = (uint32_t)(offset + total);
    return 0;
}

static int netlink_genl_request(int fd, uint16_t family, uint8_t command,
                                uint8_t version, uint32_t seq,
                                uint16_t request_type, const void* request_data,
                                size_t request_len, uint16_t response_type,
                                void* response_data, size_t response_len)
{
    uint8_t request[256] = {0};
    struct nlmsghdr* nlh = (struct nlmsghdr*)request;
    struct genlmsghdr* genl = (struct genlmsghdr*)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = family;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = seq;
    genl->cmd = command;
    genl->version = version;

    int ret = netlink_attr_put(request, sizeof(request), nlh, request_type,
                               request_data, request_len);
    if (ret < 0)
        return ret;

    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t sent = sendto(fd, request, nlh->nlmsg_len, 0,
                          (struct sockaddr*)&kernel, sizeof(kernel));
    if (sent != (ssize_t)nlh->nlmsg_len)
        return sent < 0 ? -errno : -EIO;

    uint64_t deadline = read_now_ms() + NETLINK_GENERIC_TIMEOUT_MS;
    for (;;) {
        uint64_t now = read_now_ms();
        if (now >= deadline)
            return -ETIMEDOUT;

        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        ret = poll(&pfd, 1, (int)(deadline - now));
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (ret == 0)
            return -ETIMEDOUT;

        uint8_t reply[NETLINK_BUFFER_SIZE];
        ssize_t received = recv(fd, reply, sizeof(reply), 0);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -errno;
        }

        int remaining = (int)received;
        for (struct nlmsghdr* msg = (struct nlmsghdr*)reply;
             NLMSG_OK(msg, remaining); msg = NLMSG_NEXT(msg, remaining)) {
            if (msg->nlmsg_seq != seq)
                continue;
            if (msg->nlmsg_type == NLMSG_ERROR) {
                if (msg->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
                    return -EPROTO;
                const struct nlmsgerr* error =
                    (const struct nlmsgerr*)NLMSG_DATA(msg);
                return error->error ? error->error : -ENOENT;
            }
            if (msg->nlmsg_type != family ||
                msg->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
                continue;

            size_t attr_len = msg->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
            const uint8_t* pos = (const uint8_t*)NLMSG_DATA(msg) + GENL_HDRLEN;
            while (attr_len >= sizeof(struct nlattr)) {
                const struct nlattr* attr = (const struct nlattr*)pos;
                if (attr->nla_len < NLA_HDRLEN || attr->nla_len > attr_len)
                    return -EPROTO;

                size_t payload_len = attr->nla_len - NLA_HDRLEN;
                if ((attr->nla_type & NLA_TYPE_MASK) == response_type) {
                    if (payload_len < response_len)
                        return -EPROTO;
                    memcpy(response_data, pos + NLA_HDRLEN, response_len);
                    return 0;
                }

                size_t next = NLA_ALIGN(attr->nla_len);
                if (next > attr_len)
                    return -EPROTO;
                pos += next;
                attr_len -= next;
            }
            return -ENOENT;
        }
    }
}

int netlink_get_xsk_features(uint32_t ifindex, uint64_t* features)
{
    if (!ifindex || !features)
        return -EINVAL;
    *features = 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0)
        return -errno;

    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    int ret = bind(fd, (struct sockaddr*)&local, sizeof(local));
    if (ret < 0) {
        ret = -errno;
        close(fd);
        return ret;
    }

    uint16_t family_id = 0;
    static const char family_name[] = NETDEV_FAMILY_NAME;
    ret = netlink_genl_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1, 1,
                               CTRL_ATTR_FAMILY_NAME, family_name,
                               sizeof(family_name), CTRL_ATTR_FAMILY_ID,
                               &family_id, sizeof(family_id));
    if (ret == 0)
        ret = netlink_genl_request(fd, family_id, NETDEV_CMD_DEV_GET,
                                   NETDEV_FAMILY_VERSION, 2,
                                   NETDEV_A_DEV_IFINDEX, &ifindex,
                                   sizeof(ifindex), NETDEV_A_DEV_XSK_FEATURES,
                                   features, sizeof(*features));
    close(fd);
    return ret;
}

static void netlink_process_msg(struct nlmsghdr* nlh)
{
    switch (nlh->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            parse_link_event(nlh);
            break;
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            parse_route_event(nlh);
            break;
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
            parse_neighbor_event(nlh);
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            parse_addr_event(nlh);
            break;
        default:
            break;
    }
}

static int netlink_send_dump(int fd, int type, uint32_t seq)
{
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg gen;
    } req = {0};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.nlh.nlmsg_type = (uint16_t)type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = seq;
    req.nlh.nlmsg_pid = (uint32_t)getpid();
    req.gen.rtgen_family = AF_UNSPEC;

    ssize_t sent = send(fd, &req, req.nlh.nlmsg_len, 0);
    if (sent == (ssize_t)req.nlh.nlmsg_len)
        return 0;
    if (sent >= 0)
        errno = EIO;
    return -1;
}

static int netlink_dump_error(const struct nlmsghdr* nlh)
{
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
        errno = EPROTO;
        ERR_LOG("netlink: short NLMSG_ERROR len=%u", nlh->nlmsg_len);
        return -1;
    }

    const struct nlmsgerr* error = (const struct nlmsgerr*)NLMSG_DATA(nlh);
    if (error->error == 0)
        return 0;
    errno = -error->error;
    ERR_LOG("netlink: dump error=%d (%s) for type=%u seq=%u",
            error->error, strerror(errno), error->msg.nlmsg_type,
            error->msg.nlmsg_seq);
    return -1;
}

static int netlink_dump_sync(int fd)
{
    uint32_t seq_base = (uint32_t)getpid();
    static const int types[] = {
        RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, RTM_GETNEIGH
    };

    for (uint32_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        uint32_t seq = seq_base + t + 1;
        if (netlink_send_dump(fd, types[t], seq) < 0)
            return -1;

        uint64_t deadline = read_now_ms() + NETLINK_DUMP_TIMEOUT_MS;

        bool done = false;
        while (!done) {
            uint64_t now = read_now_ms();
            if (now >= deadline) {
                errno = ETIMEDOUT;
                ERR_LOG("netlink: dump timeout after %u ms",
                        NETLINK_DUMP_TIMEOUT_MS);
                return -1;
            }

            struct pollfd pfd = {.fd = fd, .events = POLLIN};
            int poll_ret = poll(&pfd, 1, (int)(deadline - now));
            if (poll_ret < 0) {
                if (errno == EINTR)
                    continue;
                ERR_LOG("netlink: dump poll failed: %s", strerror(errno));
                return -1;
            }
            if (poll_ret == 0) {
                errno = ETIMEDOUT;
                ERR_LOG("netlink: dump poll timeout after %u ms",
                        NETLINK_DUMP_TIMEOUT_MS);
                return -1;
            }

            char buf[NETLINK_BUFFER_SIZE];
            ssize_t received = recv(fd, buf, sizeof(buf), 0);
            if (received < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                ERR_LOG("netlink: dump recv failed: %s", strerror(errno));
                return -1;
            }
            if (received == 0) {
                ERR_LOG("netlink: dump recv 0");
                return -1;
            }

            int remaining = (int)received;
            struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
            for (; NLMSG_OK(nlh, remaining);
                 nlh = NLMSG_NEXT(nlh, remaining)) {
                if (nlh->nlmsg_seq == seq) {
                    if (nlh->nlmsg_type == NLMSG_DONE) {
                        done = true;
                        break;
                    }
                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        if (netlink_dump_error(nlh) < 0)
                            return -1;
                        done = true;
                        break;
                    }
                }
                netlink_process_msg(nlh);
            }
        }
    }

    return 0;
}


static void netlink_err_cb(struct task* tk)
{
    ERR_LOG("netlink: epoll error/hup on fd=%d", tk->fd);
    exit(-1);
}

static void netlink_close(worker* w)
{
    close(w->stack.netlink_fd);
    w->stack.netlink_fd = -1;
}

int netlink_init(worker* w)
{
	struct sockaddr_nl sa = {0};

	w->stack.netlink_fd = socket(AF_NETLINK,
                                 SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                                 NETLINK_ROUTE);
	if (w->stack.netlink_fd < 0) {
        ERR_LOG("netlink: Socket failed: %s", strerror(errno));
		return -1;
	}

	sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE |
                   RTMGRP_NEIGH | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(w->stack.netlink_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        ERR_LOG("netlink: bind failed: %s", strerror(errno));
		netlink_close(w);
		return -1;
	}

    if (netlink_dump_sync(w->stack.netlink_fd) < 0) {
        ERR_LOG("netlink: initial dump failed");
        netlink_close(w);
        return -1;
    }

    task* tk = create_task(TASK_TYPE_FD_READ);
    if (!tk) {
        ERR_LOG("netlink_init: create_task failed");
        netlink_close(w);
        return -1;
    }
    tk->fd = w->stack.netlink_fd;
    tk->cb_read = netlink_recv_cb;
    tk->cb_err = netlink_err_cb;

    if (register_task(w->master, tk) < 0) {
        ERR_LOG("netlink_init: register_task failed");
        destroy_task(tk);
        netlink_close(w);
        return -1;
    }

	return 0;
}

void netlink_recv_cb(struct task* tk) {
    int fd = tk->fd;
    char buf[NETLINK_BUFFER_SIZE];
    for (;;) {
        ssize_t received = recv(fd, buf, sizeof(buf), 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            ERR_LOG("netlink: recv failed: %s", strerror(errno));
            return;
        }
        if (received == 0) {
            ERR_LOG("netlink: recv 0, treat as error fd=%d", fd);
            netlink_err_cb(tk);
            return;
        }

        if ((size_t)received < sizeof(struct nlmsghdr)) {
            WARN_LOG("netlink: short message len=%zd", received);
            continue;
        }

        int remaining = (int)received;
        struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
        for (; NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE)
                continue;

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    ERR_LOG("netlink: NLMSG_ERROR but too short len=%u", nlh->nlmsg_len);
                    continue;
                }
                struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(nlh);
                if (e->error != 0) {
                    ERR_LOG("netlink: NLMSG_ERROR=%d (%s) for type=%u seq=%u", e->error, strerror(-e->error),
                            e->msg.nlmsg_type, e->msg.nlmsg_seq);
                }
                continue;
            }

            netlink_process_msg(nlh);
        }

        if (remaining > 0)
            WARN_LOG("netlink: trailing bytes=%d", remaining);
    }
}

