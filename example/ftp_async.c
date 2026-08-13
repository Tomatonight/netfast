/*
 * Minimal passive-mode FTP server built exclusively on NetFast's async
 * socket API.  It is intentionally small, but speaks enough RFC 959 for a
 * standard FTP client to upload and download files:
 *
 *   USER, PASS, SYST, FEAT, PWD, TYPE, PASV, EPSV, STOR, RETR, SIZE, NOOP,
 *   and QUIT.
 *
 * The process serves one control connection and exits after QUIT.  It is a
 * protocol/API example, not an Internet-facing FTP implementation: there is
 * no TLS and paths are restricted to a single safe basename.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "netfast.h"

#define FTP_CONTROL_CAP 4096U
#define FTP_DATA_CHUNK (32U * 1024U)
#define FTP_NAME_CAP 128U
#define FTP_PASSIVE_PORT 30000U

typedef struct ftp_server ftp_server;
typedef struct ftp_session ftp_session;
typedef struct ftp_op ftp_op;

typedef enum ftp_op_kind {
    FTP_OP_SERVER_SOCKET,
    FTP_OP_SERVER_REUSEADDR,
    FTP_OP_SERVER_BIND,
    FTP_OP_SERVER_LISTEN,
    FTP_OP_CONTROL_ACCEPT,
    FTP_OP_CONTROL_READ,
    FTP_OP_CONTROL_WRITE,
    FTP_OP_DATA_SOCKET,
    FTP_OP_DATA_REUSEADDR,
    FTP_OP_DATA_BIND,
    FTP_OP_DATA_LISTEN,
    FTP_OP_DATA_GETSOCKNAME,
    FTP_OP_DATA_ACCEPT,
    FTP_OP_STOR_READ,
    FTP_OP_RETR_WRITE,
    FTP_OP_CLOSE,
} ftp_op_kind;

typedef enum ftp_reply_after {
    FTP_REPLY_READ_NEXT,
    FTP_REPLY_START_TRANSFER,
    FTP_REPLY_STOP,
} ftp_reply_after;

typedef enum ftp_transfer_kind {
    FTP_TRANSFER_NONE,
    FTP_TRANSFER_STOR,
    FTP_TRANSFER_RETR,
} ftp_transfer_kind;

typedef enum ftp_close_after {
    FTP_CLOSE_NONE,
    FTP_CLOSE_STOR_OK,
    FTP_CLOSE_STOR_ERROR,
    FTP_CLOSE_RETR_OK,
} ftp_close_after;

struct ftp_server {
    int cq_fd;
    int listen_fd;
    int reuseaddr;
    uint16_t passive_port;
    bool stop;
    struct sockaddr_in listen_addr;
    char advertised_ip[INET_ADDRSTRLEN];
    char root[PATH_MAX];
    ftp_session *session;
};

struct ftp_session {
    ftp_server *server;
    int control_fd;
    int data_listen_fd;
    int data_fd;
    bool logged_in;
    bool control_read_pending;
    bool reply_pending;
    bool data_accept_pending;
    bool start_after_reply;
    bool pasv_extended;
    ftp_transfer_kind transfer;
    struct sockaddr_in pasv_addr;
    socklen_t pasv_addr_len;
    char control_buf[FTP_CONTROL_CAP];
    size_t control_len;
    char filename[FTP_NAME_CAP];
    FILE *file;
    uint64_t file_len;
    uint64_t file_offset;
};

struct ftp_op {
    ftp_op *next;
    net_async_req *request;
    ftp_op_kind kind;
    ftp_session *session;
    int fd;
    char *buffer;
    size_t length;
    size_t offset;
    bool owns_buffer;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ftp_reply_after reply_after;
    ftp_close_after close_after;
};

static ftp_server g_server = {
    .cq_fd = -1,
    .listen_fd = -1,
};
static ftp_op *g_ops;

static void log_line(const char *level, const char *message)
{
    fprintf(stderr, "[ftp-async] %s: %s\n", level, message);
    fflush(stderr);
}

static void log_errno(const char *where, int error)
{
    char line[256];
    snprintf(line, sizeof(line), "%s: %s", where, strerror(error));
    log_line("ERROR", line);
}

static const char *op_name(ftp_op_kind kind)
{
    switch (kind) {
    case FTP_OP_DATA_SOCKET:
        return "socket";
    case FTP_OP_DATA_REUSEADDR:
        return "setsockopt(SO_REUSEADDR)";
    case FTP_OP_DATA_BIND:
        return "bind";
    case FTP_OP_DATA_LISTEN:
        return "listen";
    default:
        return "operation";
    }
}

static ftp_op *op_create(ftp_op_kind kind, ftp_session *session)
{
    ftp_op *op = calloc(1, sizeof(*op));
    if (op)
        op->kind = kind;
    if (op)
        op->session = session;
    return op;
}

static void op_free(ftp_op *op)
{
    if (!op)
        return;
    if (op->owns_buffer)
        free(op->buffer);
    free(op);
}

static void op_link(ftp_op *op)
{
    op->next = g_ops;
    g_ops = op;
}

static void op_unlink(ftp_op *op)
{
    ftp_op **link = &g_ops;
    while (*link && *link != op)
        link = &(*link)->next;
    if (*link)
        *link = op->next;
    op->next = NULL;
}

static ftp_op *op_find(net_async_req *request)
{
    for (ftp_op *op = g_ops; op; op = op->next) {
        if (op->request == request)
            return op;
    }
    return NULL;
}

static int submit_operation(ftp_op *op)
{
    ftp_session *session = op->session;
    ftp_server *server = session ? session->server : &g_server;

    switch (op->kind) {
    case FTP_OP_SERVER_SOCKET:
    case FTP_OP_DATA_SOCKET:
        op->request = net_async_req_create(-1, NET_ASYNC_SOCKET, AF_INET,
                                            SOCK_STREAM, IPPROTO_TCP);
        break;
    case FTP_OP_SERVER_REUSEADDR:
    case FTP_OP_DATA_REUSEADDR:
        op->request = net_async_req_create(op->fd, NET_ASYNC_SETSOCKOPT,
                                            SOL_SOCKET, SO_REUSEADDR,
                                            &server->reuseaddr,
                                            (socklen_t)sizeof(server->reuseaddr));
        break;
    case FTP_OP_SERVER_BIND:
        op->request = net_async_req_create(op->fd, NET_ASYNC_BIND,
                                            (const struct sockaddr *)&server->listen_addr,
                                            (socklen_t)sizeof(server->listen_addr));
        break;
    case FTP_OP_SERVER_LISTEN:
    case FTP_OP_DATA_LISTEN:
        op->request = net_async_req_create(op->fd, NET_ASYNC_LISTEN, 8);
        break;
    case FTP_OP_CONTROL_ACCEPT:
    case FTP_OP_DATA_ACCEPT:
        op->peer_addr_len = sizeof(op->peer_addr);
        op->request = net_async_req_create(op->fd, NET_ASYNC_ACCEPT,
                                            (struct sockaddr *)&op->peer_addr,
                                            &op->peer_addr_len);
        break;
    case FTP_OP_CONTROL_READ:
        op->request = net_async_req_create(session->control_fd, NET_ASYNC_READ,
                                            op->buffer, (uint32_t)op->length);
        break;
    case FTP_OP_CONTROL_WRITE:
    case FTP_OP_RETR_WRITE:
        op->request = net_async_req_create(op->fd, NET_ASYNC_WRITE,
                                            op->buffer + op->offset,
                                            (uint32_t)(op->length - op->offset));
        break;
    case FTP_OP_STOR_READ:
        op->request = net_async_req_create(op->fd, NET_ASYNC_READ,
                                            op->buffer, (uint32_t)op->length);
        break;
    case FTP_OP_DATA_BIND:
        op->request = net_async_req_create(op->fd, NET_ASYNC_BIND,
                                            (const struct sockaddr *)&session->pasv_addr,
                                            (socklen_t)sizeof(session->pasv_addr));
        break;
    case FTP_OP_DATA_GETSOCKNAME:
        session->pasv_addr_len = sizeof(session->pasv_addr);
        op->request = net_async_req_create(op->fd, NET_ASYNC_GETSOCKNAME,
                                            (struct sockaddr *)&session->pasv_addr,
                                            &session->pasv_addr_len);
        break;
    case FTP_OP_CLOSE:
        op->request = net_async_req_create(op->fd, NET_ASYNC_CLOSE);
        break;
    }

    if (!op->request) {
        log_errno("create async request", errno);
        return -1;
    }

    op_link(op);
    if (net_async_submit(server->cq_fd, op->request) == 0)
        return 0;

    log_errno("submit async request", errno);
    op_unlink(op);
    net_async_req_destroy(op->request);
    op->request = NULL;
    return -1;
}

static int submit_simple(ftp_op_kind kind, ftp_session *session, int fd)
{
    ftp_op *op = op_create(kind, session);
    if (!op)
        return -1;
    op->fd = fd;
    if (submit_operation(op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_close(ftp_session *session, int fd, ftp_close_after after)
{
    ftp_op *op = op_create(FTP_OP_CLOSE, session);
    if (!op)
        return -1;
    op->fd = fd;
    op->close_after = after;
    if (submit_operation(op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_control_read(ftp_session *session);
static void process_next_command(ftp_session *session);
static void maybe_start_transfer(ftp_session *session);

static int submit_reply(ftp_session *session, const char *message,
                        ftp_reply_after after)
{
    if (session->reply_pending) {
        log_line("ERROR", "attempted overlapping control replies");
        return -1;
    }

    size_t length = strlen(message);
    ftp_op *op = op_create(FTP_OP_CONTROL_WRITE, session);
    if (!op)
        return -1;
    op->buffer = malloc(length + 1);
    if (!op->buffer) {
        op_free(op);
        return -1;
    }
    memcpy(op->buffer, message, length + 1);
    op->owns_buffer = true;
    op->length = length;
    op->fd = session->control_fd;
    op->reply_after = after;
    session->reply_pending = true;
    if (submit_operation(op) == 0)
        return 0;
    session->reply_pending = false;
    op_free(op);
    return -1;
}

static int submit_control_read(ftp_session *session)
{
    if (session->control_read_pending || session->reply_pending ||
        session->server->stop)
        return 0;
    if (session->control_len == sizeof(session->control_buf)) {
        (void)submit_reply(session, "500 Command too long\r\n", FTP_REPLY_READ_NEXT);
        session->control_len = 0;
        return -1;
    }

    ftp_op *op = op_create(FTP_OP_CONTROL_READ, session);
    if (!op)
        return -1;
    op->fd = session->control_fd;
    op->buffer = session->control_buf + session->control_len;
    op->length = sizeof(session->control_buf) - session->control_len;
    session->control_read_pending = true;
    if (submit_operation(op) == 0)
        return 0;
    session->control_read_pending = false;
    op_free(op);
    return -1;
}

static bool safe_filename(const char *name)
{
    size_t length = strlen(name);
    if (length == 0 || length >= FTP_NAME_CAP)
        return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static int make_path(const ftp_session *session, const char *filename,
                     char path[PATH_MAX])
{
    int written = snprintf(path, PATH_MAX, "%s/%s", session->server->root,
                           filename);
    return written >= 0 && written < PATH_MAX ? 0 : -1;
}

static void close_transfer_file(ftp_session *session)
{
    if (session->file)
        fclose(session->file);
    session->file = NULL;
}

static int open_upload(ftp_session *session, const char *filename)
{
    char path[PATH_MAX];
    if (make_path(session, filename, path) < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    close_transfer_file(session);
    session->file = fopen(path, "wb");
    if (!session->file)
        return -1;
    session->file_len = 0;
    session->file_offset = 0;
    return 0;
}

static int open_download(ftp_session *session, const char *filename)
{
    char path[PATH_MAX];
    if (make_path(session, filename, path) < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    close_transfer_file(session);
    session->file = fopen(path, "rb");
    if (!session->file)
        return -1;
    struct stat status;
    if (fstat(fileno(session->file), &status) != 0 || status.st_size < 0) {
        int saved_errno = errno ? errno : EIO;
        close_transfer_file(session);
        errno = saved_errno;
        return -1;
    }
    session->file_len = (uint64_t)status.st_size;
    session->file_offset = 0;
    return 0;
}

static int submit_data_accept(ftp_session *session)
{
    if (session->data_accept_pending || session->data_listen_fd < 0)
        return -1;
    session->data_accept_pending = true;
    if (submit_simple(FTP_OP_DATA_ACCEPT, session, session->data_listen_fd) == 0)
        return 0;
    session->data_accept_pending = false;
    return -1;
}

static int submit_stor_read(ftp_session *session)
{
    ftp_op *op = op_create(FTP_OP_STOR_READ, session);
    if (!op)
        return -1;
    op->fd = session->data_fd;
    op->buffer = malloc(FTP_DATA_CHUNK);
    if (!op->buffer) {
        op_free(op);
        return -1;
    }
    op->owns_buffer = true;
    op->length = FTP_DATA_CHUNK;
    if (submit_operation(op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static int submit_retr_write(ftp_session *session)
{
    if (session->file_offset == session->file_len) {
        int fd = session->data_fd;
        session->data_fd = -1;
        close_transfer_file(session);
        return submit_close(session, fd, FTP_CLOSE_RETR_OK);
    }

    size_t length = (size_t)(session->file_len - session->file_offset);
    if (length > FTP_DATA_CHUNK)
        length = FTP_DATA_CHUNK;
    ftp_op *op = op_create(FTP_OP_RETR_WRITE, session);
    if (!op)
        return -1;
    op->fd = session->data_fd;
    op->buffer = malloc(length);
    if (!op->buffer) {
        op_free(op);
        return -1;
    }
    if (fread(op->buffer, 1, length, session->file) != length) {
        int saved_errno = ferror(session->file) ? EIO : errno;
        op_free(op);
        errno = saved_errno ? saved_errno : EIO;
        return -1;
    }
    op->owns_buffer = true;
    op->length = length;
    if (submit_operation(op) == 0)
        return 0;
    op_free(op);
    return -1;
}

static void maybe_start_transfer(ftp_session *session)
{
    if (!session->start_after_reply || session->data_fd < 0 ||
        session->transfer == FTP_TRANSFER_NONE)
        return;

    session->start_after_reply = false;
    int ret = session->transfer == FTP_TRANSFER_STOR
        ? submit_stor_read(session) : submit_retr_write(session);
    if (ret != 0) {
        log_errno("start FTP data transfer", errno);
        session->server->stop = true;
    }
}

static int start_pasv(ftp_session *session, bool extended)
{
    if (session->data_listen_fd >= 0 || session->data_fd >= 0 ||
        session->data_accept_pending || session->transfer != FTP_TRANSFER_NONE) {
        return submit_reply(session, "425 Data connection already active\r\n",
                            FTP_REPLY_READ_NEXT);
    }
    session->pasv_extended = extended;
    session->pasv_addr = session->server->listen_addr;
    session->pasv_addr.sin_port = htons(session->server->passive_port);
    if (submit_simple(FTP_OP_DATA_SOCKET, session, -1) == 0)
        return 0;
    return -1;
}

static int begin_transfer(ftp_session *session, ftp_transfer_kind transfer,
                          const char *argument)
{
    if (!session->logged_in)
        return submit_reply(session, "530 Please login with USER and PASS\r\n",
                            FTP_REPLY_READ_NEXT);
    if (!safe_filename(argument))
        return submit_reply(session, "550 Invalid filename\r\n", FTP_REPLY_READ_NEXT);
    if (!session->data_accept_pending && session->data_fd < 0)
        return submit_reply(session, "425 Use PASV or EPSV first\r\n",
                            FTP_REPLY_READ_NEXT);

    if (transfer == FTP_TRANSFER_RETR && open_download(session, argument) < 0) {
        return submit_reply(session, "550 File unavailable\r\n", FTP_REPLY_READ_NEXT);
    }
    if (transfer == FTP_TRANSFER_STOR && open_upload(session, argument) < 0) {
        return submit_reply(session, "550 Cannot create file\r\n",
                            FTP_REPLY_READ_NEXT);
    }
    snprintf(session->filename, sizeof(session->filename), "%s", argument);
    session->transfer = transfer;
    return submit_reply(session, "150 Opening passive data connection\r\n",
                        FTP_REPLY_START_TRANSFER);
}

static void handle_command(ftp_session *session, char *line)
{
    char *argument = line;
    while (*argument && !isspace((unsigned char)*argument))
        argument++;
    if (*argument)
        *argument++ = '\0';
    while (*argument == ' ' || *argument == '\t')
        argument++;

    if (strcasecmp(line, "USER") == 0) {
        session->logged_in = false;
        (void)submit_reply(session, "331 User name okay, need password\r\n",
                           FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "PASS") == 0) {
        session->logged_in = true;
        (void)submit_reply(session, "230 Login successful\r\n", FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "SYST") == 0) {
        (void)submit_reply(session, "215 UNIX Type: L8\r\n", FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "FEAT") == 0) {
        (void)submit_reply(session, "211-Features\r\n EPSV\r\n PASV\r\n SIZE\r\n211 End\r\n",
                           FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "PWD") == 0 || strcasecmp(line, "XPWD") == 0) {
        (void)submit_reply(session, "257 \"/\" is current directory\r\n",
                           FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "TYPE") == 0) {
        (void)submit_reply(session, "200 Type set\r\n", FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "NOOP") == 0) {
        (void)submit_reply(session, "200 NOOP okay\r\n", FTP_REPLY_READ_NEXT);
    } else if (strcasecmp(line, "PASV") == 0) {
        if (start_pasv(session, false) != 0)
            session->server->stop = true;
    } else if (strcasecmp(line, "EPSV") == 0) {
        if (start_pasv(session, true) != 0)
            session->server->stop = true;
    } else if (strcasecmp(line, "STOR") == 0) {
        if (begin_transfer(session, FTP_TRANSFER_STOR, argument) != 0)
            session->server->stop = true;
    } else if (strcasecmp(line, "RETR") == 0) {
        if (begin_transfer(session, FTP_TRANSFER_RETR, argument) != 0)
            session->server->stop = true;
    } else if (strcasecmp(line, "SIZE") == 0) {
        char path[PATH_MAX];
        struct stat status;
        char reply[128];
        if (!safe_filename(argument) || make_path(session, argument, path) < 0 ||
            stat(path, &status) != 0 || status.st_size < 0) {
            (void)submit_reply(session, "550 File unavailable\r\n", FTP_REPLY_READ_NEXT);
        } else {
            snprintf(reply, sizeof(reply), "213 %lld\r\n",
                     (long long)status.st_size);
            (void)submit_reply(session, reply, FTP_REPLY_READ_NEXT);
        }
    } else if (strcasecmp(line, "QUIT") == 0) {
        (void)submit_reply(session, "221 Goodbye\r\n", FTP_REPLY_STOP);
    } else {
        (void)submit_reply(session, "502 Command not implemented\r\n",
                           FTP_REPLY_READ_NEXT);
    }
}

static void process_next_command(ftp_session *session)
{
    if (session->reply_pending || session->control_read_pending ||
        session->server->stop)
        return;

    char *newline = memchr(session->control_buf, '\n', session->control_len);
    if (!newline) {
        (void)submit_control_read(session);
        return;
    }

    size_t line_len = (size_t)(newline - session->control_buf);
    if (line_len && session->control_buf[line_len - 1] == '\r')
        line_len--;
    session->control_buf[line_len] = '\0';

    size_t consumed = (size_t)(newline - session->control_buf) + 1;
    size_t remaining = session->control_len - consumed;
    memmove(session->control_buf, session->control_buf + consumed, remaining);
    session->control_len = remaining;

    handle_command(session, session->control_buf);
}

static void complete_control_read(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    session->control_read_pending = false;
    op_free(op);
    if (result <= 0) {
        if (result < 0)
            log_errno("FTP control read", saved_errno);
        session->server->stop = true;
        return;
    }
    session->control_len += (size_t)result;
    process_next_command(session);
}

static void complete_control_write(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    if (result <= 0) {
        if (result < 0)
            log_errno("FTP control write", saved_errno);
        session->reply_pending = false;
        op_free(op);
        session->server->stop = true;
        return;
    }
    op->offset += (size_t)result;
    if (op->offset < op->length) {
        if (submit_operation(op) == 0)
            return;
        session->reply_pending = false;
        op_free(op);
        session->server->stop = true;
        return;
    }

    ftp_reply_after after = op->reply_after;
    session->reply_pending = false;
    op_free(op);
    switch (after) {
    case FTP_REPLY_READ_NEXT:
        process_next_command(session);
        break;
    case FTP_REPLY_START_TRANSFER:
        session->start_after_reply = true;
        maybe_start_transfer(session);
        break;
    case FTP_REPLY_STOP:
        session->server->stop = true;
        break;
    }
}

static void complete_stor_read(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    if (result < 0) {
        log_errno("FTP data read", saved_errno);
        close_transfer_file(session);
        int fd = session->data_fd;
        session->data_fd = -1;
        op_free(op);
        if (fd >= 0)
            (void)submit_close(session, fd, FTP_CLOSE_STOR_ERROR);
        return;
    }
    if (result == 0) {
        int fd = session->data_fd;
        session->data_fd = -1;
        op_free(op);
        bool ok = fflush(session->file) == 0;
        if (fclose(session->file) != 0)
            ok = false;
        session->file = NULL;
        ftp_close_after after = ok ? FTP_CLOSE_STOR_OK : FTP_CLOSE_STOR_ERROR;
        if (fd >= 0 && submit_close(session, fd, after) == 0)
            return;
        session->server->stop = true;
        return;
    }
    if (fwrite(op->buffer, 1, (size_t)result, session->file) !=
        (size_t)result) {
        log_errno("write FTP upload", errno ? errno : EIO);
        close_transfer_file(session);
        int fd = session->data_fd;
        session->data_fd = -1;
        op_free(op);
        if (fd >= 0)
            (void)submit_close(session, fd, FTP_CLOSE_STOR_ERROR);
        return;
    }
    session->file_len += (uint64_t)result;
    if (submit_operation(op) == 0)
        return;
    op_free(op);
    session->server->stop = true;
}

static void complete_retr_write(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    if (result <= 0) {
        if (result < 0)
            log_errno("FTP data write", saved_errno);
        close_transfer_file(session);
        int fd = session->data_fd;
        session->data_fd = -1;
        op_free(op);
        if (fd >= 0)
            (void)submit_close(session, fd, FTP_CLOSE_STOR_ERROR);
        return;
    }
    op->offset += (size_t)result;
    if (op->offset < op->length) {
        if (submit_operation(op) == 0)
            return;
        op_free(op);
        session->server->stop = true;
        return;
    }
    session->file_offset += op->length;
    op_free(op);
    if (submit_retr_write(session) != 0)
        session->server->stop = true;
}

static void complete_close(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    ftp_close_after after = op->close_after;
    if (result < 0)
        log_errno("FTP async close", saved_errno);
    op_free(op);
    if (!session)
        return;

    switch (after) {
    case FTP_CLOSE_NONE:
        return;
    case FTP_CLOSE_STOR_OK:
        session->transfer = FTP_TRANSFER_NONE;
        (void)submit_reply(session, "226 Transfer complete\r\n", FTP_REPLY_READ_NEXT);
        return;
    case FTP_CLOSE_STOR_ERROR:
        session->transfer = FTP_TRANSFER_NONE;
        (void)submit_reply(session, "451 Transfer aborted\r\n", FTP_REPLY_READ_NEXT);
        return;
    case FTP_CLOSE_RETR_OK:
        session->transfer = FTP_TRANSFER_NONE;
        (void)submit_reply(session, "226 Transfer complete\r\n", FTP_REPLY_READ_NEXT);
        return;
    }
}

static void complete_data_accept(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    session->data_accept_pending = false;
    op_free(op);
    if (result < 0) {
        log_errno("FTP data accept", saved_errno);
        if (session->transfer != FTP_TRANSFER_NONE)
            (void)submit_reply(session, "425 Cannot open data connection\r\n",
                               FTP_REPLY_READ_NEXT);
        return;
    }
    session->data_fd = result;
    if (session->data_listen_fd >= 0) {
        int listener = session->data_listen_fd;
        session->data_listen_fd = -1;
        (void)submit_close(session, listener, FTP_CLOSE_NONE);
    }
    maybe_start_transfer(session);
}

static void complete_data_getsockname(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    int listener = op->fd;
    op_free(op);
    if (result < 0) {
        log_errno("FTP passive getsockname", saved_errno);
        (void)submit_reply(session, "425 Cannot enter passive mode\r\n",
                           FTP_REPLY_READ_NEXT);
        return;
    }

    uint16_t port = ntohs(session->pasv_addr.sin_port);
    char reply[160];
    if (session->pasv_extended) {
        snprintf(reply, sizeof(reply), "229 Entering Extended Passive Mode (|||%u|)\r\n",
                 port);
    } else {
        const uint8_t *ip = (const uint8_t *)&session->server->listen_addr.sin_addr;
        snprintf(reply, sizeof(reply),
                 "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u)\r\n",
                 ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xffu);
    }
    if (submit_data_accept(session) != 0 ||
        submit_reply(session, reply, FTP_REPLY_READ_NEXT) != 0) {
        (void)submit_close(session, listener, FTP_CLOSE_NONE);
        session->data_listen_fd = -1;
        session->server->stop = true;
    }
}

static void complete_data_setup(ftp_op *op, int result, int saved_errno)
{
    ftp_session *session = op->session;
    ftp_op_kind kind = op->kind;
    int fd = op->fd;
    op_free(op);
    if (result < 0) {
        char where[128];
        snprintf(where, sizeof(where), "FTP passive %s", op_name(kind));
        log_errno(where, saved_errno);
        if (session->data_listen_fd >= 0) {
            int listener = session->data_listen_fd;
            session->data_listen_fd = -1;
            (void)submit_close(session, listener, FTP_CLOSE_NONE);
        }
        (void)submit_reply(session, "425 Cannot enter passive mode\r\n",
                           FTP_REPLY_READ_NEXT);
        return;
    }

    switch (kind) {
    case FTP_OP_DATA_SOCKET:
        session->data_listen_fd = result;
        (void)submit_simple(FTP_OP_DATA_REUSEADDR, session, result);
        break;
    case FTP_OP_DATA_REUSEADDR:
        (void)submit_simple(FTP_OP_DATA_BIND, session, fd);
        break;
    case FTP_OP_DATA_BIND:
        (void)submit_simple(FTP_OP_DATA_LISTEN, session, fd);
        break;
    case FTP_OP_DATA_LISTEN:
        (void)submit_simple(FTP_OP_DATA_GETSOCKNAME, session, fd);
        break;
    default:
        break;
    }
}

static void complete_server_setup(ftp_op *op, int result, int saved_errno)
{
    ftp_op_kind kind = op->kind;
    int fd = op->fd;
    op_free(op);
    if (result < 0) {
        log_errno("FTP server setup", saved_errno);
        g_server.stop = true;
        return;
    }

    switch (kind) {
    case FTP_OP_SERVER_SOCKET:
        g_server.listen_fd = result;
        (void)submit_simple(FTP_OP_SERVER_REUSEADDR, NULL, result);
        break;
    case FTP_OP_SERVER_REUSEADDR:
        (void)submit_simple(FTP_OP_SERVER_BIND, NULL, fd);
        break;
    case FTP_OP_SERVER_BIND:
        (void)submit_simple(FTP_OP_SERVER_LISTEN, NULL, fd);
        break;
    case FTP_OP_SERVER_LISTEN:
        if (submit_simple(FTP_OP_CONTROL_ACCEPT, NULL, fd) != 0)
            g_server.stop = true;
        break;
    default:
        break;
    }
}

static void complete_control_accept(ftp_op *op, int result, int saved_errno)
{
    op_free(op);
    if (result < 0) {
        log_errno("FTP control accept", saved_errno);
        g_server.stop = true;
        return;
    }
    ftp_session *session = calloc(1, sizeof(*session));
    if (!session) {
        g_server.stop = true;
        return;
    }
    session->server = &g_server;
    session->control_fd = result;
    session->data_listen_fd = -1;
    session->data_fd = -1;
    g_server.session = session;
    log_line("INFO", "control connection accepted");
    if (submit_reply(session, "220 NetFast async FTP ready\r\n",
                     FTP_REPLY_READ_NEXT) != 0)
        g_server.stop = true;
}

static void dispatch_completion(net_async_req *request)
{
    ftp_op *op = op_find(request);
    if (!op) {
        log_line("ERROR", "completion did not match an FTP operation");
        net_async_req_destroy(request);
        g_server.stop = true;
        return;
    }
    int result = net_async_req_result(request);
    int saved_errno = result < 0 ? -result : 0;
    op_unlink(op);
    op->request = NULL;
    net_async_req_destroy(request);

    switch (op->kind) {
    case FTP_OP_SERVER_SOCKET:
    case FTP_OP_SERVER_REUSEADDR:
    case FTP_OP_SERVER_BIND:
    case FTP_OP_SERVER_LISTEN:
        complete_server_setup(op, result, saved_errno);
        break;
    case FTP_OP_CONTROL_ACCEPT:
        complete_control_accept(op, result, saved_errno);
        break;
    case FTP_OP_CONTROL_READ:
        complete_control_read(op, result, saved_errno);
        break;
    case FTP_OP_CONTROL_WRITE:
        complete_control_write(op, result, saved_errno);
        break;
    case FTP_OP_DATA_SOCKET:
    case FTP_OP_DATA_REUSEADDR:
    case FTP_OP_DATA_BIND:
    case FTP_OP_DATA_LISTEN:
        complete_data_setup(op, result, saved_errno);
        break;
    case FTP_OP_DATA_GETSOCKNAME:
        complete_data_getsockname(op, result, saved_errno);
        break;
    case FTP_OP_DATA_ACCEPT:
        complete_data_accept(op, result, saved_errno);
        break;
    case FTP_OP_STOR_READ:
        complete_stor_read(op, result, saved_errno);
        break;
    case FTP_OP_RETR_WRITE:
        complete_retr_write(op, result, saved_errno);
        break;
    case FTP_OP_CLOSE:
        complete_close(op, result, saved_errno);
        break;
    }
}

static int parse_args(int argc, char **argv)
{
    const char *bind_ip = "127.0.0.1";
    uint16_t port = 2121;
    uint16_t passive_port = FTP_PASSIVE_PORT;
    const char *root = "/tmp/netfast-ftp-root";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_ip = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (!end || *end || value == 0 || value > 65535)
                return -1;
            port = (uint16_t)value;
        } else if (strcmp(argv[i], "--pasv-port") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (!end || *end || value == 0 || value > 65535)
                return -1;
            passive_port = (uint16_t)value;
        } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            root = argv[++i];
        } else {
            return -1;
        }
    }

    if (strlen(root) >= sizeof(g_server.root) ||
        inet_pton(AF_INET, bind_ip, &g_server.listen_addr.sin_addr) != 1)
        return -1;
    snprintf(g_server.root, sizeof(g_server.root), "%s", root);
    snprintf(g_server.advertised_ip, sizeof(g_server.advertised_ip), "%s", bind_ip);
    g_server.listen_addr.sin_family = AF_INET;
    g_server.listen_addr.sin_port = htons(port);
    g_server.passive_port = passive_port;
    g_server.reuseaddr = 1;

    if (mkdir(g_server.root, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    if (parse_args(argc, argv) != 0) {
        fprintf(stderr, "Usage: %s [--bind IPv4] [--port 1-65535] "
                "[--pasv-port 1-65535] [--root DIR]\n",
                argv[0]);
        return 2;
    }
    g_server.cq_fd = net_async_create();
    if (g_server.cq_fd < 0) {
        perror("net_async_create");
        return 1;
    }
    if (submit_simple(FTP_OP_SERVER_SOCKET, NULL, -1) != 0) {
        perror("start FTP server");
        net_async_close(g_server.cq_fd);
        return 1;
    }

    printf("NetFast async FTP listening on %s:%u, root=%s\n",
           g_server.advertised_ip, ntohs(g_server.listen_addr.sin_port),
           g_server.root);
    fflush(stdout);

    while (!g_server.stop) {
        net_async_req *completed[32];
        int count = net_async_wait(g_server.cq_fd, completed, 1, 32, 1000);
        if (count < 0) {
            perror("net_async_wait");
            g_server.stop = true;
            break;
        }
        for (int i = 0; i < count; ++i)
            dispatch_completion(completed[i]);
    }

    /* Let queued FIN/ACK packets progress before process cleanup detaches XDP. */
    sleep(2);
    if (g_server.cq_fd >= 0)
        (void)net_async_close(g_server.cq_fd);
    if (g_server.session)
        close_transfer_file(g_server.session);
    free(g_server.session);
    return 0;
}
