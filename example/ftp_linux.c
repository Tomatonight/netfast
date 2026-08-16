/*
 * Minimal passive-mode FTP server using Linux kernel sockets.
 *
 * This intentionally implements the same command subset and uses the same
 * 32 KiB data chunks as ftp_async.c so it can serve as a performance and
 * correctness baseline for NetFast.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FTP_CONTROL_CAP 4096U
#define FTP_DATA_CHUNK (32U * 1024U)
#define FTP_NAME_CAP 128U
#define FTP_PASSIVE_PORT 30000U

typedef struct ftp_server {
    struct sockaddr_in listen_addr;
    char advertised_ip[INET_ADDRSTRLEN];
    char device[IFNAMSIZ];
    char root[PATH_MAX];
    uint16_t passive_port;
} ftp_server;

static double elapsed_seconds(const struct timespec *start,
                              const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static void log_transfer(const char *kind, uint64_t bytes,
                         const struct timespec *start)
{
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    double seconds = elapsed_seconds(start, &end);
    double mib_s = seconds > 0.0
        ? (double)bytes / (1024.0 * 1024.0) / seconds : 0.0;
    fprintf(stderr, "[ftp-linux] INFO: %s %llu bytes in %.3f s, %.2f MiB/s\n",
            kind, (unsigned long long)bytes, seconds, mib_s);
    fflush(stderr);
}

static int send_all(int fd, const void *buffer, size_t length)
{
    const char *cursor = buffer;
    while (length != 0) {
        ssize_t sent = send(fd, cursor, length, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (sent == 0) {
            errno = EPIPE;
            return -1;
        }
        cursor += (size_t)sent;
        length -= (size_t)sent;
    }
    return 0;
}

static int send_reply(int fd, const char *reply)
{
    return send_all(fd, reply, strlen(reply));
}

static int recv_line(int fd, char *line, size_t capacity)
{
    size_t length = 0;
    while (length + 1 < capacity) {
        char c;
        ssize_t received = recv(fd, &c, 1, 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (received == 0)
            return 0;
        if (c == '\n') {
            if (length != 0 && line[length - 1] == '\r')
                length--;
            line[length] = '\0';
            return 1;
        }
        line[length++] = c;
    }
    errno = EMSGSIZE;
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

static int make_path(const ftp_server *server, const char *filename,
                     char path[PATH_MAX])
{
    int written = snprintf(path, PATH_MAX, "%s/%s", server->root, filename);
    return written >= 0 && written < PATH_MAX ? 0 : -1;
}

static int create_listener(const struct sockaddr_in *address, const char *device)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    int reuseaddr = 1;
    if ((device[0] != '\0' &&
         setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device,
                    strlen(device) + 1) != 0) ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                   sizeof(reuseaddr)) != 0 ||
        bind(fd, (const struct sockaddr *)address, sizeof(*address)) != 0 ||
        listen(fd, 8) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int start_passive(const ftp_server *server, int control_fd,
                         bool extended)
{
    struct sockaddr_in address = server->listen_addr;
    address.sin_port = htons(server->passive_port);
    int fd = create_listener(&address, server->device);
    if (fd < 0)
        return -1;

    char reply[128];
    if (extended) {
        snprintf(reply, sizeof(reply), "229 Entering Extended Passive Mode (|||%u|)\r\n",
                 server->passive_port);
    } else {
        const uint8_t *ip = (const uint8_t *)&address.sin_addr;
        snprintf(reply, sizeof(reply),
                 "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u)\r\n",
                 (unsigned)ip[0], (unsigned)ip[1],
                 (unsigned)ip[2], (unsigned)ip[3],
                 (unsigned)(server->passive_port >> 8),
                 (unsigned)(server->passive_port & 0xffu));
    }
    if (send_reply(control_fd, reply) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int accept_data(int passive_fd, int control_fd)
{
    if (send_reply(control_fd, "150 Opening passive data connection\r\n") != 0)
        return -1;
    for (;;) {
        int fd = accept(passive_fd, NULL, NULL);
        if (fd >= 0)
            return fd;
        if (errno != EINTR)
            return -1;
    }
}

static int receive_file(const ftp_server *server, int passive_fd,
                        int control_fd, const char *filename)
{
    char path[PATH_MAX];
    if (!safe_filename(filename) || make_path(server, filename, path) != 0) {
        (void)send_reply(control_fd, "550 Invalid filename\r\n");
        return 0;
    }
    FILE *file = fopen(path, "wb");
    if (!file) {
        (void)send_reply(control_fd, "550 Cannot create file\r\n");
        return 0;
    }
    int data_fd = accept_data(passive_fd, control_fd);
    if (data_fd < 0) {
        fclose(file);
        return -1;
    }

    char buffer[FTP_DATA_CHUNK];
    uint64_t total = 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int ret = 0;
    for (;;) {
        ssize_t received = recv(data_fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            ret = -1;
            break;
        }
        if (received == 0)
            break;
        if (fwrite(buffer, 1, (size_t)received, file) != (size_t)received) {
            errno = EIO;
            ret = -1;
            break;
        }
        total += (uint64_t)received;
    }
    int saved_errno = errno;
    if (fclose(file) != 0 && ret == 0) {
        saved_errno = errno;
        ret = -1;
    }
    close(data_fd);
    if (ret != 0) {
        errno = saved_errno;
        return -1;
    }
    log_transfer("STOR", total, &start);
    return send_reply(control_fd, "226 Transfer complete\r\n");
}

static int send_file(const ftp_server *server, int passive_fd,
                     int control_fd, const char *filename)
{
    char path[PATH_MAX];
    if (!safe_filename(filename) || make_path(server, filename, path) != 0) {
        (void)send_reply(control_fd, "550 Invalid filename\r\n");
        return 0;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        (void)send_reply(control_fd, "550 File unavailable\r\n");
        return 0;
    }
    int data_fd = accept_data(passive_fd, control_fd);
    if (data_fd < 0) {
        fclose(file);
        return -1;
    }

    char buffer[FTP_DATA_CHUNK];
    uint64_t total = 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int ret = 0;
    for (;;) {
        size_t length = fread(buffer, 1, sizeof(buffer), file);
        if (length != 0) {
            if (send_all(data_fd, buffer, length) != 0) {
                ret = -1;
                break;
            }
            total += length;
        }
        if (length != sizeof(buffer)) {
            if (ferror(file)) {
                errno = EIO;
                ret = -1;
            }
            break;
        }
    }
    int saved_errno = errno;
    fclose(file);
    close(data_fd);
    if (ret != 0) {
        errno = saved_errno;
        return -1;
    }
    log_transfer("RETR", total, &start);
    return send_reply(control_fd, "226 Transfer complete\r\n");
}

static int file_size(const ftp_server *server, int control_fd,
                     const char *filename)
{
    char path[PATH_MAX];
    struct stat status;
    if (!safe_filename(filename) || make_path(server, filename, path) != 0 ||
        stat(path, &status) != 0 || status.st_size < 0)
        return send_reply(control_fd, "550 File unavailable\r\n");
    char reply[128];
    snprintf(reply, sizeof(reply), "213 %lld\r\n", (long long)status.st_size);
    return send_reply(control_fd, reply);
}

static int serve_session(const ftp_server *server, int control_fd)
{
    int passive_fd = -1;
    bool logged_in = false;
    char line[FTP_CONTROL_CAP];
    if (send_reply(control_fd, "220 Linux socket FTP ready\r\n") != 0)
        return -1;

    for (;;) {
        int result = recv_line(control_fd, line, sizeof(line));
        if (result <= 0)
            break;
        char *argument = line;
        while (*argument && !isspace((unsigned char)*argument))
            argument++;
        if (*argument)
            *argument++ = '\0';
        while (*argument == ' ' || *argument == '\t')
            argument++;

        if (strcasecmp(line, "USER") == 0) {
            logged_in = false;
            result = send_reply(control_fd, "331 User name okay, need password\r\n");
        } else if (strcasecmp(line, "PASS") == 0) {
            logged_in = true;
            result = send_reply(control_fd, "230 Login successful\r\n");
        } else if (strcasecmp(line, "SYST") == 0) {
            result = send_reply(control_fd, "215 UNIX Type: L8\r\n");
        } else if (strcasecmp(line, "FEAT") == 0) {
            result = send_reply(control_fd,
                "211-Features\r\n EPSV\r\n PASV\r\n SIZE\r\n211 End\r\n");
        } else if (strcasecmp(line, "PWD") == 0 ||
                   strcasecmp(line, "XPWD") == 0) {
            result = send_reply(control_fd, "257 \"/\" is current directory\r\n");
        } else if (strcasecmp(line, "TYPE") == 0) {
            result = send_reply(control_fd, "200 Type set\r\n");
        } else if (strcasecmp(line, "NOOP") == 0) {
            result = send_reply(control_fd, "200 NOOP okay\r\n");
        } else if (strcasecmp(line, "PASV") == 0 ||
                   strcasecmp(line, "EPSV") == 0) {
            if (passive_fd >= 0) {
                close(passive_fd);
            }
            passive_fd = start_passive(server, control_fd,
                                       strcasecmp(line, "EPSV") == 0);
            result = passive_fd >= 0 ? 0 : -1;
        } else if (strcasecmp(line, "STOR") == 0 ||
                   strcasecmp(line, "RETR") == 0) {
            if (!logged_in) {
                result = send_reply(control_fd,
                                    "530 Please login with USER and PASS\r\n");
            } else if (passive_fd < 0) {
                result = send_reply(control_fd, "425 Use PASV or EPSV first\r\n");
            } else {
                result = strcasecmp(line, "STOR") == 0
                    ? receive_file(server, passive_fd, control_fd, argument)
                    : send_file(server, passive_fd, control_fd, argument);
                close(passive_fd);
                passive_fd = -1;
            }
        } else if (strcasecmp(line, "SIZE") == 0) {
            result = file_size(server, control_fd, argument);
        } else if (strcasecmp(line, "QUIT") == 0) {
            (void)send_reply(control_fd, "221 Goodbye\r\n");
            break;
        } else {
            result = send_reply(control_fd, "502 Command not implemented\r\n");
        }
        if (result != 0)
            break;
    }
    if (passive_fd >= 0)
        close(passive_fd);
    return 0;
}

static int parse_args(int argc, char **argv, ftp_server *server)
{
    const char *bind_ip = "127.0.0.1";
    const char *root = "/tmp/linux-ftp-root";
    uint16_t port = 2121;
    uint16_t passive_port = FTP_PASSIVE_PORT;

    for (int i = 1; i < argc; ++i) {
        const char *value;
        if ((strcmp(argv[i], "--bind") == 0 ||
             strcmp(argv[i], "--port") == 0 ||
             strcmp(argv[i], "--pasv-port") == 0 ||
             strcmp(argv[i], "--root") == 0 ||
             strcmp(argv[i], "--device") == 0) && i + 1 < argc) {
            value = argv[++i];
        } else {
            return -1;
        }
        if (strcmp(argv[i - 1], "--bind") == 0) {
            bind_ip = value;
        } else if (strcmp(argv[i - 1], "--root") == 0) {
            root = value;
        } else if (strcmp(argv[i - 1], "--device") == 0) {
            if (strlen(value) >= sizeof(server->device))
                return -1;
            snprintf(server->device, sizeof(server->device), "%s", value);
        } else {
            char *end = NULL;
            unsigned long number = strtoul(value, &end, 10);
            if (!end || *end || number == 0 || number > 65535)
                return -1;
            if (strcmp(argv[i - 1], "--port") == 0)
                port = (uint16_t)number;
            else
                passive_port = (uint16_t)number;
        }
    }
    if (strlen(root) >= sizeof(server->root) ||
        inet_pton(AF_INET, bind_ip, &server->listen_addr.sin_addr) != 1)
        return -1;
    snprintf(server->root, sizeof(server->root), "%s", root);
    snprintf(server->advertised_ip, sizeof(server->advertised_ip), "%s", bind_ip);
    server->listen_addr.sin_family = AF_INET;
    server->listen_addr.sin_port = htons(port);
    server->passive_port = passive_port;
    if (mkdir(server->root, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    ftp_server server = {0};
    if (parse_args(argc, argv, &server) != 0) {
        fprintf(stderr, "Usage: %s [--bind IPv4] [--port 1-65535] "
                "[--pasv-port 1-65535] [--root DIR] [--device IFNAME]\n",
                argv[0]);
        return 2;
    }
    int listen_fd = create_listener(&server.listen_addr, server.device);
    if (listen_fd < 0) {
        perror("create FTP listener");
        return 1;
    }
    printf("Linux socket FTP listening on %s:%u, root=%s\n",
           server.advertised_ip, ntohs(server.listen_addr.sin_port), server.root);
    fflush(stdout);

    int control_fd;
    do {
        control_fd = accept(listen_fd, NULL, NULL);
    } while (control_fd < 0 && errno == EINTR);
    if (control_fd < 0) {
        perror("accept FTP control connection");
        close(listen_fd);
        return 1;
    }
    fprintf(stderr, "[ftp-linux] INFO: control connection accepted\n");
    int ret = serve_session(&server, control_fd);
    if (ret != 0)
        perror("serve FTP session");
    close(control_fd);
    close(listen_fd);
    return ret != 0;
}
