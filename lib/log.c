#include "log.h"

#include "init.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int file_fd = -1;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static char active_logfile[256];

#define LOG_RATE_LIMIT_MS 1000ULL

static uint64_t log_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static bool log_rate_limit_allow(log_rate_limit *limit, uint64_t *suppressed)
{
    uint64_t now_ms = log_now_ms();
    uint64_t last_ms = atomic_load_explicit(&limit->last_ms, memory_order_relaxed);

    for (;;) {
        if (last_ms && now_ms - last_ms < LOG_RATE_LIMIT_MS) {
            atomic_fetch_add_explicit(&limit->suppressed, 1, memory_order_relaxed);
            return false;
        }

        if (atomic_compare_exchange_weak_explicit(&limit->last_ms, &last_ms, now_ms,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
            *suppressed = atomic_exchange_explicit(&limit->suppressed, 0,
                                                    memory_order_relaxed);
            return true;
        }
    }
}

static void log_write_all(int fd, const char* data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t written = write(fd, data + offset, len - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        break;
    }
}

static void log_vout(const char *format, va_list args, uint64_t suppressed)
{
    char log_buf[1024];
    int written = vsnprintf(log_buf, sizeof(log_buf), format, args);
    if (written < 0)
        return;

    size_t len = (size_t)written;
    if (len >= sizeof(log_buf))
        len = sizeof(log_buf) - 1;

    if (suppressed && len < sizeof(log_buf) - 1) {
        int suffix = snprintf(log_buf + len, sizeof(log_buf) - len,
                              " [suppressed=%" PRIu64 "]", suppressed);
        if (suffix > 0) {
            size_t suffix_len = (size_t)suffix;
            len += suffix_len < sizeof(log_buf) - len ? suffix_len : sizeof(log_buf) - len - 1;
        }
    }

    if (len == 0 || log_buf[len - 1] != '\n') {
        if (len < sizeof(log_buf) - 1)
            log_buf[len++] = '\n';
        else
            log_buf[len - 1] = '\n';
    }

    pthread_mutex_lock(&log_lock);
    int fd = file_fd;
    if (fd < 0) {
        pthread_mutex_unlock(&log_lock);
        return;
    }

    log_write_all(fd, log_buf, len);
    pthread_mutex_unlock(&log_lock);
}

int log_init(void)
{
    if (!g_cfg.logfile[0])
        return -1;

    pthread_mutex_lock(&log_lock);
    if (file_fd >= 0 && strcmp(active_logfile, g_cfg.logfile) == 0) {
        pthread_mutex_unlock(&log_lock);
        return 0;
    }
    pthread_mutex_unlock(&log_lock);

    int fd = open(g_cfg.logfile, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;

    pthread_mutex_lock(&log_lock);
    int old_fd = file_fd;
    if (old_fd >= 0 && strcmp(active_logfile, g_cfg.logfile) == 0) {
        pthread_mutex_unlock(&log_lock);
        close(fd);
        return 0;
    }

    file_fd = fd;
    snprintf(active_logfile, sizeof(active_logfile), "%s", g_cfg.logfile);
    pthread_mutex_unlock(&log_lock);

    if (old_fd >= 0)
        close(old_fd);

    return 0;
}

void log_out(const char *format, ...)
{
    if (!format)
        return;

    va_list args;
    va_start(args, format);
    log_vout(format, args, 0);
    va_end(args);
}

void log_out_limited(log_rate_limit *limit, const char *format, ...)
{
    if (!limit || !format)
        return;

    uint64_t suppressed;
    if (!log_rate_limit_allow(limit, &suppressed))
        return;

    va_list args;
    va_start(args, format);
    log_vout(format, args, suppressed);
    va_end(args);
}
