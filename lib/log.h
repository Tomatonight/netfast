#ifndef LOG_H
#define LOG_H

#include <stdatomic.h>
#include <stdint.h>

typedef struct log_rate_limit {
    atomic_uint_fast64_t last_ms;
    atomic_uint_fast64_t suppressed;
} log_rate_limit;

#define LOG_RATE_LIMIT_INIT { 0, 0 }

int log_init(void);
void log_out(const char* format, ...) __attribute__((format(printf, 1, 2)));
void log_out_limited(log_rate_limit* limit, const char* format, ...)
    __attribute__((format(printf, 2, 3)));

#define LOG_LIMITED(prefix, format, ...) do { \
    static log_rate_limit log_limit = LOG_RATE_LIMIT_INIT; \
    log_out_limited(&log_limit, prefix " [%s:%d %s] " format, \
                    __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
} while (0)

#define WARN_LOG(format, ...) \
    LOG_LIMITED("[WARN]", format, ##__VA_ARGS__)

#define ERR_LOG(format, ...) \
    LOG_LIMITED("[ERROR]", format, ##__VA_ARGS__)

#ifdef DEBUG
#define DEBUG_LOG(format, ...) \
    log_out("[DEBUG] [%s:%d %s] " format, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define DEBUG_LOG(...) do { } while (0)
#endif

#endif
