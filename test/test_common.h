#ifndef NETFAST_TEST_COMMON_H
#define NETFAST_TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>

#define TEST_FAIL(fmt, ...)                                                     \
    do {                                                                        \
        fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__,          \
                ##__VA_ARGS__);                                                \
        return 1;                                                               \
    } while (0)

#define TEST_ASSERT(expr)                                                       \
    do {                                                                        \
        if (!(expr))                                                            \
            TEST_FAIL("assertion failed: %s", #expr);                         \
    } while (0)

#define TEST_RUN(fn)                                                            \
    do {                                                                        \
        printf("[ RUN      ] %s\n", #fn);                                     \
        if ((fn)() != 0)                                                        \
            return 1;                                                           \
        printf("[       OK ] %s\n", #fn);                                     \
    } while (0)

#define TEST_RUN_CALL(label, expression)                                       \
    do {                                                                        \
        printf("[ RUN      ] %s\n", (label));                                  \
        if ((expression) != 0)                                                  \
            return 1;                                                           \
        printf("[       OK ] %s\n", (label));                                  \
    } while (0)

#endif
