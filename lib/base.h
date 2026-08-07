#ifndef BASE_H
#define BASE_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <time.h>


#define IP_STR "%u.%u.%u.%u"
#define IP_ARG(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]

typedef struct sockaddr_in sockaddr_in;

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

typedef struct ref_info {
    atomic_int ref_cnt;
    atomic_bool useful;
    void (*free_info)(void*);
} ref_info;

static inline void ref_inc(ref_info* r) {
    atomic_fetch_add_explicit(&r->ref_cnt, 1, memory_order_acq_rel);
}

static inline bool ref_inc_not_zero(ref_info* r) {
    int old = atomic_load_explicit(&r->ref_cnt, memory_order_acquire);
    while (old != 0) {
        if (atomic_compare_exchange_weak_explicit(
                &r->ref_cnt, &old, old + 1,
                memory_order_acq_rel, memory_order_acquire)) {
            return true;
        }
    }
    return false;
}


static inline bool ref_dec_and_test(ref_info* r)
{
    int old = atomic_load_explicit(&r->ref_cnt, memory_order_acquire);
    while (old != 0) {
        if (atomic_compare_exchange_weak_explicit(
                &r->ref_cnt, &old, old - 1,
                memory_order_acq_rel, memory_order_acquire))
            return old == 1;
    }
    return false;
}

#define CREATE_REF(type, name, free_fn)                   \
    type* name = (type*)calloc(1, sizeof(type));             \
    if (name) {                                              \
        atomic_init(&(name)->ref.ref_cnt, 1);                  \
        atomic_init(&(name)->ref.useful, true);               \
        (name)->ref.free_info = (void (*)(void*))(free_fn);    \
    }

#define INIT_REF(obj, free_fn)                            \
    do {                                                    \
        atomic_init(&(obj)->ref.ref_cnt, 1);                  \
        atomic_init(&(obj)->ref.useful, true);               \
        (obj)->ref.free_info = (void (*)(void*))(free_fn);    \
    } while (0)

#define REF_USABLE(obj) ((obj) && atomic_load_explicit(&(obj)->ref.useful, memory_order_acquire))

#define GET_REF(dst, src)                                 \
    do {                                                    \
        (dst) = (src);                                       \
        if ((dst)) {                                         \
            ref_inc(&(dst)->ref);                              \
        }                                                   \
    } while (0)

#define PUT_REF_NONNULL(obj)                              \
    do {                                                    \
        if (ref_dec_and_test(&(obj)->ref)) {                  \
            if ((obj)->ref.free_info) {                      \
                (obj)->ref.free_info((void*)(obj));            \
            } else {                                         \
                free((void*)(obj));                            \
            }                                                   \
        }                                                       \
    } while (0)

#define PUT_REF(obj)                                      \
    do {                                                    \
        if ((obj))                                          \
            PUT_REF_NONNULL(obj);                           \
    } while (0)

#define DESTROY_REF(obj)                                  \
    do {                                                    \
        if ((obj)) {                                         \
            atomic_store_explicit(&(obj)->ref.useful, false, memory_order_release); \
            PUT_REF_NONNULL(obj);                            \
        }                                                   \
    } while (0)

#define MOVE_REF(dst, src)                                   \
    do {                                                    \
        (dst) = (src);                                       \
        (src) = NULL;                                        \
    } while (0)
#define INC_REF(obj) ref_inc(&(obj)->ref)

#define INC_REF_NOT_ZERO(obj) ref_inc_not_zero(&(obj)->ref)
#define GET_REF_CNT(obj) \
    atomic_load_explicit(&(obj)->ref.ref_cnt, memory_order_acquire)

typedef pthread_spinlock_t spinlock_t;

static inline void spin_lock_init(spinlock_t* lock)
{
    (void)pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
}

static inline void spin_lock(spinlock_t* lock)
{
    (void)pthread_spin_lock(lock);
}

static inline void spin_unlock(spinlock_t* lock)
{
    (void)pthread_spin_unlock(lock);
}

typedef struct spin_rwlock {
    atomic_int state;
} spin_rwlock_t;

static inline void spin_rwlock_init(spin_rwlock_t* l)
{
    atomic_init(&l->state, 0);
}

static inline void spin_rwlock_rdlock(spin_rwlock_t* l)
{
    for (;;) {
        int s = atomic_load_explicit(&l->state, memory_order_acquire);
        if (s >= 0) {
            if (atomic_compare_exchange_weak_explicit(&l->state, &s, s + 1,
                                                     memory_order_acq_rel,
                                                     memory_order_relaxed))
                return;
            continue;
        }
        /* writer holds lock */
        sched_yield();
    }
}

static inline void spin_rwlock_wrlock(spin_rwlock_t* l)
{
    for (;;) {
        int expected = 0;
        if (atomic_compare_exchange_weak_explicit(&l->state, &expected, -1,
                                                 memory_order_acq_rel,
                                                 memory_order_relaxed))
            return;
        sched_yield();
    }
}

static inline void spin_rwlock_unlock(spin_rwlock_t* l)
{
    int s = atomic_load_explicit(&l->state, memory_order_acquire);
    if (s == -1) {
        atomic_store_explicit(&l->state, 0, memory_order_release);
        return;
    }

    atomic_fetch_sub_explicit(&l->state, 1, memory_order_acq_rel);
}

typedef pthread_mutex_t mutex_t;

static inline void mutex_init(mutex_t* mtx)
{
    (void)pthread_mutex_init(mtx, NULL);
}

static inline void mutex_lock(mutex_t* mtx)
{
    (void)pthread_mutex_lock(mtx);
}

static inline void mutex_unlock(mutex_t* mtx)
{
    (void)pthread_mutex_unlock(mtx);
}

static inline void mutex_destroy(mutex_t* mtx)
{
    (void)pthread_mutex_destroy(mtx);
}

extern __thread uint64_t current_time_ms
    __attribute__((tls_model("initial-exec")));

static inline uint64_t read_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint64_t)((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));
}

static inline uint64_t get_current_time_ms(void) {
    return current_time_ms;
};

uint16_t checksum_protocol(const void* data, uint32_t len, uint32_t saddr, uint32_t daddr, uint8_t protocol);
uint16_t checksum(const void* buff, uint32_t len, uint32_t start_sum);
uint32_t checksum_partial(const void* buff, uint32_t len, uint32_t start_sum);

static inline uint32_t get_time(const struct timeval* timeval)
{
    return (uint32_t)((uint64_t)timeval->tv_sec * 1000 +
                      (uint64_t)timeval->tv_usec / 1000);
}

#endif // BASE_H
