#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "fd_entry.h"
#include "req.h"

#define FD_START 0x08888888
#define FD_TABLE_CAP (1024 * 128)
#define FD_LOCK_COUNT 256

static fd_entry** g_fd_table;
static uint32_t* g_free_slots;
static uint32_t g_free_n;
static spin_rwlock_t g_fd_locks[FD_LOCK_COUNT];
static spin_rwlock_t g_free_lock;

static inline int fd_to_slot(int fd)
{
    if (fd < FD_START)
        return -1;
    return fd - FD_START;
}

static inline uint32_t fd_lock_idx(uint32_t slot)
{
    return slot & (FD_LOCK_COUNT - 1U);
}

int fd_table_init(void)
{
    if (g_fd_table)
        return 0;

    fd_entry** table = calloc(FD_TABLE_CAP, sizeof(*table));
    uint32_t* free_slots = malloc(sizeof(*free_slots) * FD_TABLE_CAP);
    if (!table || !free_slots) {
        free(table);
        free(free_slots);
        return -1;
    }

    for (uint32_t i = 0; i < FD_LOCK_COUNT; ++i)
        spin_rwlock_init(&g_fd_locks[i]);

    g_fd_table = table;
    g_free_slots = free_slots;
    g_free_n = FD_TABLE_CAP;
    for (uint32_t i = 0; i < FD_TABLE_CAP; ++i)
        g_free_slots[i] = FD_TABLE_CAP - 1u - i;
    return 0;
}

static void destroy_fd_entry(fd_entry* entry)
{
    int slot = fd_to_slot(entry->fd);
    if (slot >= 0) {
        uint32_t idx = fd_lock_idx((uint32_t)slot);
        spin_rwlock_wrlock(&g_fd_locks[idx]);
        g_fd_table[slot] = NULL;
        spin_rwlock_unlock(&g_fd_locks[idx]);

        spin_rwlock_wrlock(&g_free_lock);
        g_free_slots[g_free_n++] = (uint32_t)slot;
        spin_rwlock_unlock(&g_free_lock);
    }

    mutex_destroy(&entry->mtx);
    free(entry);
}

fd_entry* alloc_fd_entry_with_worker(void* value, const fd_entry_ops* ops,
                                     worker* w)
{
    if (fd_table_init() < 0)
        return NULL;

    CREATE_REF(fd_entry, entry, destroy_fd_entry);
    if (!entry)
        return NULL;

    entry->fd = -1;
    entry->value = value;
    entry->ops = ops;
    atomic_init(&entry->w, (uintptr_t)w);
    mutex_init(&entry->mtx);

    spin_rwlock_wrlock(&g_free_lock);
    if (g_free_n == 0) {
        spin_rwlock_unlock(&g_free_lock);
        DESTROY_REF(entry);
        return NULL;
    }

    uint32_t slot = g_free_slots[--g_free_n];
    spin_rwlock_unlock(&g_free_lock);

    entry->fd = FD_START + (int)slot;

    uint32_t idx = fd_lock_idx(slot);
    spin_rwlock_wrlock(&g_fd_locks[idx]);
    g_fd_table[slot] = entry;
    spin_rwlock_unlock(&g_fd_locks[idx]);
    return entry;
}

fd_entry* hold_fd_entry(int fd)
{
    int slot = fd_to_slot(fd);
    if (slot < 0)
        return NULL;

    if ((uint32_t)slot >= FD_TABLE_CAP)
        return NULL;

    uint32_t idx = fd_lock_idx((uint32_t)slot);
    spin_rwlock_rdlock(&g_fd_locks[idx]);
    fd_entry* entry = g_fd_table[slot];
    if (entry && (!REF_USABLE(entry) || !INC_REF_NOT_ZERO(entry)))
        entry = NULL;
    spin_rwlock_unlock(&g_fd_locks[idx]);

    if (entry && !REF_USABLE(entry)) {
        PUT_REF(entry);
        entry = NULL;
    }
    return entry;
}

fd_entry* get_sock_entry_by_req(const req* r)
{

    switch (r->type) {
    case REQ_BIND:         return r->argv.bind.entry;
    case REQ_CONNECT:      return r->argv.connect.entry;
    case REQ_LISTEN:       return r->argv.listen.entry;
    case REQ_ACCEPT:       return r->argv.accept.entry;
    case REQ_WRITE:        return r->argv.write.entry;
    case REQ_READ:         return r->argv.read.entry;
    case REQ_SENDTO:       return r->argv.sendto.entry;
    case REQ_RECVFROM:     return r->argv.recvfrom.entry;
    case REQ_GETSOCKNAME:  return r->argv.getsockname.entry;
    case REQ_GETPEERNAME:  return r->argv.getpeername.entry;
    case REQ_CLOSE:        return r->argv.close.entry;
    case REQ_SHUTDOWN:     return r->argv.shutdown.entry;
    case REQ_SETSOCKOPT:   return r->argv.setsockopt.entry;
    case REQ_GETSOCKOPT:   return r->argv.getsockopt.entry;
    case REQ_FCNTL:        return r->argv.fcntl.entry;
    case REQ_POLL:        return r->argv.poll.entry;
    case REQ_EPOLL_CTL:  return r->argv.epoll_ctl.entry;
    default:               return NULL;
    }
}
