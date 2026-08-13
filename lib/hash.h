#ifndef HASH_H
#define HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "base.h"

#define MIN_HASH_SIZE 256u

typedef struct hash_node {
    struct hash_node* next;
    struct hash_node** pprev;
    uint32_t hash;
} hash_node;

typedef struct hash {
    hash_node** buckets;
    spin_rwlock_t* bucket_locks;
    uint32_t size;
    uint32_t mask;
    ptrdiff_t key_offset;
    uint32_t key_len;
} hash;

#define HASH_KEY_OFFSET(type, node_member, key_member)                         \
    ((ptrdiff_t)offsetof(type, key_member) -                                   \
     (ptrdiff_t)offsetof(type, node_member))

#define HASH_CONTAINER_OF(node, type, member)                                 \
    ((type*)((uint8_t*)(node) - offsetof(type, member)))

hash* hash_create(uint32_t size, ptrdiff_t key_offset, uint32_t key_len);
hash* hash_create_safe(uint32_t size, ptrdiff_t key_offset,
                       uint32_t key_len);
/* The table must be empty; intrusive nodes are owned by their objects. */
void hash_destroy(hash* h);

uint32_t general_hash_algorithm(const uint8_t* data, uint32_t len);

static inline const void* hash_node_key(const hash* h,
                                        const hash_node* node)
{
    return (const uint8_t*)node + h->key_offset;
}

static inline uint32_t hash_bucket_index(const hash* h, uint32_t value)
{
    return value & h->mask;
}

/* The caller must hold the appropriate bucket lock for the locked helpers. */
hash_node* hash_find_node_locked(const hash* h, uint32_t index,
                                 const void* key, uint32_t value);
void hash_link_node_locked(hash* h, uint32_t index, hash_node* node,
                           uint32_t value);
void hash_unlink_node_locked(hash_node* node);

hash_node* hash_find_node(const hash* h, const void* key);
/* A node's key must remain unchanged while the node is in the table. */
bool hash_add_node(hash* h, hash_node* node);
/* The node must currently belong to this table. */
void hash_del_node(hash* h, hash_node* node);
hash_node* hash_del_key(hash* h, const void* key);
bool hash_is_empty(const hash* h);

#define HASH_HAS_BUCKET_LOCK(h) ((h)->bucket_locks != NULL)
#define HASH_BUCKET_RDLOCK(h, idx)                                             \
    do {                                                                       \
        if (HASH_HAS_BUCKET_LOCK(h))                                           \
            spin_rwlock_rdlock(&(h)->bucket_locks[(idx)]);                    \
    } while (0)
#define HASH_BUCKET_WRLOCK(h, idx)                                             \
    do {                                                                       \
        if (HASH_HAS_BUCKET_LOCK(h))                                           \
            spin_rwlock_wrlock(&(h)->bucket_locks[(idx)]);                    \
    } while (0)
#define HASH_BUCKET_UNLOCK(h, idx)                                             \
    do {                                                                       \
        if (HASH_HAS_BUCKET_LOCK(h))                                           \
            spin_rwlock_unlock(&(h)->bucket_locks[(idx)]);                    \
    } while (0)

#endif
