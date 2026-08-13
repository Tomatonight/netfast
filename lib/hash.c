#include "hash.h"

#include <stdlib.h>
#include <string.h>

static uint32_t round_hash_size(uint32_t requested)
{
    uint32_t size = MIN_HASH_SIZE;
    while (size < requested && size <= UINT32_MAX / 2u)
        size <<= 1;
    return size >= requested ? size : 0;
}

hash* hash_create(uint32_t requested, ptrdiff_t key_offset, uint32_t key_len)
{
    uint32_t size = round_hash_size(requested);
    if (!size)
        return NULL;

    hash* h = calloc(1, sizeof(*h));
    if (!h)
        return NULL;
    h->buckets = calloc(size, sizeof(*h->buckets));
    if (!h->buckets) {
        free(h);
        return NULL;
    }
    h->size = size;
    h->mask = size - 1u;
    h->key_offset = key_offset;
    h->key_len = key_len;
    return h;
}

hash* hash_create_safe(uint32_t size, ptrdiff_t key_offset, uint32_t key_len)
{
    hash* h = hash_create(size, key_offset, key_len);
    if (!h)
        return NULL;

    h->bucket_locks = calloc(h->size, sizeof(*h->bucket_locks));
    if (!h->bucket_locks) {
        hash_destroy(h);
        return NULL;
    }
    for (uint32_t i = 0; i < h->size; i++)
        spin_rwlock_init(&h->bucket_locks[i]);
    return h;
}

void hash_destroy(hash* h)
{
    if (!h)
        return;
    free(h->bucket_locks);
    free(h->buckets);
    free(h);
}

uint32_t general_hash_algorithm(const uint8_t* data, uint32_t len)
{
    uint32_t value = 2166136261u;
    for (uint32_t i = 0; i < len; i++) {
        value ^= data[i];
        value *= 16777619u;
    }
    return value;
}

hash_node* hash_find_node_locked(const hash* h, uint32_t index,
                                 const void* key, uint32_t value)
{
    for (hash_node* node = h->buckets[index]; node; node = node->next) {
        if (node->hash == value &&
            memcmp(hash_node_key(h, node), key, h->key_len) == 0)
            return node;
    }
    return NULL;
}

void hash_link_node_locked(hash* h, uint32_t index, hash_node* node,
                           uint32_t value)
{
    node->hash = value;
    node->next = h->buckets[index];
    node->pprev = &h->buckets[index];
    if (node->next)
        node->next->pprev = &node->next;
    h->buckets[index] = node;
}

void hash_unlink_node_locked(hash_node* node)
{
    *node->pprev = node->next;
    if (node->next)
        node->next->pprev = node->pprev;
    node->next = NULL;
    node->pprev = NULL;
}

hash_node* hash_find_node(const hash* h, const void* key)
{
    uint32_t value = general_hash_algorithm(key, h->key_len);
    uint32_t index = hash_bucket_index(h, value);
    HASH_BUCKET_RDLOCK(h, index);
    hash_node* node = hash_find_node_locked(h, index, key, value);
    HASH_BUCKET_UNLOCK(h, index);
    return node;
}

bool hash_add_node(hash* h, hash_node* node)
{
    const void* key = hash_node_key(h, node);
    uint32_t value = general_hash_algorithm(key, h->key_len);
    uint32_t index = hash_bucket_index(h, value);
    HASH_BUCKET_WRLOCK(h, index);
    bool available = !hash_find_node_locked(h, index, key, value);
    if (available)
        hash_link_node_locked(h, index, node, value);
    HASH_BUCKET_UNLOCK(h, index);
    return available;
}

void hash_del_node(hash* h, hash_node* node)
{
    uint32_t index = hash_bucket_index(h, node->hash);
    HASH_BUCKET_WRLOCK(h, index);
    hash_unlink_node_locked(node);
    HASH_BUCKET_UNLOCK(h, index);
}

hash_node* hash_del_key(hash* h, const void* key)
{
    uint32_t value = general_hash_algorithm(key, h->key_len);
    uint32_t index = hash_bucket_index(h, value);
    HASH_BUCKET_WRLOCK(h, index);
    hash_node* node = hash_find_node_locked(h, index, key, value);
    if (node)
        hash_unlink_node_locked(node);
    HASH_BUCKET_UNLOCK(h, index);
    return node;
}

bool hash_is_empty(const hash* h)
{
    for (uint32_t i = 0; i < h->size; i++) {
        HASH_BUCKET_RDLOCK(h, i);
        bool empty = h->buckets[i] == NULL;
        HASH_BUCKET_UNLOCK(h, i);
        if (!empty)
            return false;
    }
    return true;
}
