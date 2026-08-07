#include "hash.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

hash* hash_create(uint32_t size)
{
	hash* new_hash = calloc(1, sizeof(*new_hash));
	if (!new_hash)
		return NULL;

	size = size > MIN_HASH_SIZE ? size : MIN_HASH_SIZE;
	new_hash->hash_lists = calloc(size, sizeof(list_node*));
	if (!new_hash->hash_lists) {
		free(new_hash);
		return NULL;
	}
	new_hash->size = size;

	for (uint32_t i = 0; i < size; i++) {
		new_hash->hash_lists[i] = create_list_node(0);
		if (!new_hash->hash_lists[i]) {
			hash_destroy(new_hash);
			return NULL;
		}
	}
	return new_hash;
}

hash* hash_create_safe(uint32_t size)
{
    hash* h = hash_create(size);
    if (!h)
        return NULL;

    h->bucket_locks = calloc(h->size, sizeof(spin_rwlock_t));
    if (!h->bucket_locks) {
        hash_destroy(h);
        return NULL;
    }

    for (uint32_t i = 0; i < h->size; i++) {
        spin_rwlock_init(&h->bucket_locks[i]);
    }
    return h;
}

static void free_hash_data(uint64_t element)
{
    list_node* node = (list_node*)(uintptr_t)element;
    hash_data* data = (hash_data*)((uint8_t*)node - offsetof(hash_data, node));
    free(data);
}

void hash_destroy(hash* h)
{
    free(h->bucket_locks);
    h->bucket_locks = NULL;

    for (uint32_t i = 0; i < h->size; i++) {
        if (h->hash_lists[i]) {
            clear_list_head(h->hash_lists[i], free_hash_data);
            destroy_list_node(h->hash_lists[i], NULL);
            h->hash_lists[i] = NULL;
        }
    }
    free(h->hash_lists);

    free(h);
}

static uint32_t hash_key_len(uint32_t key_len)
{
    return key_len > DEFAULT_HASH_KEY_SIZE ? DEFAULT_HASH_KEY_SIZE : key_len;
}

static hash_data* hash_bucket_find(hash* h, uint32_t index,
                                   const uint8_t* key, uint32_t key_len)
{
    hash_data* data;
    list_node* next;
    FOR_EACH_LIST_SAFE_OFFSET(h->hash_lists[index], data, next,
                              hash_data, node) {
        if (data->key_len == key_len && memcmp(data->key, key, key_len) == 0)
            return data;
    }
    return NULL;
}

static hash_data* hash_data_create(const uint8_t* key, uint32_t key_len,
                                   uint64_t element)
{
    hash_data* data = calloc(1, sizeof(*data));
    if (!data)
        return NULL;

    data->node.element = (uint64_t)(uintptr_t)&data->node;
    memcpy(data->key, key, key_len);
    data->key_len = key_len;
    data->element = element;
    return data;
}

bool hash_element_exist(hash* h, const uint8_t* key, uint32_t key_len)
{

    key_len = hash_key_len(key_len);
    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_RDLOCK(h, index);
    bool exists = hash_bucket_find(h, index, key, key_len) != NULL;
    HASH_BUCKET_UNLOCK(h, index);
    return exists;
}

void hash_update(hash* h, const uint8_t* key, uint32_t key_len, uint64_t element)
{

    key_len = hash_key_len(key_len);

    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_WRLOCK(h, index);

    hash_data* exist = hash_bucket_find(h, index, key, key_len);
    if (exist) {
        exist->element = element;
        HASH_BUCKET_UNLOCK(h, index);
        return;
    }

    hash_data* data = hash_data_create(key, key_len, element);
    if (!data) {
        HASH_BUCKET_UNLOCK(h, index);
        return;
    }

    add_list_node(h->hash_lists[index], &data->node);
    HASH_BUCKET_UNLOCK(h, index);
}

bool hash_add(hash* h, const uint8_t* key, uint32_t key_len, uint64_t element)
{

    key_len = hash_key_len(key_len);

    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_WRLOCK(h, index);

    if (hash_bucket_find(h, index, key, key_len)) {
        HASH_BUCKET_UNLOCK(h, index);
        return false;
    }

    hash_data* data = hash_data_create(key, key_len, element);
    if (!data) {
        HASH_BUCKET_UNLOCK(h, index);
        return false;
    }

    add_list_node(h->hash_lists[index], &data->node);
    HASH_BUCKET_UNLOCK(h, index);
    return true;
}

uint64_t hash_del(hash* h, const uint8_t* key, uint32_t key_len)
{

    key_len = hash_key_len(key_len);

    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_WRLOCK(h, index);

    hash_data* data = hash_bucket_find(h, index, key, key_len);
    if (!data) {
        HASH_BUCKET_UNLOCK(h, index);
        return 0;
    }

    uint64_t element = data->element;
    remove_list_node(&data->node);
    free(data);

    HASH_BUCKET_UNLOCK(h, index);
    return element;
}

uint64_t hash_get_element(hash* h, const uint8_t* key, uint32_t key_len)
{

    key_len = hash_key_len(key_len);

    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_RDLOCK(h, index);

    hash_data* data = hash_bucket_find(h, index, key, key_len);
    uint64_t v = data ? data->element : 0;

    HASH_BUCKET_UNLOCK(h, index);
    return v;
}
uint64_t hash_get_element_ref(hash* h, const uint8_t* key, uint32_t key_len,
                              uint32_t ref_offset)
{

    key_len = hash_key_len(key_len);

    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_RDLOCK(h, index);

    hash_data* data = hash_bucket_find(h, index, key, key_len);
    uint64_t v = data ? data->element : 0;
    if (v) {
        ref_info* ref = (ref_info*)((uint8_t*)(uintptr_t)v + ref_offset);
        ref_inc(ref);
    }
    HASH_BUCKET_UNLOCK(h, index);
    return v;
}
bool hash_is_empty(hash* h)
{

    for (uint32_t i = 0; i < h->size; i++) {
        HASH_BUCKET_RDLOCK(h, i);
        bool empty = h->hash_lists[i]->next == NULL;
        HASH_BUCKET_UNLOCK(h, i);
        if (!empty)
            return false;
    }

    return true;
}

uint32_t general_hash_algorithm(const uint8_t* data, uint32_t len)
{
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

int hash_operate_element(hash* h, const uint8_t* key, uint32_t key_len,
                         int (*operate)(uint64_t* element, void* ctx), void* ctx)
{
    key_len = hash_key_len(key_len);

    uint32_t index = general_hash_algorithm(key, key_len) % h->size;
    HASH_BUCKET_WRLOCK(h, index);

    hash_data* data = hash_bucket_find(h, index, key, key_len);
    if (!data) {
        HASH_BUCKET_UNLOCK(h, index);
        return 0;
    }

    int ret = operate(&data->element, ctx);

    HASH_BUCKET_UNLOCK(h, index);
    return ret;
}
