#ifndef HASH_H
#define HASH_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "list.h"
#include "base.h"

#define MIN_HASH_SIZE 256u
#define DEFAULT_HASH_KEY_SIZE 64u

typedef struct hash {
	list_node** hash_lists;
	uint32_t size;
	spin_rwlock_t* bucket_locks;
} hash;

typedef struct hash_data {
	list_node node;
	uint8_t key[DEFAULT_HASH_KEY_SIZE];
	uint32_t key_len;
	uint64_t element;
} hash_data;


#define HASH_ELEMENT_WALK(hash_arg,func) \
	do { \
		hash* __hash = (hash_arg); \
		if (!__hash) break; \
		for(uint32_t i=0;i<__hash->size;i++){ \
			HASH_BUCKET_RDLOCK(__hash, i); \
			hash_data* __data; \
			list_node* __tmp; \
			FOR_EACH_LIST_SAFE_OFFSET(__hash->hash_lists[i], __data, __tmp, hash_data, node){ \
				func(__data->element); \
			} \
			HASH_BUCKET_UNLOCK(__hash, i); \
		} \
	} while(0)

hash* hash_create(uint32_t size);
hash* hash_create_safe(uint32_t size);

void hash_destroy(hash* h);
void hash_update(hash* h, const uint8_t* key, uint32_t key_len, uint64_t element);
uint64_t hash_del(hash* h, const uint8_t* key, uint32_t key_len);
bool hash_element_exist(hash* h, const uint8_t* key, uint32_t key_len);
uint64_t hash_get_element(hash* h, const uint8_t* key, uint32_t key_len);
uint64_t hash_get_element_ref(hash* h, const uint8_t* key, uint32_t key_len,
                              uint32_t ref_offset);
uint32_t general_hash_algorithm(const uint8_t* data, uint32_t len);
bool hash_add(hash* h, const uint8_t* key, uint32_t key_len, uint64_t element);
bool hash_is_empty(hash* h);
int hash_operate_element(hash* h, const uint8_t* key, uint32_t key_len,
                         int (*operate)(uint64_t* element, void* ctx), void* ctx);

/* bucket-level locks helpers */
#define HASH_HAS_BUCKET_LOCK(h) ((h)->bucket_locks != NULL)
#define HASH_BUCKET_RDLOCK(h, idx) do { if (HASH_HAS_BUCKET_LOCK(h)) spin_rwlock_rdlock(&(h)->bucket_locks[(idx)]); } while (0)
#define HASH_BUCKET_WRLOCK(h, idx) do { if (HASH_HAS_BUCKET_LOCK(h)) spin_rwlock_wrlock(&(h)->bucket_locks[(idx)]); } while (0)
#define HASH_BUCKET_UNLOCK(h, idx) do { if (HASH_HAS_BUCKET_LOCK(h)) spin_rwlock_unlock(&(h)->bucket_locks[(idx)]); } while (0)

#endif
