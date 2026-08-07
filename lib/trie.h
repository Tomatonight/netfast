#ifndef TRIE_H
#define TRIE_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

enum trie_type {
	TRIE_IPV4,
	TRIE_IPV6,
};

typedef struct trie_node {
	struct trie_node* left_node;
	struct trie_node* right_node;
	struct trie_node* parent;
	bool exist_element;
	uint64_t element;
	uint32_t depth;
} trie_node;

typedef struct trie {
	enum trie_type type;
	trie_node root;
	int (*cb_add)(trie_node*, uint64_t);
	int (*cb_delete)(trie_node*, uint64_t);
	uint64_t (*cb_search)(trie_node*, void* argv);
	bool use_rwlock;
	pthread_rwlock_t rwlock;
} trie;

#define TRIE_INIT_RWLOCK(t, enable) do { \
	(t)->use_rwlock = (enable); \
	if ((t)->use_rwlock) pthread_rwlock_init(&(t)->rwlock, NULL); \
} while(0)

#define TRIE_DESTROY_RWLOCK(t) do { \
	if ((t)->use_rwlock) pthread_rwlock_destroy(&(t)->rwlock); \
} while(0)

#define TRIE_RDLOCK(t) do { \
	if ((t)->use_rwlock) pthread_rwlock_rdlock(&(t)->rwlock); \
} while(0)

#define TRIE_WRLOCK(t) do { \
	if ((t)->use_rwlock) pthread_rwlock_wrlock(&(t)->rwlock); \
} while(0)

#define TRIE_UNLOCK(t) do { \
	if ((t)->use_rwlock) pthread_rwlock_unlock(&(t)->rwlock); \
} while(0)

#define DEFINE_TRIE(name, trie_type_value, add_cb, del_cb, search_cb, rw_lock) \
	trie name = { \
		.type = (trie_type_value), \
		.cb_add = (add_cb), \
		.cb_delete = (del_cb), \
		.cb_search = (search_cb), \
		.use_rwlock = (rw_lock), \
		.rwlock = PTHREAD_RWLOCK_INITIALIZER, \
	}

/* IPv4 keys are passed by value in the low 32 bits. IPv6 keys are pointers
 * to 16 network-order bytes carried through uintptr_t. */
int add_trie_element(trie* trie, uint64_t net, uint32_t mask, uint64_t element);
int delete_trie_element(trie* trie, uint64_t net, uint32_t mask, uint64_t element);
uint64_t search_trie_element(trie* trie, uint64_t net, uint32_t mask,
                             bool prefix_search, void* argv);

/* clear all nodes and elements */
void trie_clear(trie* t, void (*free_element)(uint64_t element));

#endif

