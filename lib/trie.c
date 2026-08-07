#include "trie.h"

#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

static trie_node* create_trie_node(trie_node* parent)
{
	trie_node* node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;
	node->parent = parent;
	node->depth = parent->depth + 1;
	return node;
}

static void clear_empty_branch(trie_node* node)
{
	while (node && node->parent && !node->left_node &&
		   !node->right_node && !node->exist_element) {
		trie_node* parent = node->parent;
		if (parent->left_node == node)
			parent->left_node = NULL;
		else
			parent->right_node = NULL;
		free(node);
		node = parent;
	}
}

static uint32_t trie_max_depth(const trie* trie)
{
	return trie->type == TRIE_IPV4 ? 32u : 128u;
}

static trie_node* find_trie_node_common(trie* trie, uint64_t net,
										uint32_t mask, bool create,
										bool search_prefix)
{
	trie_node* cur = &trie->root;
	uint32_t net_host = ntohl((uint32_t)net);
	const uint8_t* net6 = (const uint8_t*)(uintptr_t)net;
	if (trie->type == TRIE_IPV6 && !net6)
		return NULL;

	trie_node* last_exist_node = cur->exist_element ? cur : NULL;
	for (uint32_t bit_idx = 0; bit_idx < mask; ++bit_idx) {
		bool bit;
		if (trie->type == TRIE_IPV6) {
			bit = (net6[bit_idx / 8u] >> (7u - (bit_idx % 8u))) & 0x01u;
		} else {
			uint32_t shift = 31u - bit_idx;
			bit = (net_host >> shift) & 0x01u;
		}

		trie_node** next = bit ? &cur->right_node : &cur->left_node;
		if (!*next && create)
			*next = create_trie_node(cur);
		if (!*next)
			return search_prefix ? last_exist_node : NULL;
		cur = *next;
		if (cur->exist_element)
			last_exist_node = cur;
	}
	return cur;
}

int add_trie_element(trie* trie, uint64_t net, uint32_t mask, uint64_t info)
{
	if (mask > trie_max_depth(trie)) {
		ERR_LOG("add trie: mask %u is too long", mask);
		return -1;
	}
	TRIE_WRLOCK(trie);
	trie_node* find = find_trie_node_common(trie, net, mask, true, false);
	int ret = find ? trie->cb_add(find, info) : -ENOMEM;
	TRIE_UNLOCK(trie);
	return ret;
}

int delete_trie_element(trie* trie, uint64_t net, uint32_t mask, uint64_t info)
{
	if (mask > trie_max_depth(trie)) {
		ERR_LOG("delete trie: mask %u is too long", mask);
		return -1;
	}
	TRIE_WRLOCK(trie);
	trie_node* find = find_trie_node_common(trie, net, mask, false, false);
	if (!find) {
		TRIE_UNLOCK(trie);
		WARN_LOG("delete_trie:no node");
		return 0;
	}
	int ret = trie->cb_delete(find, info);
	clear_empty_branch(find);
	TRIE_UNLOCK(trie);
	return ret;
}

uint64_t search_trie_element(trie* trie, uint64_t net, uint32_t mask,
									 bool prefix_search, void* argv)
{
	if (mask > trie_max_depth(trie)) {
		ERR_LOG("search trie: mask %u is too long", mask);
		return 0;
	}
	TRIE_RDLOCK(trie);
	trie_node* find = find_trie_node_common(trie, net, mask, false, prefix_search);
	uint64_t ret = 0;
	while (find) {
		if (find->exist_element)
			ret = trie->cb_search(find, argv);
		if (ret || !prefix_search)
			break;
		do {
			find = find->parent;
		} while (find && !find->exist_element);
	}
	TRIE_UNLOCK(trie);
	return ret;
}

static void trie_free_branch(trie_node* node,
                             void (*free_element)(uint64_t element))
{
    if (node->left_node)
        trie_free_branch(node->left_node, free_element);
    if (node->right_node)
        trie_free_branch(node->right_node, free_element);
    if (node->exist_element && free_element)
        free_element(node->element);
    free(node);
}

void trie_clear(trie* t, void (*free_element)(uint64_t element))
{
    TRIE_WRLOCK(t);
    if (t->root.left_node)
        trie_free_branch(t->root.left_node, free_element);
    if (t->root.right_node)
        trie_free_branch(t->root.right_node, free_element);
    if (t->root.exist_element && free_element)
        free_element(t->root.element);
    t->root.left_node = NULL;
    t->root.right_node = NULL;
    t->root.exist_element = false;
    t->root.element = 0;
    TRIE_UNLOCK(t);
}
