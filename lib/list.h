#ifndef LIST_H
#define LIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct list_node {
	struct list_node* pre;
	struct list_node* next;
	uint64_t element;
} list_node;

#define FOR_EACH_LIST(head, element) \
		for (element = (head)->next; element != NULL; element = element->next)


#define FOR_EACH_LIST_SAFE(head, element, tmp) \
		for (element = (head)->next, tmp = (element ? element->next : NULL); \
			 element != NULL; \
			 element = tmp, tmp = (element ? element->next : NULL))


#define FOR_EACH_LIST_OFFSET(head, element, type, member) \
		for (list_node *__node = (head)->next; \
			 __node != NULL && (element = (type*)((uint8_t*)__node - offsetof(type, member))); \
			 __node = __node->next)


#define FOR_EACH_LIST_SAFE_OFFSET(head, element, tmp_node, type, member) \
	for (list_node *__node = (head)->next; \
		 __node != NULL && ((tmp_node = __node->next), \
			(element = (type*)((uint8_t*)__node - offsetof(type, member))), 1); \
		 __node = tmp_node)

#define LIST_ATTACHED(node) \
	((node)->pre)

list_node* create_list_node(uint64_t element);
void add_list_node(list_node* pre, list_node* add);
int add_list_node_compare(list_node* head, list_node* add,
                          int (*compare)(list_node*, list_node*));
void add_list_node_pre(list_node* last, list_node* add);
void remove_list_node(list_node* remove);
void destroy_list_node(list_node* destroy, void (*free_element)(uint64_t));
bool list_node_exist(list_node* head, list_node* node);
bool list_element_exist(list_node* head, uint64_t element);
void clear_list_head(list_node* head, void (*free_element)(uint64_t));

#endif
