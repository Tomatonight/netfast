#include "list.h"

#include <stdlib.h>

list_node* create_list_node(uint64_t element)
{
	list_node* new_node = calloc(1, sizeof(*new_node));
	if (!new_node)
		return NULL;
	new_node->element = element;
	return new_node;
}

void add_list_node(list_node* pre, list_node* add)
{
	list_node* next = pre->next;
	add->pre = pre;
	add->next = next;
	pre->next = add;
	if (next)
		next->pre = add;
}

int add_list_node_compare(list_node* head, list_node* add,
						  int (*compare)(list_node*, list_node*))
{

	list_node* pre = head;
	list_node* curr = head->next;
	while (curr) {
		int ret = compare(curr, add);
		if (ret > 0) {
			add_list_node(pre, add);
			return 0;
		}
		if (ret < 0) {
			pre = curr;
			curr = curr->next;
			continue;
		}
		return -1;
	}
	add_list_node(pre, add);
	return 0;
}

void add_list_node_pre(list_node* last, list_node* add)
{
	list_node* pre = last->pre;
	add->pre = pre;
	add->next = last;
	last->pre = add;
	if (pre)
		pre->next = add;
}

void remove_list_node(list_node* remove)
{
	list_node* pre = remove->pre;
	list_node* next = remove->next;
	if (pre)
		pre->next = next;
	if (next)
		next->pre = pre;
	remove->pre = NULL;
	remove->next = NULL;
}

void destroy_list_node(list_node* destroy, void (*free_element)(uint64_t))
{

	if (free_element)
		free_element(destroy->element);
	free(destroy);
}

bool list_node_exist(list_node* head, list_node* node)
{
	list_node* tmp;
	FOR_EACH_LIST(head, tmp) {
		if (tmp == node)
			return true;
	}
	return false;
}

bool list_element_exist(list_node* head, uint64_t element)
{
	list_node* tmp;
	FOR_EACH_LIST(head, tmp) {
		if (tmp->element == element)
			return true;
	}
	return false;
}

void clear_list_head(list_node* head, void (*free_element)(uint64_t))
{
	list_node *element,*next;
	FOR_EACH_LIST_SAFE(head, element, next) {
		remove_list_node(element);
		destroy_list_node(element, free_element);
	}
	head->next = head->pre = NULL;
}
