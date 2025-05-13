#ifndef INTERNAL_IO_SLIST_H
#define INTERNAL_IO_SLIST_H

#include <linux/io_uring_types.h>

#define __wq_list_for_each(pos, head)				\
	for (pos = (head)->first; pos; pos = (pos)->next)

#define wq_list_for_each(pos, prv, head)			\
	for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

#define wq_list_for_each_resume(pos, prv)			\
	for (; pos; prv = pos, pos = (pos)->next)

#define wq_list_empty(list)	(READ_ONCE((list)->first) == NULL)

#define INIT_WQ_LIST(list)	do {				\
	(list)->first = NULL;					\
} while (0)

/*
 The list is a singly linked list, so we need to keep track of the
 last element in the list. This is done by keeping a pointer to the
 last element in the list.
*/
static inline void wq_list_add_after(struct io_wq_work_node *node,
				     struct io_wq_work_node *pos,
				     struct io_wq_work_list *list)
{
	struct io_wq_work_node *next = pos->next;

	pos->next = node;
	node->next = next;
	if (!next)
		list->last = node;
}

/*
 Add a node to the end of the list. If the list is empty, set
 the first and last pointers to the new node.
*/
static inline void wq_list_add_tail(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = NULL;
	if (!list->first) {
		list->last = node;
		WRITE_ONCE(list->first, node);
	} else {
		list->last->next = node;
		list->last = node;
	}
}

/*
 Add a node to the head of the list. If the list is empty, set
 the first and last pointers to the new node.
*/
static inline void wq_list_add_head(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = list->first;
	if (!node->next)
		list->last = node;
	WRITE_ONCE(list->first, node);
}

/*
 This function wq_list_cut removes a range of nodes from a singly-linked list, starting from the node after prev up to and including last. 
 It updates the list's first and last pointers as necessary.
*/
static inline void wq_list_cut(struct io_wq_work_list *list,
			       struct io_wq_work_node *last,
			       struct io_wq_work_node *prev)
{
	/* first in the list, if prev==NULL */
	if (!prev)
		WRITE_ONCE(list->first, last->next);
	else
		prev->next = last->next;

	if (last == list->last)
		list->last = prev;
	last->next = NULL;
}

/*
 This function wq_list_splice takes a list and a node and splices the list into the node's next pointer. 
 It updates the list's first and last pointers as necessary.
*/
static inline void __wq_list_splice(struct io_wq_work_list *list,
				    struct io_wq_work_node *to)
{
	list->last->next = to->next;
	to->next = list->first;
	INIT_WQ_LIST(list);
}

/*
 This function wq_list_splice checks if the list is empty and if not, it calls __wq_list_splice to splice the list into the node's next pointer. 
 It returns true if the list was not empty, false otherwise.
*/
static inline bool wq_list_splice(struct io_wq_work_list *list,
				  struct io_wq_work_node *to)
{
	if (!wq_list_empty(list)) {
		__wq_list_splice(list, to);
		return true;
	}
	return false;
}

/*
 This function wq_stack_add_head adds a node to the head of a stack. 
 It updates the stack's next pointer to point to the new node.
*/
static inline void wq_stack_add_head(struct io_wq_work_node *node,
				     struct io_wq_work_node *stack)
{
	node->next = stack->next;
	stack->next = node;
}

/*
 This function wq_list_del removes a node from a singly-linked list. It takes the list, the node to be removed, and the previous node as arguments. 
 Instead of implementing the removal logic itself, it simply calls wq_list_cut (defined in io_uring/slist.h:wq_list_cut) to perform the actual removal.
*/
static inline void wq_list_del(struct io_wq_work_list *list,
			       struct io_wq_work_node *node,
			       struct io_wq_work_node *prev)
{
	wq_list_cut(list, node, prev);
}

/*
 This function extracts the top node from a stack and returns it. 
 It does this by updating the stack's next pointer to point to the node after the top node, effectively removing the top node from the stack.
*/
static inline
struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
{
	struct io_wq_work_node *node = stack->next;

	stack->next = node->next;
	return node;
}

/*
 This function wq_stack_empty checks if a stack is empty by checking if the next pointer of the stack is NULL.
*/
static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)
{
	if (!work->list.next)
		return NULL;

	return container_of(work->list.next, struct io_wq_work, list);
}

#endif // INTERNAL_IO_SLIST_H
