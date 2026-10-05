#ifndef RBTREE_H
#define RBTREE_H

#include <stddef.h>

/* 红黑颜色 */
#define RB_RED   0
#define RB_BLACK 1

/* 侵入式节点：嵌入到你的业务结构体中 */
struct rb_node {
    unsigned long  rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
};

/* 树根 */
struct rb_root {
    struct rb_node *rb_node;
};

#define RB_ROOT (struct rb_root){ NULL }

/* 核心宏：从成员指针反查结构体首指针（侵入式核心） */
#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) ); })

#define rb_entry(ptr, type, member) container_of(ptr, type, member)

/* 内部辅助：获取父节点、颜色 */
#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r)    ((r)->rb_parent_color & 1)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) rb_color(r)

/* 初始化节点 */
static inline void rb_init_node(struct rb_node *rb)
{
    rb->rb_parent_color = 0;
    rb->rb_right = NULL;
    rb->rb_left = NULL;
}

/* 判空 */
static inline int RB_EMPTY_NODE(const struct rb_node *node)
{
    return node->rb_parent_color == 0;
}

static inline int RB_EMPTY_ROOT(const struct rb_root *root)
{
    return root->rb_node == NULL;
}

/* 遍历：最左/最右/前驱/后继 */
struct rb_node *rb_first(const struct rb_root *root);
struct rb_node *rb_last(const struct rb_root *root);
/* node must be non-NULL; reaching the end of traversal returns NULL. */
struct rb_node *rb_next(const struct rb_node *node);
struct rb_node *rb_prev(const struct rb_node *node);

/* 核心操作 */
void rb_insert_color(struct rb_node *node, struct rb_root *root);
void rb_erase(struct rb_node *node, struct rb_root *root);
void rb_replace_node(struct rb_node *victim, struct rb_node *new,
                     struct rb_root *root);

/* 插入节点（仅挂到树上，不做平衡；随后必须调用 rb_insert_color） */
static inline void rb_link_node(struct rb_node *node,
                                struct rb_node *parent,
                                struct rb_node **rb_link)
{
    node->rb_parent_color = (unsigned long)parent;
    node->rb_left = node->rb_right = NULL;
    *rb_link = node;
}

/* 遍历宏：顺序遍历整棵树 */
#define rb_for_each_entry(pos, root, member)                    \
    for (pos = rb_entry(rb_first(root), typeof(*pos), member);  \
         &pos->member != NULL;                                  \
         pos = rb_entry(rb_next(&pos->member), typeof(*pos), member))

#endif /* RBTREE_H */
