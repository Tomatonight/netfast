#include "rb_tree.h"

/* 设置父节点 + 颜色 */
static inline void rb_set_parent_color(struct rb_node *rb,
                                       struct rb_node *p, int color)
{
    rb->rb_parent_color = (unsigned long)p | color;
}

static inline void rb_set_black(struct rb_node *rb)
{
    rb->rb_parent_color |= RB_BLACK;
}

static inline struct rb_node *rb_red_parent(struct rb_node *red)
{
    return (struct rb_node *)red->rb_parent_color;
}

/* 左旋 */
static void rb_rotate_left(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *right = node->rb_right;
    struct rb_node *parent = rb_parent(node);

    if ((node->rb_right = right->rb_left))
        rb_set_parent_color(right->rb_left, node, rb_color(right->rb_left));
    right->rb_left = node;

    rb_set_parent_color(right, parent, rb_color(node));

    if (parent) {
        if (parent->rb_left == node)
            parent->rb_left = right;
        else
            parent->rb_right = right;
    } else
        root->rb_node = right;

    rb_set_parent_color(node, right, RB_RED);
}

/* 右旋 */
static void rb_rotate_right(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *left = node->rb_left;
    struct rb_node *parent = rb_parent(node);

    if ((node->rb_left = left->rb_right))
        rb_set_parent_color(left->rb_right, node, rb_color(left->rb_right));
    left->rb_right = node;

    rb_set_parent_color(left, parent, rb_color(node));

    if (parent) {
        if (parent->rb_left == node)
            parent->rb_left = left;
        else
            parent->rb_right = left;
    } else
        root->rb_node = left;

    rb_set_parent_color(node, left, RB_RED);
}

/* 插入后平衡修复 */
void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *parent, *gparent;

    while ((parent = rb_red_parent(node)) && rb_is_red(parent)) {
        gparent = rb_red_parent(parent);

        if (parent == gparent->rb_left) {
            struct rb_node *uncle = gparent->rb_right;
            if (uncle && rb_is_red(uncle)) {
                rb_set_black(uncle);
                rb_set_black(parent);
                rb_set_parent_color(gparent, rb_parent(gparent), RB_RED);
                node = gparent;
                continue;
            }

            if (parent->rb_right == node) {
                struct rb_node *tmp;
                rb_rotate_left(parent, root);
                tmp = parent;
                parent = node;
                node = tmp;
            }

            rb_set_black(parent);
            rb_set_parent_color(gparent, rb_parent(gparent), RB_RED);
            rb_rotate_right(gparent, root);
        } else {
            struct rb_node *uncle = gparent->rb_left;
            if (uncle && rb_is_red(uncle)) {
                rb_set_black(uncle);
                rb_set_black(parent);
                rb_set_parent_color(gparent, rb_parent(gparent), RB_RED);
                node = gparent;
                continue;
            }

            if (parent->rb_left == node) {
                struct rb_node *tmp;
                rb_rotate_right(parent, root);
                tmp = parent;
                parent = node;
                node = tmp;
            }

            rb_set_black(parent);
            rb_set_parent_color(gparent, rb_parent(gparent), RB_RED);
            rb_rotate_left(gparent, root);
        }
    }

    rb_set_black(root->rb_node);
}

/* 删除后平衡修复 */
static void rb_erase_color(struct rb_node *node, struct rb_node *parent,
                             struct rb_root *root)
{
    struct rb_node *other;

    while ((!node || rb_is_black(node)) && node != root->rb_node) {
        if (parent->rb_left == node) {
            other = parent->rb_right;
            if (rb_is_red(other)) {
                rb_set_black(other);
                rb_set_parent_color(parent, rb_parent(parent), RB_RED);
                rb_rotate_left(parent, root);
                other = parent->rb_right;
            }
            if ((!other->rb_left || rb_is_black(other->rb_left)) &&
                (!other->rb_right || rb_is_black(other->rb_right))) {
                rb_set_parent_color(other, parent, RB_RED);
                node = parent;
                parent = rb_parent(node);
                continue;
            }
            if (!other->rb_right || rb_is_black(other->rb_right)) {
                rb_set_black(other->rb_left);
                rb_set_parent_color(other, parent, RB_RED);
                rb_rotate_right(other, root);
                other = parent->rb_right;
            }
            rb_set_parent_color(other, parent, rb_color(parent));
            rb_set_black(parent);
            rb_set_black(other->rb_right);
            rb_rotate_left(parent, root);
            node = root->rb_node;
            break;
        } else {
            other = parent->rb_left;
            if (rb_is_red(other)) {
                rb_set_black(other);
                rb_set_parent_color(parent, rb_parent(parent), RB_RED);
                rb_rotate_right(parent, root);
                other = parent->rb_left;
            }
            if ((!other->rb_left || rb_is_black(other->rb_left)) &&
                (!other->rb_right || rb_is_black(other->rb_right))) {
                rb_set_parent_color(other, parent, RB_RED);
                node = parent;
                parent = rb_parent(node);
                continue;
            }
            if (!other->rb_left || rb_is_black(other->rb_left)) {
                rb_set_black(other->rb_right);
                rb_set_parent_color(other, parent, RB_RED);
                rb_rotate_left(other, root);
                other = parent->rb_left;
            }
            rb_set_parent_color(other, parent, rb_color(parent));
            rb_set_black(parent);
            rb_set_black(other->rb_left);
            rb_rotate_right(parent, root);
            node = root->rb_node;
            break;
        }
    }
    if (node)
        rb_set_black(node);
}

/* 删除节点 */
void rb_erase(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *child, *parent;
    int color;

    if (!node->rb_left)
        child = node->rb_right;
    else if (!node->rb_right)
        child = node->rb_left;
    else {
        struct rb_node *old = node;
        struct rb_node *left;

        node = node->rb_right;
        while ((left = node->rb_left) != NULL)
            node = left;

        if (rb_parent(old)) {
            if (rb_parent(old)->rb_left == old)
                rb_parent(old)->rb_left = node;
            else
                rb_parent(old)->rb_right = node;
        } else
            root->rb_node = node;

        child = node->rb_right;
        parent = rb_parent(node);
        color = rb_color(node);

        if (parent == old) {
            parent = node;
        } else {
            if (child)
                rb_set_parent_color(child, parent, RB_BLACK);
            parent->rb_left = child;

            node->rb_right = old->rb_right;
            rb_set_parent_color(old->rb_right, node, rb_color(old->rb_right));
        }

        node->rb_parent_color = old->rb_parent_color;
        node->rb_left = old->rb_left;
        rb_set_parent_color(old->rb_left, node, rb_color(old->rb_left));

        goto color;
    }

    parent = rb_parent(node);
    color = rb_color(node);

    if (child)
        rb_set_parent_color(child, parent, RB_BLACK);

    if (parent) {
        if (parent->rb_left == node)
            parent->rb_left = child;
        else
            parent->rb_right = child;
    } else
        root->rb_node = child;

color:
    if (color == RB_BLACK)
        rb_erase_color(child, parent, root);
}

/* 替换节点 */
void rb_replace_node(struct rb_node *victim, struct rb_node *new_node,
                     struct rb_root *root)
{
    struct rb_node *parent = rb_parent(victim);

    new_node->rb_parent_color = victim->rb_parent_color;

    if (parent) {
        if (parent->rb_left == victim)
            parent->rb_left = new_node;
        else
            parent->rb_right = new_node;
    } else
        root->rb_node = new_node;

    if (victim->rb_left)
        rb_set_parent_color(victim->rb_left, new_node, rb_color(victim->rb_left));
    if (victim->rb_right)
        rb_set_parent_color(victim->rb_right, new_node, rb_color(victim->rb_right));
}

/* 最左节点（最小值） */
struct rb_node *rb_first(const struct rb_root *root)
{
    struct rb_node *n = root->rb_node;
    if (!n) return NULL;
    while (n->rb_left)
        n = n->rb_left;
    return n;
}

/* 最右节点（最大值） */
struct rb_node *rb_last(const struct rb_root *root)
{
    struct rb_node *n = root->rb_node;
    if (!n) return NULL;
    while (n->rb_right)
        n = n->rb_right;
    return n;
}

/* 后继节点 */
struct rb_node *rb_next(const struct rb_node *node)
{
    struct rb_node *parent;

    if (rb_parent(node) == node)
        return NULL;

    if (node->rb_right) {
        node = node->rb_right;
        while (node->rb_left)
            node = node->rb_left;
        return (struct rb_node *)node;
    }

    while ((parent = rb_parent(node)) && node == parent->rb_right)
        node = parent;

    return parent;
}

/* 前驱节点 */
struct rb_node *rb_prev(const struct rb_node *node)
{
    struct rb_node *parent;

    if (rb_parent(node) == node)
        return NULL;

    if (node->rb_left) {
        node = node->rb_left;
        while (node->rb_right)
            node = node->rb_right;
        return (struct rb_node *)node;
    }

    while ((parent = rb_parent(node)) && node == parent->rb_left)
        node = parent;

    return parent;
}
