#include "rb_tree.h"

/* Linux-kernel-style intrusive red-black tree implementation. */

static inline void rb_set_parent(struct rb_node *node, struct rb_node *parent)
{
    node->rb_parent_color = (node->rb_parent_color & 3) |
                            (unsigned long)parent;
}

static inline void rb_set_color(struct rb_node *node, int color)
{
    node->rb_parent_color = (node->rb_parent_color & ~1UL) | color;
}

static inline void rb_set_parent_color(struct rb_node *node,
                                       struct rb_node *parent, int color)
{
    node->rb_parent_color = (unsigned long)parent | color;
}

static void rb_rotate_left(struct rb_node *old, struct rb_root *root)
{
    struct rb_node *new = old->rb_right;
    struct rb_node *parent = rb_parent(old);

    old->rb_right = new->rb_left;
    if (new->rb_left)
        rb_set_parent(new->rb_left, old);
    new->rb_left = old;
    rb_set_parent(old, new);
    if (parent) {
        if (parent->rb_left == old) parent->rb_left = new;
        else parent->rb_right = new;
    } else root->rb_node = new;
    rb_set_parent(new, parent);
}

static void rb_rotate_right(struct rb_node *old, struct rb_root *root)
{
    struct rb_node *new = old->rb_left;
    struct rb_node *parent = rb_parent(old);

    old->rb_left = new->rb_right;
    if (new->rb_right)
        rb_set_parent(new->rb_right, old);
    new->rb_right = old;
    rb_set_parent(old, new);
    if (parent) {
        if (parent->rb_left == old) parent->rb_left = new;
        else parent->rb_right = new;
    } else root->rb_node = new;
    rb_set_parent(new, parent);
}

void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
    struct rb_node *parent, *gparent, *uncle;

    rb_set_color(node, RB_RED);
    while ((parent = rb_parent(node)) && rb_is_red(parent)) {
        gparent = rb_parent(parent);
        if (parent == gparent->rb_left) {
            uncle = gparent->rb_right;
            if (uncle && rb_is_red(uncle)) {
                rb_set_color(uncle, RB_BLACK);
                rb_set_color(parent, RB_BLACK);
                rb_set_color(gparent, RB_RED);
                node = gparent;
                continue;
            }
            if (parent->rb_right == node) {
                rb_rotate_left(parent, root);
                parent = rb_parent(node);
            }
            rb_set_color(parent, RB_BLACK);
            rb_set_color(gparent, RB_RED);
            rb_rotate_right(gparent, root);
        } else {
            uncle = gparent->rb_left;
            if (uncle && rb_is_red(uncle)) {
                rb_set_color(uncle, RB_BLACK);
                rb_set_color(parent, RB_BLACK);
                rb_set_color(gparent, RB_RED);
                node = gparent;
                continue;
            }
            if (parent->rb_left == node) {
                rb_rotate_right(parent, root);
                parent = rb_parent(node);
            }
            rb_set_color(parent, RB_BLACK);
            rb_set_color(gparent, RB_RED);
            rb_rotate_left(gparent, root);
        }
    }
    if (root->rb_node) rb_set_color(root->rb_node, RB_BLACK);
}

static inline int rb_node_color(const struct rb_node *node)
{
    return node ? rb_color(node) : RB_BLACK;
}

static void rb_erase_color(struct rb_node *node, struct rb_node *parent,
                           struct rb_root *root)
{
    struct rb_node *sibling;

    while ((!node || rb_node_color(node) == RB_BLACK) &&
           node != root->rb_node) {
        if (!parent) break;
        if (node == parent->rb_left) {
            sibling = parent->rb_right;
            if (rb_node_color(sibling) == RB_RED) {
                rb_set_color(sibling, RB_BLACK);
                rb_set_color(parent, RB_RED);
                rb_rotate_left(parent, root);
                sibling = parent->rb_right;
            }
            if (!sibling || (rb_node_color(sibling->rb_left) == RB_BLACK &&
                             rb_node_color(sibling->rb_right) == RB_BLACK)) {
                if (sibling) rb_set_color(sibling, RB_RED);
                node = parent;
                parent = rb_parent(node);
            } else {
                if (rb_node_color(sibling->rb_right) == RB_BLACK) {
                    if (sibling->rb_left) rb_set_color(sibling->rb_left, RB_BLACK);
                    rb_set_color(sibling, RB_RED);
                    rb_rotate_right(sibling, root);
                    sibling = parent->rb_right;
                }
                rb_set_color(sibling, rb_color(parent));
                rb_set_color(parent, RB_BLACK);
                if (sibling->rb_right) rb_set_color(sibling->rb_right, RB_BLACK);
                rb_rotate_left(parent, root);
                node = root->rb_node;
                parent = NULL;
            }
        } else {
            sibling = parent->rb_left;
            if (rb_node_color(sibling) == RB_RED) {
                rb_set_color(sibling, RB_BLACK);
                rb_set_color(parent, RB_RED);
                rb_rotate_right(parent, root);
                sibling = parent->rb_left;
            }
            if (!sibling || (rb_node_color(sibling->rb_left) == RB_BLACK &&
                             rb_node_color(sibling->rb_right) == RB_BLACK)) {
                if (sibling) rb_set_color(sibling, RB_RED);
                node = parent;
                parent = rb_parent(node);
            } else {
                if (rb_node_color(sibling->rb_left) == RB_BLACK) {
                    if (sibling->rb_right) rb_set_color(sibling->rb_right, RB_BLACK);
                    rb_set_color(sibling, RB_RED);
                    rb_rotate_left(sibling, root);
                    sibling = parent->rb_left;
                }
                rb_set_color(sibling, rb_color(parent));
                rb_set_color(parent, RB_BLACK);
                if (sibling->rb_left) rb_set_color(sibling->rb_left, RB_BLACK);
                rb_rotate_right(parent, root);
                node = root->rb_node;
                parent = NULL;
            }
        }
    }
    if (node) rb_set_color(node, RB_BLACK);
}

void rb_erase(struct rb_node *victim, struct rb_root *root)
{
    struct rb_node *child, *parent, *successor;
    int color;

    if (!victim->rb_left) {
        child = victim->rb_right;
        parent = rb_parent(victim);
        color = rb_color(victim);
        if (child) rb_set_parent(child, parent);
    } else if (!victim->rb_right) {
        child = victim->rb_left;
        parent = rb_parent(victim);
        color = rb_color(victim);
        if (child) rb_set_parent(child, parent);
    } else {
        struct rb_node *old = victim;
        successor = victim->rb_right;
        while (successor->rb_left) successor = successor->rb_left;
        child = successor->rb_right;
        parent = rb_parent(successor);
        color = rb_color(successor);
        if (parent == old) {
            parent = successor;
            if (child) rb_set_parent(child, successor);
        } else {
            if (child) rb_set_parent(child, parent);
            parent->rb_left = child;
            successor->rb_right = old->rb_right;
            rb_set_parent(old->rb_right, successor);
        }
        successor->rb_left = old->rb_left;
        rb_set_parent(old->rb_left, successor);
        rb_set_parent_color(successor, rb_parent(old), rb_color(old));
        if (rb_parent(old)) {
            if (rb_parent(old)->rb_left == old) rb_parent(old)->rb_left = successor;
            else rb_parent(old)->rb_right = successor;
        } else root->rb_node = successor;
        if (color == RB_BLACK) rb_erase_color(child, parent, root);
        return;
    }
    if (parent) {
        if (parent->rb_left == victim) parent->rb_left = child;
        else parent->rb_right = child;
    } else root->rb_node = child;
    if (color == RB_BLACK) rb_erase_color(child, parent, root);
}

void rb_replace_node(struct rb_node *victim, struct rb_node *new_node,
                     struct rb_root *root)
{
    struct rb_node *parent = rb_parent(victim);
    new_node->rb_parent_color = victim->rb_parent_color;
    new_node->rb_left = victim->rb_left;
    new_node->rb_right = victim->rb_right;
    if (new_node->rb_left) rb_set_parent(new_node->rb_left, new_node);
    if (new_node->rb_right) rb_set_parent(new_node->rb_right, new_node);
    if (parent) {
        if (parent->rb_left == victim) parent->rb_left = new_node;
        else parent->rb_right = new_node;
    } else root->rb_node = new_node;
}

struct rb_node *rb_first(const struct rb_root *root)
{
    struct rb_node *node = root->rb_node;
    if (!node) return NULL;
    while (node->rb_left) node = node->rb_left;
    return node;
}

struct rb_node *rb_last(const struct rb_root *root)
{
    struct rb_node *node = root->rb_node;
    if (!node) return NULL;
    while (node->rb_right) node = node->rb_right;
    return node;
}

struct rb_node *rb_next(const struct rb_node *node)
{
    struct rb_node *parent;
    if (node->rb_right) {
        node = node->rb_right;
        while (node->rb_left) node = node->rb_left;
        return (struct rb_node *)node;
    }
    while ((parent = rb_parent(node)) && node == parent->rb_right) node = parent;
    return parent;
}

struct rb_node *rb_prev(const struct rb_node *node)
{
    struct rb_node *parent;
    if (node->rb_left) {
        node = node->rb_left;
        while (node->rb_right) node = node->rb_right;
        return (struct rb_node *)node;
    }
    while ((parent = rb_parent(node)) && node == parent->rb_left) node = parent;
    return parent;
}
