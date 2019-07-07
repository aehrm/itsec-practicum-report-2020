#ifndef __HASH_RESULT_H__
#define __HASH_RESULT_H__ 1

#include "rb_tree.h"

struct result_container;

struct hash_result {
    unsigned char *prefix;
    unsigned char prefix_len;
    unsigned char *hash;
    unsigned char *preimage;

    result_container *container;
};

struct result_container {
    hash_result **results;
    int results_num;
    int prefix_len;
    int hash_len;
    int preimage_len;
    unsigned char* (*get_prefix) (unsigned char *hash);
};

struct result_tree {
    struct rb_tree *rb_tree;
    result_container *container;
};

void container_init(result_container *container, unsigned char *data, int data_len);
result_tree* container_create_trees(result_container *container, int n);
int container_tree_remaining(result_tree *tree);
hash_result* container_tree_test_hash(result_tree *tree, unsigned char *hash, unsigned char *preimage);

#endif
