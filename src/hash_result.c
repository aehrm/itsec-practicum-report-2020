#include <string.h>
#include "hash_result.h"

int hash_result_rb_cmp(rb_tree *tree, rb_node *node_a, rb_node *node_b) {
    unsigned char *prefix_a = ((hash_result*) node_a->value)->prefix;
    unsigned char *prefix_b = ((hash_result*) node_b->value)->prefix;
    result_container *container = ((hash_result*) node_a->value)->container;

    for (int i = 0; i < container->prefix_len; i++) {
        int ret = (prefix_a[i] > prefix_b[i]) - (prefix_a[i] < prefix_b[i]);
        if (ret != 0) return ret;
    }

    return 0;
}


void container_init(result_container *container, unsigned char *data, int data_len)
{
    container->results_num = data_len / container->prefix_len;
    hash_result **results = (hash_result**) malloc(container->results_num * sizeof(hash_result*));
    container->results = results;

    for (int i = 0; i < container->results_num; i++) {
        hash_result *obj = (hash_result*) malloc(sizeof *obj);
        obj->prefix = data + i*(container->prefix_len);
        obj->hash = NULL;
        obj->preimage = NULL;
        obj->container = container;
        results[i] = obj;
    }
}

hash_result* container_tree_test_hash(result_tree *tree, unsigned char *hash, unsigned char *preimage)
{
    unsigned char* prefix = tree->container->get_prefix(hash);
    hash_result search_obj = { .prefix = prefix, .container = tree->container };

    // find matching node
    hash_result *node = (hash_result*) rb_tree_find(tree->rb_tree, &search_obj);

    if (node == NULL) {
        return NULL;
    }

    rb_tree_remove(tree->rb_tree, node);
    node->hash = (unsigned char*) malloc(tree->container->hash_len * sizeof(unsigned char));
    memcpy(node->hash, hash, tree->container->hash_len);
    node->preimage = (unsigned char*) malloc(tree->container->preimage_len * sizeof(unsigned char));
    memcpy(node->preimage, preimage, tree->container->preimage_len);

    return node;
}

int container_tree_remaining(result_tree *tree)
{
    return rb_tree_size(tree->rb_tree);
}

result_tree* container_create_trees(result_container *container, int n)
{
    result_tree* trees = (result_tree*) malloc(n * sizeof(result_tree));
    int split_index = 0;
    for (int i = 0; i < n; i++) {
        rb_tree* tree = rb_tree_create(&hash_result_rb_cmp);
        int portion_num = (container->results_num - split_index) / (n - i);

        for (int j = split_index; j < split_index + portion_num; j++) {
            rb_tree_insert(tree, container->results[j]);
        }

        trees[i] = { .rb_tree = tree, .container = container };

        split_index += portion_num;
    }

    return trees;
}
