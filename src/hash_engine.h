#ifndef __HASH_ENGINE_H__
#define __HASH_ENGINE_H__ 1

#include "rb_tree/rb_tree.h"
#include "hash_method.h"

typedef struct {
    unsigned char *prefix;
    int prefix_bits;
    char *hash_str;
    char *preimage_str;
} result_element;

typedef struct {
    hash_method *method;
    result_element *results;
    int results_num;
    struct rb_tree *rb_tree;
} hash_engine;

void hash_engine_init(hash_engine *engine, hash_method *method, unsigned char *data, int data_bits, int prefix_bits);
int hash_engine_run(hash_engine *engine);

#endif

