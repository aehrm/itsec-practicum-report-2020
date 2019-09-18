#ifndef __HASH_ENGINE_H__
#define __HASH_ENGINE_H__ 1

#include "rb_tree/rb_tree.h"

typedef struct {
    unsigned char *prefix;
    int prefix_bits;
    char *hash_str;
    char *preimage_str;
} result_element;

typedef struct {
    result_element *results;
    int results_num;
    struct rb_tree *rb_tree;
} hash_engine;

void hash_engine_init(hash_engine *engine, unsigned char *data, int data_bits, int prefix_bits);
void print_statusline(hash_engine *engine, double starttime, unsigned long progress, double last_print, unsigned long last_progress);
result_element* hash_engine_search(hash_engine *engine, unsigned char *prefix, int prefix_bits);

#endif

