#ifndef __HASH_ENGINE_H__
#define __HASH_ENGINE_H__ 1

#define TESTBIT(A,k)    ( A[((k)/8)] &  (1 <<  (7-(k)%8)) )
#define SETBIT(A,k)     ( A[((k)/8)] |= (1 <<  (7-(k)%8)) )
#define CLEARBIT(A,k)   ( A[((k)/8)] &= ~(1 << (7-(k)%8)) )


#include "rb_tree/rb_tree.h"

typedef struct {
    unsigned char *prefix;
    int prefix_bits;
    unsigned char *hash;
    int hash_len;
    unsigned char *preimage;
    int preimage_len;
} result_element;

typedef struct {
    result_element *results;
    int results_num;
    struct rb_tree *rb_tree;
} hash_engine;

void hash_engine_init(hash_engine *engine, unsigned char *data, int data_bits, int prefix_bits);
void print_statusline(hash_engine *engine, unsigned long progress, double rate);
result_element* hash_engine_search(hash_engine *engine, unsigned char *prefix, int prefix_bits);

#endif

