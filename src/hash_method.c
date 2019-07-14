#include "hash_method.h"

typedef struct {
    void *params;
    int (*max_prefix_bits) (void *params);
    hash_context* (*hash_context_alloc) (void *params);
    void (*hash_context_rekey) (void *params, hash_context *ctx);
    int (*hash_context_next_result) (void *params, hash_context *ctx);
    void (*hash_context_get_prefix) (void *params, hash_context *ctx, int prefix_bits, unsigned char *prefix);
    void (*serialize_result) (void *params, hash_context *res, char **hash_serialized, char **preimage_serialized);
} hash_method_impl;

int hash_method_max_prefix_bits(hash_method *meth)
{
    return ((hash_method_impl*)meth)->max_prefix_bits(((hash_method_impl*)meth)->params);
}

hash_context* hash_context_alloc(hash_method *meth)
{
    return ((hash_method_impl*)meth)->hash_context_alloc(((hash_method_impl*)meth)->params);
}

void hash_context_rekey(hash_method *meth, hash_context *ctx)
{
    ((hash_method_impl*)meth)->hash_context_rekey(((hash_method_impl*)meth)->params, ctx);
}

int hash_context_next_result(hash_method *meth, hash_context *ctx)
{
    return ((hash_method_impl*)meth)->hash_context_next_result(((hash_method_impl*)meth)->params, ctx);
}

void hash_context_get_prefix(hash_method *meth, hash_context *ctx, int prefix_bits, unsigned char *prefix)
{
    ((hash_method_impl*)meth)->hash_context_get_prefix(((hash_method_impl*)meth)->params, ctx, prefix_bits, prefix);
}

void serialize_result(hash_method *meth, hash_context *res, char **hash_serialized, char **preimage_serialized)
{
    ((hash_method_impl*)meth)->serialize_result(((hash_method_impl*)meth)->params, res, hash_serialized, preimage_serialized);
}

#include "hash_method_p2pk.c"
#include "hash_method_p2pkh.c"
#include "hash_method_p2sh.c"
