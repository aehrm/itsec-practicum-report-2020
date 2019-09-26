#include "hash_method.h"

typedef struct {
    void *params;
    int (*max_prefix_bits) (void *params);
    int (*batch_size) (void *params);
    hash_context* (*hash_context_alloc) (void *params);
    void (*hash_context_rekey) (void *params, hash_context *ctx);
    int (*hash_context_next_result) (void *params, hash_context *ctx);
    void (*hash_context_get_prefixes) (void *params, hash_context *ctx, int prefix_bits, unsigned char **prefixes);
    void (*serialize_result) (void *params, hash_context *res, int index, char **hash_serialized, char **preimage_serialized);
} hash_method_impl;

int hash_method_max_prefix_bits(hash_method *meth)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    return meth_impl->max_prefix_bits(meth_impl->params);
}

int hash_method_batch_size(hash_method *meth)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    return meth_impl->batch_size(meth_impl->params);
}

hash_context* hash_context_alloc(hash_method *meth)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    return meth_impl->hash_context_alloc(meth_impl->params);
}

void hash_context_rekey(hash_method *meth, hash_context *ctx)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    meth_impl->hash_context_rekey(meth_impl->params, ctx);
}

int hash_context_next_result(hash_method *meth, hash_context *ctx)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    return meth_impl->hash_context_next_result(meth_impl->params, ctx);
}

void hash_context_get_prefixes(hash_method *meth, hash_context *ctx, int prefix_bits, unsigned char **prefixes)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    meth_impl->hash_context_get_prefixes(meth_impl->params, ctx, prefix_bits, prefixes);
}

void serialize_result(hash_method *meth, hash_context *res, int index, char **hash_serialized, char **preimage_serialized)
{
    hash_method_impl *meth_impl = (hash_method_impl*) meth;
    meth_impl->serialize_result(meth_impl->params, res, index, hash_serialized, preimage_serialized);
}

#include "hash_method_p2pk.c"
#include "hash_method_p2pkh.c"
#include "hash_method_p2sh.c"
