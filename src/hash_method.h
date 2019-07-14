#ifndef __HASH_METHOD_H__
#define __HASH_METHOD_H__ 1

typedef void hash_context;

typedef struct {
    int max_prefix_bits;

    hash_context* (*hash_context_alloc) ();
    void (*hash_context_rekey) (hash_context *ctx);
    int (*hash_context_next_result) (hash_context *ctx);
    void (*hash_context_get_prefix) (hash_context *ctx, int prefix_bits, unsigned char *prefix);

    void (*serialize_result) (hash_context *res, char **hash_serialized, char **preimage_serialized);
} hash_method;

extern hash_method hash_method_p2pk;
extern hash_method hash_method_p2pkh;
//void hash_method_p2sh_init(hash_method *method);

#endif
