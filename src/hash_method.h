#ifndef __HASH_METHOD_H__
#define __HASH_METHOD_H__ 1

#include "hash_engine.h"

typedef void hash_context;
typedef void hash_method;

hash_method* hash_method_p2pk();
hash_method* hash_method_p2pkh();
hash_method* hash_method_p2sh(unsigned char *pubkey, int pubkey_len);

int hash_method_batch_size(hash_method *meth);
int hash_method_max_prefix_bits(hash_method *meth);
hash_context* hash_context_alloc(hash_method *meth);
void hash_context_rekey(hash_method *meth, hash_context *ctx);
int hash_context_next_result(hash_method *meth, hash_context *ctx);
void hash_context_get_prefixes(hash_method *meth, hash_context *ctx, int prefix_bits, unsigned char **prefix);
void hash_context_write_result(hash_method *meth, hash_context *res, int index, result_element *el);

#endif
