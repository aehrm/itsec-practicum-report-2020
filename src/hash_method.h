#ifndef __HASH_METHOD_H__
#define __HASH_METHOD_H__ 1

typedef void hash_context;
typedef void hash_method;

hash_method* hash_method_p2pk();
hash_method* hash_method_p2pkh();
hash_method* hash_method_p2sh(unsigned char *pubkey, int pubkey_len);

int hash_method_max_prefix_bits(hash_method *meth);
hash_context* hash_context_alloc(hash_method *meth);
void hash_context_rekey(hash_method *meth, hash_context *ctx);
int hash_context_next_result(hash_method *meth, hash_context *ctx);
void hash_context_get_prefix(hash_method *meth, hash_context *ctx, int prefix_bits, unsigned char *prefix);
void serialize_result(hash_method *meth, hash_context *res, char **hash_serialized, char **preimage_serialized);

#endif
