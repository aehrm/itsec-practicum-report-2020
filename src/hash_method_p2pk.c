#include "hash_method.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <math.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>
#include <cstring>

#define BATCH_SIZE 1024
#define COORD_BYTES 32

struct p2pk_hash_ctx {
    BN_CTX *bn_ctx;
    EC_POINT *batchinc;
    EC_KEY *basekey;
    EC_POINT *points[BATCH_SIZE];
};


int p2pk_max_bits(void *params)
{
    return COORD_BYTES * 8;
}

int p2pk_batch_size(void *params)
{
    return BATCH_SIZE;
}

hash_context* p2pk_ctx_alloc(void *params)
{
    BIGNUM *bn_batch_size = BN_new(); BN_set_word(bn_batch_size, BATCH_SIZE);
    p2pk_hash_ctx *ctx = (p2pk_hash_ctx*) malloc(sizeof(struct p2pk_hash_ctx));
    ctx->basekey = EC_KEY_new_by_curve_name(NID_secp256k1);
    ctx->bn_ctx = BN_CTX_new();

    const EC_GROUP *pgroup = EC_KEY_get0_group(ctx->basekey);
    ctx->batchinc = EC_POINT_new(pgroup);
    EC_POINT_mul(pgroup, ctx->batchinc, bn_batch_size, NULL, NULL, ctx->bn_ctx);

    for (int i = 0; i < BATCH_SIZE; i++)
        ctx->points[i] = EC_POINT_new(pgroup);

    return ctx;
}

void p2pk_ctx_rekey(void *params, hash_context *ctx)
{
    BN_CTX *bn_ctx = ((p2pk_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pk_hash_ctx*) ctx)->basekey;
    EC_POINT **points = ((p2pk_hash_ctx*) ctx)->points;
    const EC_GROUP *pgroup = EC_KEY_get0_group(basekey);
    const EC_POINT *pgen = EC_GROUP_get0_generator(pgroup);
    EC_KEY_generate_key(basekey);
    EC_POINT_copy(points[0], EC_KEY_get0_public_key(basekey));

    // points[i] = points[i-1] + G
    for (int i = 1; i < BATCH_SIZE; i++) {
        EC_POINT_add(pgroup, points[i], points[i-1], pgen, bn_ctx);
    }
}

int p2pk_ctx_next(void *params, hash_context *ctx)
{
    BIGNUM *bn_batch_size = BN_new(); BN_set_word(bn_batch_size, BATCH_SIZE);
    BN_CTX *bn_ctx = ((p2pk_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pk_hash_ctx*) ctx)->basekey;
    EC_POINT **points = ((p2pk_hash_ctx*) ctx)->points;
    EC_POINT *batchinc = ((p2pk_hash_ctx*) ctx)->batchinc;
    const EC_GROUP *pgroup = EC_KEY_get0_group(basekey);
    const EC_POINT *pgen = EC_GROUP_get0_generator(pgroup);

    // add batchinc to basekey
    BIGNUM *priv = BN_dup(EC_KEY_get0_private_key(basekey));
    EC_POINT *pub = EC_POINT_dup(EC_KEY_get0_public_key(basekey), pgroup);
    BN_add(priv, priv, bn_batch_size);
    EC_POINT_add(pgroup, pub, pub, batchinc, bn_ctx);
    EC_KEY_set_private_key(basekey, priv);
    EC_KEY_set_public_key(basekey, pub);

    // add batchinc to points
    for (int i = 0; i < BATCH_SIZE; i++)
        EC_POINT_add(pgroup, points[i], points[i], batchinc, bn_ctx);

    // make affine
    EC_POINTs_make_affine(pgroup, BATCH_SIZE, points, bn_ctx);

    return 1;
}

void p2pk_serialize_result(void *params, hash_context *ctx, int index, char **hash_serialized, char **preimage_serialized)
{
    BN_CTX *bn_ctx = ((p2pk_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pk_hash_ctx*) ctx)->basekey;
    EC_POINT **points = ((p2pk_hash_ctx*) ctx)->points;
    const EC_GROUP *pgroup = EC_KEY_get0_group(basekey);
    const EC_POINT *pgen = EC_GROUP_get0_generator(pgroup);

    // public key in compressed format (i.e. omitting y-coordinate)
    *hash_serialized = EC_POINT_point2hex(pgroup, points[index], POINT_CONVERSION_COMPRESSED, bn_ctx);

    // compute private key; priv_basekey + i
    BIGNUM *priv = BN_dup(EC_KEY_get0_private_key(basekey));
    BIGNUM *offset = BN_new(); BN_set_word(offset, index);
    BN_add(priv, priv, offset);

    // private key as 256-bit number (TODO use wallet import format)
    *preimage_serialized = BN_bn2hex(priv);
}


void p2pk_ctx_prefixes(void *params, hash_context *ctx, int prefix_bits, unsigned char **prefixes)
{
    int prefix_bytes = (int) ceil((double) prefix_bits / 8);
    EC_POINT **points = ((p2pk_hash_ctx*) ctx)->points;
    BN_CTX *bn_ctx = ((p2pk_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pk_hash_ctx*) ctx)->basekey;
    const EC_GROUP *pgroup = EC_KEY_get0_group(basekey);

    BIGNUM *x = BN_new();
    unsigned char x_bytes[COORD_BYTES];

    for (int i = 0; i < BATCH_SIZE; i++) {
        EC_POINT_get_affine_coordinates(pgroup, points[i], x, NULL, bn_ctx);
        BN_bn2bin(x, x_bytes);
        memcpy(prefixes[i], x_bytes, prefix_bytes);
    }
}


hash_method* hash_method_p2pk()
{
    hash_method_impl *meth = (hash_method_impl*) malloc(sizeof (hash_method_impl));
    meth->max_prefix_bits = &p2pk_max_bits;
    meth->batch_size = &p2pk_batch_size;
    meth->hash_context_alloc = &p2pk_ctx_alloc;
    meth->hash_context_rekey = &p2pk_ctx_rekey;
    meth->hash_context_next_result = &p2pk_ctx_next;
    meth->hash_context_get_prefixes = &p2pk_ctx_prefixes;
    meth->serialize_result = &p2pk_serialize_result;

    return (hash_method*) meth;
};
