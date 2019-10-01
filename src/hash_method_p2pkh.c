#include "hash_method.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <math.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>
#include <cstring>

#define BATCH_SIZE 1024
#define HASH_BYTES 20

struct p2pkh_hash_ctx {
    BN_CTX *bn_ctx;
    EC_POINT *batchinc;
    EC_KEY *basekey;
    EC_POINT *points[BATCH_SIZE];
    unsigned char *ripemdhashes[BATCH_SIZE];
};


int p2pkh_max_bits(void *params)
{
    return HASH_BYTES * 8;
}

int p2pkh_batch_size(void *params)
{
    return BATCH_SIZE;
}

int p2pkh_construct_script(void *params, unsigned char *out, result_element *result)
{
    if (out == NULL) return 25;

    out[0] = 0x76; // OP_DUP
    out[1] = 0xA9; // OP_HASH160
    out[2] = 20; // 33 bytes to push
    memcpy(out+3, results->hash, 20); // pubkey
    out[23] = 0x88; // OP_EQUALVERIFY
    out[24] = 0xAC; // OP_CHECKSIG
    out += 25;
        
    return 25;
}

hash_context* p2pkh_ctx_alloc(void *params)
{
    BIGNUM *bn_batch_size = BN_new(); BN_set_word(bn_batch_size, BATCH_SIZE);
    p2pkh_hash_ctx *ctx = (p2pkh_hash_ctx*) malloc(sizeof(struct p2pkh_hash_ctx));
    ctx->basekey = EC_KEY_new_by_curve_name(NID_secp256k1);
    ctx->bn_ctx = BN_CTX_new();

    const EC_GROUP *pgroup = EC_KEY_get0_group(ctx->basekey);
    ctx->batchinc = EC_POINT_new(pgroup);
    EC_POINT_mul(pgroup, ctx->batchinc, bn_batch_size, NULL, NULL, ctx->bn_ctx);

    for (int i = 0; i < BATCH_SIZE; i++)
        ctx->points[i] = EC_POINT_new(pgroup);

    unsigned char *hash_container = (unsigned char*) malloc(HASH_BYTES * BATCH_SIZE * sizeof(unsigned char));
    for (int i = 0; i < BATCH_SIZE; i++)
        ctx->ripemdhashes[i] = hash_container + HASH_BYTES * i;

    return ctx;
}

void p2pkh_ctx_rekey(void *params, hash_context *ctx)
{
    BN_CTX *bn_ctx = ((p2pkh_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pkh_hash_ctx*) ctx)->basekey;
    EC_POINT **points = ((p2pkh_hash_ctx*) ctx)->points;
    const EC_GROUP *pgroup = EC_KEY_get0_group(basekey);
    const EC_POINT *pgen = EC_GROUP_get0_generator(pgroup);
    EC_KEY_generate_key(basekey);
    EC_POINT_copy(points[0], EC_KEY_get0_public_key(basekey));

    // points[i] = points[i-1] + G
    for (int i = 1; i < BATCH_SIZE; i++) {
        EC_POINT_add(pgroup, points[i], points[i-1], pgen, bn_ctx);
    }
}

int p2pkh_ctx_next(void *params, hash_context *ctx)
{
    BIGNUM *bn_batch_size = BN_new(); BN_set_word(bn_batch_size, BATCH_SIZE);
    BN_CTX *bn_ctx = ((p2pkh_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pkh_hash_ctx*) ctx)->basekey;
    EC_POINT **points = ((p2pkh_hash_ctx*) ctx)->points;
    EC_POINT *batchinc = ((p2pkh_hash_ctx*) ctx)->batchinc;
    unsigned char **hashes = ((p2pkh_hash_ctx*) ctx)->ripemdhashes;
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

    unsigned char pubkey_serialized[33];
    unsigned char sha256md[32];
    // comupte ripemd(sha256(pubkey))
    for (int i = 0; i < BATCH_SIZE; i++) {
        EC_POINT_point2oct(pgroup, points[i], POINT_CONVERSION_COMPRESSED, pubkey_serialized, 33 * sizeof(unsigned char), bn_ctx);
        SHA256(pubkey_serialized, 33 * sizeof(unsigned char), sha256md);
        RIPEMD160(sha256md, 32 * sizeof(unsigned char), hashes[i]);
    }

    return 1;
}

void p2pkh_write_result(void *params, hash_context *ctx, int index, result_element *res)
{
    BN_CTX *bn_ctx = ((p2pkh_hash_ctx*) ctx)->bn_ctx;
    EC_KEY *basekey = ((p2pkh_hash_ctx*) ctx)->basekey;
    unsigned char *hash = ((p2pkh_hash_ctx*) ctx)->ripemdhashes[index];
    char buffer[2];

    // 20 bytes ripemd hash
    res->hash = (unsigned char*) malloc(20 * sizeof(unsigned char));
    memcpy(res->hash, hash, 20);
    res->hash_len = 20;

    // compute private key; priv_basekey + i
    BIGNUM *priv = BN_dup(EC_KEY_get0_private_key(basekey));
    BIGNUM *offset = BN_new(); BN_set_word(offset, index);
    BN_add(priv, priv, offset);

    // private key as 256-bit number (TODO use wallet import format)
    res->preimage = (unsigned char*) malloc(32 * sizeof(unsigned char));
    res->preimage_len = BN_bn2bin(priv, res->preimage);
}


void p2pkh_ctx_prefixes(void *params, hash_context *ctx, int prefix_bits, unsigned char **prefixes)
{
    unsigned char **hashes = ((p2pkh_hash_ctx*) ctx)->ripemdhashes;
    for (int i = 0; i < BATCH_SIZE; i++) {
        memcpy(prefixes[i], hashes[i], ceil((double) prefix_bits / 8));
    }
}


hash_method* hash_method_p2pkh()
{
    hash_method_impl *meth = (hash_method_impl*) malloc(sizeof (hash_method_impl));
    meth->max_prefix_bits = &p2pkh_max_bits;
    meth->batch_size = &p2pkh_batch_size;
    meth->construct_tx = &p2pkh_construct_script;
    meth->hash_context_alloc = &p2pkh_ctx_alloc;
    meth->hash_context_rekey = &p2pkh_ctx_rekey;
    meth->hash_context_next_result = &p2pkh_ctx_next;
    meth->hash_context_get_prefixes = &p2pkh_ctx_prefixes;
    meth->write_result = &p2pkh_write_result;

    return (hash_method*) meth;
};
