#include "hash_method.h"
#include "secp256k1.h"
#include <math.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>


void p2pk_serialize_result(hash_context *res, char **hash_serialized, char **preimage_serialized)
{
    secp256k1_ge *pubkey = (secp256k1_ge*) res->hash;
    secp256k1_scalar *seckey = (secp256k1_scalar*) res->preimage;
    char buffer[2];

    // public key in compressed format (i.e. omitting y-coordinate)
    unsigned char pubkey_serialized[33];
    size_t null;
    secp256k1_eckey_pubkey_serialize(pubkey, pubkey_serialized, &null, 1);

    char *hash_str = (char*) malloc(2 * 33 * sizeof (char) + 1);
    *hash_serialized = hash_str;

    for (int i = 0; i < 33; i++) {
        sprintf(buffer, "%.2X", pubkey_serialized[i]);
        memcpy(hash_str+2*i, buffer, 2);
    }
    hash_str[2*33] = '\0';

    // private key as 256-bit number (TODO use wallet import format)
    unsigned char seckey_serialized[32];
    secp256k1_scalar_get_b32(seckey_serialized, seckey);
    char *preimage_str = (char*) malloc(2 * 32 * sizeof (char) + 1);
    *preimage_serialized = preimage_str;

    for (int i = 0; i < 32; i++) {
        sprintf(buffer, "%.2X", seckey_serialized[i]);
        memcpy(preimage_str+2*i, buffer, 2);
    }
    preimage_str[2*32] = '\0';
}

void p2pk_ctx_alloc(hash_context *ctx)
{
    ctx->preimage = (secp256k1_scalar*) malloc(sizeof (secp256k1_scalar));
    ctx->hash = (secp256k1_ge*) malloc(sizeof (secp256k1_ge));
}

void p2pk_ctx_rekey(hash_context *ctx)
{
    unsigned char seckey[32];
    arc4random_buf(seckey, 32);
    secp256k1_scalar_set_b32((secp256k1_scalar*) ctx->preimage, seckey, NULL);

    secp256k1_gej point;
    secp256k1_ecmult_const(&point, &secp256k1_ge_const_g, (secp256k1_scalar*) ctx->preimage, 256);
    secp256k1_ge_set_gej_var((secp256k1_ge*) ctx->hash, &point);
}

int p2pk_ctx_next(hash_context *ctx)
{
    secp256k1_scalar ONE;
    secp256k1_scalar_set_int(&ONE, 1);

    secp256k1_scalar *privkey = (secp256k1_scalar*) ctx->preimage;
    secp256k1_ge *pubkey = (secp256k1_ge*) ctx->hash;

    secp256k1_gej point;
    secp256k1_gej_set_ge(&point, pubkey);
    secp256k1_gej_add_ge_var(&point, &point, &secp256k1_ge_const_g, NULL);


    secp256k1_ge_set_gej_var(pubkey, &point);
    secp256k1_scalar_add(privkey, privkey, &ONE);

    return 1;
}

void p2pk_ctx_prefix(hash_context *ctx, int prefix_bits, unsigned char *prefix)
{
    unsigned char pubkey[32];
    secp256k1_ge point = *((secp256k1_ge*) ctx->hash);
    secp256k1_fe_get_b32(pubkey, &(point.x));

    memcpy(prefix, pubkey, ceil((double) prefix_bits / 8));
}


hash_method hash_method_p2pk = {
    .max_prefix_bits = 256,
    .hash_context_alloc = &p2pk_ctx_alloc,
    .hash_context_rekey = &p2pk_ctx_rekey,
    .hash_context_next_result = &p2pk_ctx_next,
    .hash_context_get_prefix = &p2pk_ctx_prefix,
    .serialize_result = &p2pk_serialize_result,
};
