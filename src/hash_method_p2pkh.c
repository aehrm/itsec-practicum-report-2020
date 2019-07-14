#include "hash_method.h"
#include "secp256k1.h"
#include <math.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

struct p2pkh_hash_ctx {
    secp256k1_scalar privkey;
    secp256k1_ge pubkey;
    unsigned char ripemdhash[20];
};


hash_context* p2pkh_ctx_alloc()
{
    return malloc(sizeof (struct p2pkh_hash_ctx));
}

void p2pkh_ctx_rekey(hash_context *ctx)
{
    secp256k1_scalar *privkey = &(((p2pkh_hash_ctx*) ctx)->privkey);
    secp256k1_ge *pubkey = &(((p2pkh_hash_ctx*) ctx)->pubkey);

    unsigned char nonce[32];
    arc4random_buf(nonce, 32);
    secp256k1_scalar_set_b32(privkey, nonce, NULL);

    secp256k1_gej point;
    secp256k1_ecmult_const(&point, &secp256k1_ge_const_g, privkey, 256);
    secp256k1_ge_set_gej_var(pubkey, &point);
}

int p2pkh_ctx_next(hash_context *ctx)
{
    secp256k1_scalar *privkey = &(((p2pkh_hash_ctx*) ctx)->privkey);
    secp256k1_ge *pubkey = &(((p2pkh_hash_ctx*) ctx)->pubkey);
    unsigned char *hash = ((p2pkh_hash_ctx*) ctx)->ripemdhash;

    secp256k1_scalar ONE;
    secp256k1_scalar_set_int(&ONE, 1);

    secp256k1_gej point;
    secp256k1_gej_set_ge(&point, pubkey);
    secp256k1_gej_add_ge_var(&point, &point, &secp256k1_ge_const_g, NULL);

    // update pubkey/privkey
    secp256k1_ge_set_gej_var(pubkey, &point);
    secp256k1_scalar_add(privkey, privkey, &ONE);

    // comupte ripemd(sha256(pubkey))
    unsigned char pubkey_serialized[33];
    unsigned char sha256md[32];
    size_t null;
    secp256k1_eckey_pubkey_serialize(pubkey, pubkey_serialized, &null, 1);
    SHA256(pubkey_serialized, 33 * sizeof(unsigned char), sha256md);
    RIPEMD160(sha256md, 32 * sizeof(unsigned char), hash);

    return 1;
}

void p2pkh_serialize_result(hash_context *ctx, char **hash_serialized, char **preimage_serialized)
{
    secp256k1_scalar *privkey = &(((p2pkh_hash_ctx*) ctx)->privkey);
    unsigned char *hash = ((p2pkh_hash_ctx*) ctx)->ripemdhash;
    char buffer[2];

    // 20 bytes ripemd hash
    unsigned char pubkey_serialized[20];
    char *hash_str = (char*) malloc((2*20+1) * sizeof (char));
    *hash_serialized = hash_str;

    for (int i = 0; i < 20; i++) {
        sprintf(buffer, "%.2X", hash[i]);
        memcpy(hash_str+2*i, buffer, 2);
    }
    hash_str[2*20] = '\0';

    // private key as 256-bit number (TODO use wallet import format)
    unsigned char privkey_serialized[32];
    secp256k1_scalar_get_b32(privkey_serialized, privkey);
    char *preimage_str = (char*) malloc((2*32+1) * sizeof (char));
    *preimage_serialized = preimage_str;

    for (int i = 0; i < 32; i++) {
        sprintf(buffer, "%.2X", privkey_serialized[i]);
        memcpy(preimage_str+2*i, buffer, 2);
    }
    preimage_str[2*32] = '\0';
}


void p2pkh_ctx_prefix(hash_context *ctx, int prefix_bits, unsigned char *prefix)
{
    unsigned char *hash = ((p2pkh_hash_ctx*) ctx)->ripemdhash;
    memcpy(prefix, hash, ceil((double) prefix_bits / 8));
}


hash_method hash_method_p2pkh = {
    .max_prefix_bits = 160,
    .hash_context_alloc = &p2pkh_ctx_alloc,
    .hash_context_rekey = &p2pkh_ctx_rekey,
    .hash_context_next_result = &p2pkh_ctx_next,
    .hash_context_get_prefix = &p2pkh_ctx_prefix,
    .serialize_result = &p2pkh_serialize_result,
};

