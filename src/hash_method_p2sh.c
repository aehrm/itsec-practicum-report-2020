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

#define HASH_BYTES 20

static unsigned char SCRIPT_TEMPLATE_33[57]
    = {
        20, // PUSHDATA(20)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // nonce placeholder
        117, // OP_DROP
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // pubkey template
        173 // OP_CHECKSIGVERIFY
    };

static unsigned char SCRIPT_TEMPLATE_65[89]
    = {
        20, // PUSHDATA(20)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // nonce placeholder
        117, // OP_DROP
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // pubkey template
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        173 // OP_CHECKSIGVERIFY
    };

struct p2sh_params {
    unsigned char *pubkey;
    int pubkey_len;
};

struct p2sh_hash_ctx {
    BIGNUM *nonce;
    int script_size;
    unsigned char script[57];
    unsigned char ripemdhash[20];
};

int p2sh_batch_size(hash_method *meth)
{
    return 1;
}

int p2sh_max_bits(void *params)
{
    return 160;
}

hash_context* p2sh_ctx_alloc(void *params)
{
    unsigned char *pubkey = ((p2sh_params*) params)->pubkey;
    int pubkey_len = ((p2sh_params*) params)->pubkey_len;

    hash_context *ctx = malloc(sizeof (p2sh_hash_ctx));
    ((p2sh_hash_ctx*) ctx)->nonce = BN_new();

    unsigned char *script = ((p2sh_hash_ctx*) ctx)->script;
    ((p2sh_hash_ctx*) ctx)->script_size = pubkey_len + 24;

    if (pubkey_len == 33) {
        memcpy(script, SCRIPT_TEMPLATE_33, 57);
    } else {
        memcpy(script, SCRIPT_TEMPLATE_65, 89);
    }
    memcpy(script+23, pubkey, pubkey_len);

    return ctx;
}

void p2sh_ctx_rekey(void *params, hash_context *ctx)
{
    BIGNUM *nonce = ((p2sh_hash_ctx*) ctx)->nonce;
    BN_rand(nonce, HASH_BYTES * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
}

int p2sh_ctx_next(void *params, hash_context *ctx)
{
    BIGNUM *nonce = ((p2sh_hash_ctx*) ctx)->nonce;
    unsigned char *script = ((p2sh_hash_ctx*) ctx)->script;
    unsigned char *hash = ((p2sh_hash_ctx*) ctx)->ripemdhash;
    int script_size = ((p2sh_hash_ctx*) ctx)->script_size;

    // update nonce
    BN_add_word(nonce, 1);

    // assemble script
    unsigned char nonce_bytes[HASH_BYTES];
    BN_bn2bin(nonce, nonce_bytes);
    memcpy(script+1, nonce_bytes, HASH_BYTES);

    // comupte ripemd(sha256(pubkey))
    unsigned char sha256md[32];
    size_t null;
    SHA256(script, script_size, sha256md);
    RIPEMD160(sha256md, 32, hash);

    return 1;
}

void p2sh_serialize_result(void *params, hash_context *ctx, int index, char **hash_serialized, char **preimage_serialized)
{
    unsigned char *script = ((p2sh_hash_ctx*) ctx)->script;
    unsigned char *hash = ((p2sh_hash_ctx*) ctx)->ripemdhash;
    int script_size = ((p2sh_hash_ctx*) ctx)->script_size;
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

    // script as 57/89 serialized byte string
    char *preimage_str = (char*) malloc((2*script_size+1) * sizeof (char));
    *preimage_serialized = preimage_str;

    for (int i = 0; i < script_size; i++) {
        sprintf(buffer, "%.2X", script[i]);
        memcpy(preimage_str+2*i, buffer, 2);
    }
    preimage_str[2*script_size] = '\0';
}


void p2sh_ctx_prefixes(void *params, hash_context *ctx, int prefix_bits, unsigned char **prefixes)
{
    unsigned char *hash = ((p2sh_hash_ctx*) ctx)->ripemdhash;
    memcpy(prefixes[0], hash, ceil((double) prefix_bits / 8));
}

hash_method* hash_method_p2sh(unsigned char *pubkey, int pubkey_len)
{
    hash_method_impl *meth = (hash_method_impl*) malloc(sizeof (hash_method_impl));
    meth->max_prefix_bits = &p2sh_max_bits;
    meth->hash_context_alloc = &p2sh_ctx_alloc;
    meth->hash_context_rekey = &p2sh_ctx_rekey;
    meth->hash_context_next_result = &p2sh_ctx_next;
    meth->hash_context_get_prefixes = &p2sh_ctx_prefixes;
    meth->serialize_result = &p2sh_serialize_result;
    meth->batch_size = &p2sh_batch_size;

    p2sh_params *params = (p2sh_params*) malloc(sizeof(p2sh_params));
    params->pubkey_len = pubkey_len;
    params->pubkey = (unsigned char*) malloc(pubkey_len);
    memcpy(params->pubkey, pubkey, pubkey_len);

    meth->params = params; 

    return (hash_method*) meth;
};
