#include "util.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

#include <openssl/rand.h>

#include "libbtc/include/btc/tx.h"
#include "libbtc/include/btc/cstr.h"
#include "libbtc/include/btc/vector.h"
#include "libbtc/include/btc/script.h"

#define NONDUST 576

void fdumphex(FILE *f, unsigned char *src, int len)
{
    for (int i = 0; i < len; i++) {
        fprintf(f, "%.2x", src[i]);
    }
}

void genlink(uint160 scripthash, cstring* linkscriptsig)
{
    unsigned char nonce[16];
    cstr_resize(linkscriptsig, 0);

    cstring *script = cstr_new_sz(64);
    btc_script_append_op(script, OP_RETURN);

    RAND_bytes(nonce, 16);
    btc_script_append_pushdata(script, nonce, 16);

    btc_script_get_scripthash(script, scripthash);

    btc_script_append_op(linkscriptsig, OP_0);
    btc_script_append_pushdata(linkscriptsig, (unsigned char*) script->str, script->len);
    
    cstr_free(script, 1);
}

int tx_size(btc_tx *tx)
{
    cstring *s = cstr_new_sz(1024);
    btc_tx_serialize(s, tx, false);

    int len = s->len;
    cstr_free(s, 1);

    return len;
}

tx_chain_el* util_construct_txs(unsigned char **scripts, int *scripts_len, int script_num, int prefix_len, int data_len, int fee)
{
    tx_chain_el *head = (tx_chain_el*) malloc(sizeof(tx_chain_el*));
    cstring *linkscriptsig = cstr_new_sz(64);
    uint160 linkscripthash;


    head->prev = NULL;
    head->tx = btc_tx_new();
    head->next = (tx_chain_el*) malloc(sizeof(tx_chain_el*));
    head->next->prev = head;

    // metadata placeholder
    vector_add(head->tx->vout, btc_tx_out_new());

    // link
    genlink(linkscripthash, linkscriptsig);
    btc_tx_add_p2sh_hash160_out(head->tx, 0, linkscripthash);

    tx_chain_el* cur;
    unsigned int tx_ctr = 1;
    int script_idx = 0;

    cur = head;
    while (true) {
        cur = cur->next;
        cur->tx = btc_tx_new();

        // add input
        btc_tx_in *in = btc_tx_in_new();
        in->script_sig = cstr_new_cstr(linkscriptsig);
        vector_add(cur->tx->vin, in);

        // add data scripts
        btc_tx_out *out;
        while (script_idx < script_num && tx_size(cur->tx) < 100000) {
            out = btc_tx_out_new();
            out->value = NONDUST;
            out->script_pubkey = cstr_new_buf((const void*)scripts[script_idx], scripts_len[script_idx]);
            script_idx++;

            vector_add(cur->tx->vout, out);
        }

        if (tx_size(cur->tx) > 100000) {
            // roll back
            vector_remove_idx(cur->tx->vout, cur->tx->vout->len-1);
            script_idx--;
        }

        if (script_idx < script_num) {
            // add link
            genlink(linkscripthash, linkscriptsig);
            btc_tx_add_p2sh_hash160_out(cur->tx, 0, linkscripthash);
            cur->next = (tx_chain_el*) malloc(sizeof(tx_chain_el*));
            cur->next->prev = cur;
            
            tx_ctr++;
        } else {
            cur->next = NULL;
            break;
        }
    }

    tx_chain_el* tail = cur;

    // specify funds
    int funds = 0;
    for (cur = tail; cur->prev != NULL; cur = cur->prev) {
        funds += cur->tx->vout->len * NONDUST;
        funds += tx_size(cur->tx) * fee;

        btc_tx_out *linktx = (btc_tx_out*) vector_idx(cur->prev->tx->vout, cur->prev->tx->vout->len-1);
        linktx->value = funds;
    }


    // set metadata
    unsigned char data[15];
    memcpy(data, "hidedata", 8);
    data[8] = tx_ctr & 0xFF;
    data[9] = (tx_ctr >> 8) & 0xFF;
    data[10] = prefix_len;
    data[11] = (data_len      ) & 0xFF;
    data[12] = (data_len >>  8) & 0xFF;
    data[13] = (data_len >> 16) & 0xFF;
    data[14] = (data_len >> 24) & 0xFF;

    btc_tx_out *metadata = (btc_tx_out*) vector_idx(head->tx->vout, 0);
    metadata->script_pubkey = cstr_new_sz(64);
    metadata->value = NONDUST;
    btc_script_append_op(metadata->script_pubkey, OP_RETURN);
    btc_script_append_pushdata(metadata->script_pubkey, data, 15);


    // specify outpoints
    for (cur = head; cur->next != NULL; cur = cur->next) {
        btc_tx_outpoint outpoint;
        outpoint.n = cur->tx->vout->len;
        btc_tx_hash(cur->tx, outpoint.hash);
        btc_tx_in *linktx = (btc_tx_in*) vector_idx(cur->next->tx->vin, 0);

        linktx->prevout = outpoint;
    }

    return head;
}

void util_print_results(hash_engine *engine)
{
    fprintf(stderr, "Generated hash/preimage pairs\n");
    for (int i = 0; i < engine->results_num; i++) {
        result_element res = engine->results[i];
        fprintf(stderr, "#%d: ", i);
        fdumphex(stderr, res.hash, res.hash_len);
        fprintf(stderr, " ");
        fdumphex(stderr, res.preimage, res.preimage_len);
        fprintf(stderr, "\n");
    }

}

void util_print_txs(hash_engine *engine, hash_method *method, int bits, int data_size, int fee)
{
    unsigned char *scripts[engine->results_num];
    int scripts_len[engine->results_num];
    for (int i = 0; i < engine->results_num; i++) {
        int len = hash_method_construct_script(method, NULL, &engine->results[i]);
        scripts[i] = (unsigned char*) malloc(sizeof(unsigned char) * len);
        hash_method_construct_script(method, scripts[i], &engine->results[i]);
        scripts_len[i] = len;
    }

    fprintf(stderr, "Generated transaction\n");
    cstring *s = cstr_new_sz(1024);
    tx_chain_el* head = util_construct_txs(scripts, scripts_len, engine->results_num, bits, data_size, fee);
    for (tx_chain_el* el = head; el != NULL; el = el->next) {
        btc_tx *tx = el->tx;
        cstr_resize(s, 0);
        btc_tx_serialize(s, tx, false);

        fdumphex(stdout, (unsigned char*) s->str, s->len);
        fprintf(stdout, "\n");
    }
}
