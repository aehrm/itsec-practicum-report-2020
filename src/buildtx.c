#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <limits.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>
#include <cerrno>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>
#include "util.h"
#include "rpc.h"

#include <openssl/rand.h>

#include "libbtc/include/btc/tx.h"
#include "libbtc/include/btc/cstr.h"
#include "libbtc/include/btc/vector.h"
#include "libbtc/include/btc/script.h"

#include "cjson/cJSON.h"

#define NONDUST 576

typedef struct tx_chain_el_ {
    btc_tx *tx;
    tx_chain_el_ *prev;
    tx_chain_el_ *next;
} tx_chain_el;

void genlink(uint160 scripthash, cstring* linkscriptsig)
{
    unsigned char nonce[16];
    cstr_resize(linkscriptsig, 0);

    cstring *script = cstr_new_sz(64);
    RAND_bytes(nonce, 16);
    btc_script_append_pushdata(script, nonce, 16);
    btc_script_append_op(script, OP_DROP);
    btc_script_append_op(script, OP_TRUE);

    btc_script_get_scripthash(script, scripthash);
    btc_script_append_pushdata(linkscriptsig, (unsigned char*) script->str, script->len);
    
    cstr_free(script, 1);
}

int tx_size(btc_tx *tx)
{
    cstring *s = cstr_new_sz(1024);
    btc_tx_serialize(s, tx, true);

    int len = s->len;
    cstr_free(s, 1);

    return len;
}

tx_chain_el* construct_txs(unsigned char **scripts, int *scripts_len, int script_num, int prefix_len, int data_len, int fee)
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

    return head;
}

int sign_tx_chain(tx_chain_el *head, int fee, char *rpcurl)
{
    int ret;

    // fund head
    cJSON *out;

    cstring *s = cstr_new_sz(1024);
    btc_tx_serialize(s, head->tx, true);
    char *hextx = bintohex((unsigned char*) s->str, s->len);

    cJSON *fund_params = cJSON_CreateObject();
    cJSON_AddStringToObject(fund_params, "hexstring", hextx);
    /*cJSON_AddBoolToObject(fund_params, "iswitness", false);*/

    cJSON *options = cJSON_AddObjectToObject(fund_params, "options");
    cJSON_AddNumberToObject(options, "changePosition", 1);
    cJSON_AddNumberToObject(options, "feeRate", ((float) fee)*1e-5);
    

    ret = rpc_call(rpcurl, "fundrawtransaction", fund_params, &out);
    cJSON_Delete(fund_params);
    free(hextx);

    if (ret) return 1;
    hextx = strdup(cJSON_GetObjectItem(out, "hex")->valuestring);
    cJSON_Delete(out);

    cJSON *sign_params = cJSON_CreateObject();
    cJSON_AddStringToObject(sign_params, "hexstring", hextx);

    ret = rpc_call(rpcurl, "signrawtransactionwithwallet", sign_params, &out);
    cJSON_Delete(sign_params);
    free(hextx);

    if (ret) return 1;
    hextx = strdup(cJSON_GetObjectItem(out, "hex")->valuestring);
    cJSON_Delete(out);


    int len = strlen(hextx)/2;
    unsigned char* tx_serialized = (unsigned char*) malloc(sizeof(unsigned char) * len);
    hextobin(tx_serialized, hextx, strlen(hextx));
    free(hextx);

    btc_tx_free(head->tx);
    head->tx = btc_tx_new();
    btc_tx_deserialize(tx_serialized, len, head->tx, NULL, true);
    free(tx_serialized);

    // specify outpoints
    for (tx_chain_el *cur = head; cur->next != NULL; cur = cur->next) {
        btc_tx_outpoint outpoint;
        outpoint.n = cur->tx->vout->len-1;
        btc_tx_hash(cur->tx, outpoint.hash);
        btc_tx_in *linktx = (btc_tx_in*) vector_idx(cur->next->tx->vin, 0);

        linktx->prevout = outpoint;
    }

    return 0;
}

void read_input(FILE *infile, result_element **results, int *results_num, char **hash_method, int *data_size, int *bits)
{
    int file_size;
    unsigned char *filedata = util_read_file(infile, &file_size);
    char *in = (char*) malloc(sizeof(char) * (file_size + 1));

    memcpy(in, filedata, file_size);
    in[file_size] = '\0';
    free(filedata);

    util_read_results(in, results, results_num, hash_method, data_size, bits);
    free(in);
}

void construct_script(char *method_str, unsigned char **script, int *script_len, result_element *result)
{
    cstring *s = cstr_new_sz(32);
    if (strcmp(method_str, "p2pk") == 0) {
        btc_script_append_pushdata(s, result->hash, 33);
        btc_script_append_op(s, OP_CHECKSIG);
    } else if (strcmp(method_str, "p2pkh") == 0) {
        btc_script_build_p2pkh(s, result->hash);
    } else if (strcmp(method_str, "p2sh") == 0) {
        btc_script_build_p2sh(s, result->hash);
    } else {
        *script = NULL;
        *script_len = 0;
        return;
    }

    *script_len = s->len;
    *script = (unsigned char*) malloc(sizeof(unsigned char) * s->len);
    memcpy(*script, s->str, s->len);

    cstr_free(s, true);
}

void usage(const char *name)
{
    fprintf(stderr,
"Usage: %s [-f <file>|-] [-F <fee>] [-R <rpcurl>]\n"
"\n"
"Parameter:\n"
"-f <file>|-            Read keypairs from specified JSON file. If \"-\" was specified,\n"
"                       data is read from standard input.\n"
"-F <fee>               Construct transaction with specified fee in sat/byte.\n"
"-R <rpcurl>            Use specified bitcoind deamon endpoint, in the form\n"
"                       http://user:password@ipaddr:port/\n", name);
}

int main(int argc, char *argv[])
{
    int fee = 20;
    char *rpcurl = "http://127.0.0.1:8332/";
    FILE *infile = stdin;

    int opt;
    while ((opt = getopt(argc, argv, ":h?:f:F:R:")) != -1) {
        switch (opt) {
            case 'f':
                if (strcmp(optarg, "-") == 0) {
                    infile = stdin;
                } else {
                    infile = fopen(optarg, "r");
                    if (!infile) {
                        fprintf(stderr,
                            "Could not open %s: %s\n",
                            optarg, strerror(errno));
                        return 1;
                    }
                }
                break;
            case 'F':
                fee = atoi(optarg);
                break;
            case 'R':
                rpcurl = optarg;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    int results_num;
    result_element *results;
    char *method_str;
    int data_size;
    int bits;
    read_input(infile, &results, &results_num, &method_str, &data_size, &bits);

    if (results == NULL) {
        return 1;
    }

    unsigned char *scripts[results_num];
    int scripts_len[results_num];
    for (int i = 0; i < results_num; i++) {
        construct_script(method_str, &scripts[i], &scripts_len[i], &(results[i]));
    }

    cstring *s = cstr_new_sz(1024);
    tx_chain_el* head = construct_txs(scripts, scripts_len, results_num, bits, data_size, fee);
    if (sign_tx_chain(head, fee, rpcurl)) {
        return 1;
    }

    fprintf(stderr, "Generated transaction\n");
    for (tx_chain_el* el = head; el != NULL; el = el->next) {
        btc_tx *tx = el->tx;
        cstr_resize(s, 0);
        btc_tx_serialize(s, tx, true);

        fdumphex(stdout, (unsigned char*) s->str, s->len);
        fprintf(stdout, "\n");
    }

}
