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
#include "libbtc/include/btc/random.h"
#include "libbtc/include/btc/ecc.h"
#include "libbtc/include/btc/serialize.h"

#include "cjson/cJSON.h"
#include "../lib/libbtc/include/btc/tx.h"

static unsigned int MAX_TX_SIZE = 100000;
static unsigned int MAX_SIGOP_COUNT = 16000;

typedef struct tx_chain_el_ {
    btc_tx *tx;
    tx_chain_el_ *prev;
    tx_chain_el_ *next;
} tx_chain_el;

int tx_size(btc_tx *tx)
{
    cstring *s = cstr_new_sz(1024);
    btc_tx_serialize(s, tx, true);

    int len = s->len;
    cstr_free(s, 1);

    return len;
}

int calc_nondust(btc_tx_out *tx_out)
{
    cstring *s = cstr_new_sz(1024);
    ser_s64(s, tx_out->value);
    ser_varstr(s, tx_out->script_pubkey);

    int len = s->len;
    cstr_free(s, 1);

    return (len + 148) * 3; // cf. bitcoin, src/policy/policy.cpp: GetDustThreshold
}

tx_chain_el* construct_txs(unsigned char **scripts, int *scripts_len, int script_num, int prefix_len, int data_len, int fee)
{

    tx_chain_el* head = (tx_chain_el*) malloc(sizeof(tx_chain_el*));
    head->next = NULL;
    head->tx = btc_tx_new();
    // link placeholder
    vector_add(head->tx->vin, btc_tx_in_new());
    // metadata placeholder
    vector_add(head->tx->vout, btc_tx_out_new());

    head->prev = (tx_chain_el*) malloc(sizeof(tx_chain_el*));
    head->prev->next = head;


    tx_chain_el* cur;
    unsigned int tx_ctr = 1;
    int script_idx = 0;

    cur = head;
    while (true) {
        cur = cur->prev;
        cur->tx = btc_tx_new();

        // add input placeholder
        vector_add(cur->tx->vin, btc_tx_in_new());

        // add link placeholder
        vector_add(cur->tx->vout, btc_tx_out_new());
        cur->prev = (tx_chain_el*) malloc(sizeof(tx_chain_el*));
        cur->prev->next = cur;

        // add data scripts
        int sigops = 0;
        btc_tx_out *out;
        while (script_idx < script_num && tx_size(cur->tx) <= MAX_TX_SIZE-135 && sigops <= MAX_SIGOP_COUNT-1) { // keep space for links
            out = btc_tx_out_new();
            out->script_pubkey = cstr_new_buf((const void*)scripts[script_idx], scripts_len[script_idx]);
            out->value = calc_nondust(out);
            sigops += btc_script_classify(out->script_pubkey, NULL) == BTC_TX_MULTISIG ? 80 : 4;
            script_idx++;

            vector_add(cur->tx->vout, out);
        }

        if (tx_size(cur->tx) > MAX_TX_SIZE-135 || sigops > MAX_SIGOP_COUNT-1) {
            // roll back
            vector_remove_idx(cur->tx->vout, cur->tx->vout->len-1);
            script_idx--;
        }

        if (script_idx < script_num) {
            tx_ctr++;
        } else {
            break;
        }
    }

    tx_chain_el *tail = cur->prev;
    tail->prev = NULL;
    tail->tx = btc_tx_new();

    // link placeholder
    vector_add(tail->tx->vout, btc_tx_out_new());

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
    btc_script_append_op(metadata->script_pubkey, OP_RETURN);
    btc_script_append_pushdata(metadata->script_pubkey, data, 15);
    metadata->value = calc_nondust(metadata);

    // specify funds
    for (cur = head; cur->prev != NULL; cur = cur->prev) {
        int64_t funds = 0;
        for (int i = 0; i < cur->tx->vout->len; i++) {
            btc_tx_out* tx_out = (btc_tx_out*) vector_idx(cur->tx->vout, i);
            funds += tx_out->value;
        }
        funds += (int64_t) tx_size(cur->tx) * fee;
        fprintf(stderr, "funds %zu, tsize %d, outs %d\n", funds, tx_size(cur->tx), cur->tx->vout->len); fflush(stderr);

        btc_tx_out *linktx = (btc_tx_out*) vector_idx(cur->prev->tx->vout, 0);
        linktx->value = funds;
    }

    return tail;
}

int sign_tx_in(tx_chain_el *el, btc_key *privkey, btc_pubkey *pubkey, cstring *redeem_script)
{
    btc_tx_in *linktx = (btc_tx_in*) vector_idx(el->tx->vin, 0);
    btc_tx_out *prevout = (btc_tx_out*) vector_idx(el->prev->tx->vout, 0);
    linktx->script_sig = cstr_new_sz(64);

    uint256 sighash;
    memset(sighash, 0, sizeof(sighash));
    btc_tx_sighash(el->tx, redeem_script, 0, 1, 0, SIGVERSION_BASE, sighash);

    // c.f. lib/libbtc/src/tx.c
    uint8_t sig[64];
    size_t siglen = 0;
    btc_key_sign_hash_compact(privkey, sighash, sig, &siglen);
    unsigned char sigder_plus_hashtype[74+1];
    size_t sigderlen = 75;
    btc_ecc_compact_to_der_normalized(sig, sigder_plus_hashtype, &sigderlen);
    sigder_plus_hashtype[sigderlen] = 1;
    sigderlen+=1;

    cstr_resize(linktx->script_sig, 0);
    btc_script_append_pushdata(linktx->script_sig, (unsigned char*) sigder_plus_hashtype, sigderlen);
    btc_script_append_pushdata(linktx->script_sig, (unsigned char*) redeem_script->str, redeem_script->len);

    return 0;

}

int sign_tx_chain(tx_chain_el *tail, int fee, char *rpcurl)
{
    btc_ecc_start();
    btc_random_init();

    // generate keypair
    btc_key privkey;
    btc_privkey_gen(&privkey);
    btc_pubkey pubkey;
    btc_pubkey_from_key(&privkey, &pubkey);
    uint160 pubkeyhash;
    btc_pubkey_get_hash160(&pubkey, pubkeyhash);
    cstring *redeem_script = cstr_new_sz(1024);
    btc_script_append_pushdata(redeem_script, pubkey.pubkey, BTC_ECKEY_COMPRESSED_LENGTH);
    btc_script_append_op(redeem_script, OP_CHECKSIG);
    uint160 redeem_script_hash;
    btc_script_get_scripthash(redeem_script, redeem_script_hash);

    int ret;

    // set tail output
    btc_tx_out *tx_out = (btc_tx_out*) vector_idx(tail->tx->vout, 0);
    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2sh(tx_out->script_pubkey, redeem_script_hash);

    // fund tail
    cJSON *json_out;

    cstring *s = cstr_new_sz(1024);
    btc_tx_serialize(s, tail->tx, true);
    char *hextx = bintohex((unsigned char*) s->str, s->len);

    cJSON *fund_params = cJSON_CreateObject();
    cJSON_AddStringToObject(fund_params, "hexstring", hextx);
    /*cJSON_AddBoolToObject(fund_params, "iswitness", false);*/

    cJSON *options = cJSON_AddObjectToObject(fund_params, "options");
    cJSON_AddNumberToObject(options, "changePosition", 1);
    cJSON_AddNumberToObject(options, "feeRate", ((float) fee)*1e-5);
    

    ret = rpc_call(rpcurl, "fundrawtransaction", fund_params, &json_out);
    cJSON_Delete(fund_params);
    free(hextx);

    if (ret) return 1;
    hextx = strdup(cJSON_GetObjectItem(json_out, "hex")->valuestring);
    cJSON_Delete(json_out);

    cJSON *sign_params = cJSON_CreateObject();
    cJSON_AddStringToObject(sign_params, "hexstring", hextx);

    ret = rpc_call(rpcurl, "signrawtransactionwithwallet", sign_params, &json_out);
    cJSON_Delete(sign_params);
    free(hextx);

    if (ret) return 1;
    hextx = strdup(cJSON_GetObjectItem(json_out, "hex")->valuestring);
    cJSON_Delete(json_out);


    int len = strlen(hextx)/2;
    unsigned char* tx_serialized = (unsigned char*) malloc(sizeof(unsigned char) * len);
    hextobin(tx_serialized, hextx, strlen(hextx));
    free(hextx);

    btc_tx_free(tail->tx);
    tail->tx = btc_tx_new();
    btc_tx_deserialize(tx_serialized, len, tail->tx, NULL, true);
    free(tx_serialized);

    // specify outpoint, set output script, sign tx input
    for (tx_chain_el *cur = tail->next; cur != NULL; cur = cur->next) {
        btc_tx_outpoint outpoint;
        outpoint.n = 0;
        btc_tx_hash(cur->prev->tx, outpoint.hash);
        btc_tx_in *linktx = (btc_tx_in*) vector_idx(cur->tx->vin, 0);
        linktx->prevout = outpoint;

        if (cur->next != NULL) {
            btc_tx_out *curout = (btc_tx_out*) vector_idx(cur->tx->vout, 0);
            curout->script_pubkey = cstr_new_sz(1024);
            btc_script_build_p2sh(curout->script_pubkey, redeem_script_hash);
        }

        sign_tx_in(cur, &privkey, &pubkey, redeem_script);
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

int construct_script(char *method_str, unsigned char **script, int *script_len, result_element *results, int results_num)
{
    if (results_num == 0) {
        return 0;
    }

    int adv;
    cstring *s = cstr_new_sz(32);
    if (strcmp(method_str, "p2pk") == 0) {
        btc_script_append_pushdata(s, results->hash, 33);
        btc_script_append_op(s, OP_CHECKSIG);
        adv = 1;
    } else if (strcmp(method_str, "p2pkh") == 0) {
        btc_script_build_p2pkh(s, results->hash);
        adv = 1;
    } else if (strcmp(method_str, "p2sh") == 0) {
        btc_script_build_p2sh(s, results->hash);
        adv = 1;
    } else if (strcmp(method_str, "p2ms") == 0) {
        adv = 3;
        if (results_num < adv) adv = results_num;
        enum opcodetype opcode;
        opcode = btc_encode_op_n(1);
        cstr_append_buf(s, &opcode, 1);
        for (int i = 0; i < adv; i++) {
            btc_script_append_pushdata(s, (results+i)->hash, 33);
        }
        opcode = btc_encode_op_n(adv);
        cstr_append_buf(s, &opcode, 1);
        btc_script_append_op(s, OP_CHECKMULTISIG);
    } else {
        *script = NULL;
        *script_len = 0;
        return 0;
    }

    *script_len = s->len;
    *script = (unsigned char*) malloc(sizeof(unsigned char) * s->len);
    memcpy(*script, s->str, s->len);

    cstr_free(s, true);
    return adv;
}

void usage(const char *name)
{
    fprintf(stderr,
"Usage: %s [-f <file>|-] [-F <fee>] [-R <rpcurl>]\n"
"\n"
"Parameters:\n"
"-f <file>|-            Read keypairs from specified JSON file. If \"-\" was specified,\n"
"                       data is read from standard input.\n"
"-F <fee>               Construct transaction with specified fee in sat/byte. Default\n"
"                       is 20 sat/byte\n"
"-R <rpcurl>            Use specified bitcoind deamon endpoint, in the form\n"
"                       http://user:password@ipaddr:port/\n"
"-h                     Prints this help text.\n", name);
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

    int scripts_num = 0;
    unsigned char *scripts[results_num]; // results_num as upper bound of #scripts
    int scripts_len[results_num];
    while (results_num > 0) {
        int i = construct_script(method_str, &scripts[scripts_num], &scripts_len[scripts_num], results, results_num);
        scripts_num++;
        results_num -= i;
        results += i;
    }

    cstring *s = cstr_new_sz(1024);
    tx_chain_el* tail = construct_txs(scripts, scripts_len, scripts_num, bits, data_size, fee);
    if (sign_tx_chain(tail, fee, rpcurl)) {
        return 1;
    }

    fprintf(stderr, "Generated transaction\n");
    for (tx_chain_el *el = tail; el != NULL; el = el->next) {
        btc_tx *tx = el->tx;
        cstr_resize(s, 0);
        btc_tx_serialize(s, tx, true);

        fdumphex(stdout, (unsigned char*) s->str, s->len);
        fprintf(stdout, "\n");
    }

}
