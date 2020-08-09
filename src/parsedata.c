#define TESTBIT(A,k)    ( A[((k)/8)] &  (1 <<  (7-(k)%8)) )
#define SETBIT(A,k)     ( A[((k)/8)] |= (1 <<  (7-(k)%8)) )
#define CLEARBIT(A,k)   ( A[((k)/8)] &= ~(1 << (7-(k)%8)) )

#include "util.h"
#include "rpc.h"
#include "libbtc/include/btc/utils.h"
#include "libbtc/include/btc/serialize.h"
#include "libbtc/include/btc/tx.h"
#include "libbtc/include/btc/cstr.h"
#include "libbtc/include/btc/script.h"
#include "libbtc/include/btc/vector.h"

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <math.h>

typedef struct tx_chain_el_ {
    btc_tx *tx;
    tx_chain_el_ *prev;
    tx_chain_el_ *next;
} tx_chain_el;

unsigned char ** get_payloads(btc_tx_out *out, int *payload_num)
{
    btc_tx_out_type type = btc_script_classify(out->script_pubkey, NULL);

    int offset;
    switch (type) {
        case BTC_TX_PUBKEY:
            offset = 2;
            break;
        case BTC_TX_PUBKEYHASH:
            offset = 3;
            break;
        case BTC_TX_SCRIPTHASH:
            offset = 2;
            break;
        case BTC_TX_MULTISIG:
            break;
        default:
            fprintf(stderr, "warning: recognzied malformed output %s\n", btc_tx_out_type_to_str(type));
            return NULL;
    }

    if (type != BTC_TX_MULTISIG) {
        unsigned char ** ret = (unsigned char**) malloc(sizeof(unsigned char*));
        ret[0] = (unsigned char*) out->script_pubkey->str + 2; //offset;
        *payload_num = 1;
        return ret;
    } else {
        vector* ops = vector_new(10, btc_script_op_free_cb);
        btc_script_get_ops(out->script_pubkey, ops);

        int addr_num = ((btc_script_op*) vector_idx(ops, ops->len - 2))->op - 0x50; // OP_1 == 0x51, OP_2 == 0x52, ...
        unsigned char ** ret = (unsigned char**) malloc(sizeof(unsigned char*) * addr_num);
        for (int i = 0; i < addr_num; i++) {
            ret[i] = ((btc_script_op*) vector_idx(ops, 1+i))->data + 1;
        }
        *payload_num = addr_num;
        return ret;
    }
}

int read_tx_list(tx_chain_el **head_out, FILE *infile)
{
    tx_chain_el *head = NULL;

    // collect tx
    vector *tx_chain_el_list = vector_new(1, NULL);

    char *line = NULL;
    int lineno = 1;
    size_t len = 0;
    ssize_t read;
    char *strpos = NULL;
    unsigned char tmp;
    while ((read = getline(&line, &len, infile)) != -1) {
        cstring *txbuf = cstr_new_sz(len/2);
        for (int i = 0; i < len; i += 2) {
            sscanf(line+i, "%2hhx", &tmp);
            cstr_append_buf(txbuf, &tmp, 1);
        }

        tx_chain_el *el = (tx_chain_el*) malloc(sizeof(tx_chain_el));
        el->tx = btc_tx_new();
        if (!btc_tx_deserialize((unsigned char*) txbuf->str, txbuf->len, el->tx, NULL, true)) {
            fprintf(stderr, "Could not deserialize tx in line %d, aborting\n", lineno);
            return 1;
        }
        vector_add(tx_chain_el_list, el);
        lineno++;
    }
    fclose(infile);
    fprintf(stderr, "Read %d transactions\n", tx_chain_el_list->len);

    // build graph
    uint256 tx_hashes[tx_chain_el_list->len];
    for (int i = 0; i < tx_chain_el_list->len; i++) {
        tx_chain_el *el = (tx_chain_el*) vector_idx(tx_chain_el_list, i);
        btc_tx_hash(el->tx, tx_hashes[i]);
    }

    for (int i = 0; i < tx_chain_el_list->len; i++) {
        tx_chain_el *el = (tx_chain_el*) vector_idx(tx_chain_el_list, i);

        // test for metadata
        btc_tx_out *metadata = (btc_tx_out*) vector_idx(el->tx->vout, 0);
        unsigned char *data = (unsigned char*) metadata->script_pubkey->str + 2; // skipping OP_0 and pushdata byte
        if (metadata->script_pubkey->len >= 17 && memcmp(data, "hidedata", 8) == 0) {
            if (head == NULL) {
                head = el;
            } else {
                // more than one head? Hmm
                fprintf(stderr, "More than one metadata tx in tx chain found, aborting\n");
                return 1;
            }
        }

        uint256 backward_hash;
        btc_tx_outpoint *prevout = (btc_tx_outpoint*) vector_idx(el->tx->vin, 0);
        btc_hash_set(backward_hash, prevout->hash);
        tx_chain_el *pred = NULL;
        for (int j = 0; j < tx_chain_el_list->len; j++) {
            if (btc_hash_equal(tx_hashes[j], backward_hash)) {
                pred = (tx_chain_el*) vector_idx(tx_chain_el_list, j);
                break;
            }
        }

        if (pred != NULL) {
            el->prev = pred;
            pred->next = el;
        }
    }

    if (head == NULL) return 1;

    *head_out = head;

    return 0;
}

typedef struct {
    int prefix_bits;
    int data_len;
    int tx_num;
} tx_chain_metadata;

int read_tx_chain_metadata(btc_tx *head_tx, tx_chain_metadata *meta)
{
    meta->tx_num = 0;
    meta->data_len = 0;
    meta->prefix_bits = 0;

    btc_tx_out *metadata = (btc_tx_out*) vector_idx(head_tx->vout, 0);
    unsigned char *data = (unsigned char*) metadata->script_pubkey->str + 2; // skipping OP_0 and pushdata byte
    meta->tx_num |=  data[8] & 0xFF;
    meta->tx_num |= (data[9] & 0xFF) << 8;
    meta->prefix_bits = data[10];
    meta->data_len |=  data[11] & 0xFF;
    meta->data_len |= (data[12] & 0xFF) << 8;
    meta->data_len |= (data[13] & 0xFF) << 16;
    meta->data_len |= (data[14] & 0xFF) << 24;
    fprintf(stderr, "tx num: %d, prefix bits: %d, data length: %d\n", meta->tx_num, meta->prefix_bits, meta->data_len);

    return 0;
}

int tx_chain_write_payload(tx_chain_el *head, tx_chain_metadata *meta, FILE *output)
{
    // iterate over tx chain
    int tx_ctr = 0;
    int byte_ctr = 0;
    unsigned char carry = 0;
    int carry_pos = 0;
    for (tx_chain_el *cur = head->prev; cur != NULL && tx_ctr <= meta->tx_num; cur = cur->prev) {
        tx_ctr++;
        int outnum = cur->tx->vout->len;

        for (int i = 1; i < outnum; i++) { // first output is link
            int payload_num;
            unsigned char ** payloads = get_payloads((btc_tx_out*) vector_idx(cur->tx->vout, i), &payload_num);
            for (int j = 0; j < payload_num; j++) {
                for (int byte = 0; byte*8 < meta->prefix_bits; byte++) {
                    carry &= ~(0xFF >> carry_pos);
                    carry |= payloads[j][byte] >> carry_pos;

                    if (carry_pos + meta->prefix_bits - byte*8 >= 8) {
                        fputc(carry, output);
                        byte_ctr++;
                        carry = payloads[j][byte] << (8-carry_pos);
                    }

                    if (byte_ctr >= meta->data_len) goto end;
                }
            }
            free(payloads);

            carry_pos += meta->prefix_bits%8;
            carry_pos %= 8;
        }
    }

end:

    if (tx_ctr < meta->tx_num) {
        fprintf(stderr, "warning: premature end of tx chain; expected %d data tx, got %d\n", tx_ctr, meta->tx_num);
        return 1;
    }

    if (byte_ctr < meta->data_len) {
        fprintf(stderr, "warning: premature end of file; expected %d bytes, got %d\n", byte_ctr, meta->data_len);
        return 1;
    }

    return 0;
}

char * uint256tostr(uint256 hash)
{
    uint256 hash_reversed;
    for (int i = 0; i < 32; i++) hash_reversed[i] = hash[31-i];

    return bintohex(hash_reversed, 32);
}

int fetch_tx(char *rpcurl, uint256 txhash, btc_tx *tx)
{
    char *txid_str = uint256tostr(txhash);

    fprintf(stderr, "fetching %s\n", txid_str);
    cJSON *sign_params = cJSON_CreateObject();
    cJSON_AddStringToObject(sign_params, "txid", txid_str);

    cJSON *json_out;
    int ret = rpc_call(rpcurl, "getrawtransaction", sign_params, &json_out);
    cJSON_Delete(sign_params);
    free(txid_str);

    if (ret) return 1;

    char *hextx = json_out->valuestring;

    int len = strlen(hextx)/2;
    unsigned char* tx_serialized = (unsigned char*) malloc(sizeof(unsigned char) * len);
    hextobin(tx_serialized, hextx, strlen(hextx));
    if (!btc_tx_deserialize(tx_serialized, len, tx, NULL, true)) {
        fprintf(stderr, "Could not deserialize tx, aborting\n");
        return 1;
    }

    free(tx_serialized);
    cJSON_Delete(json_out);

    return 0;
}

int fetch_tx_list(char *rpcurl, tx_chain_el **head_out, tx_chain_metadata *meta, uint256 head_tx_hash)
{
    btc_tx *head_tx = btc_tx_new();
    if (fetch_tx(rpcurl, head_tx_hash, head_tx)) {
        fprintf(stderr, "Head tx with hash %s could not be found, aborting\n", uint256tostr(head_tx_hash));
        return 1;
    }

    if (read_tx_chain_metadata(head_tx, meta))
        return 1;

    tx_chain_el* head = (tx_chain_el*) malloc(sizeof(tx_chain_el));
    head->tx = head_tx;

    tx_chain_el *cur = head;
    uint256 cur_tx_hash;
    tx_chain_el *prev;
    for (int i = 0; i < meta->tx_num; i++) {
        btc_tx_hash(cur->tx, cur_tx_hash);
        prev = (tx_chain_el*) malloc(sizeof(tx_chain_el));
        prev->next = cur;
        prev->tx = btc_tx_new();

        uint256 backward_hash;
        btc_tx_outpoint *prevout = (btc_tx_outpoint*) vector_idx(cur->tx->vin, 0);
        btc_hash_set(backward_hash, prevout->hash);

        if (fetch_tx(rpcurl, backward_hash, prev->tx)) {
            fprintf(stderr, "warning: descendant of tx with hash %s could not be found\n", uint256tostr(cur_tx_hash));

            return 2;
        } else {
            cur->prev = prev;
            cur = prev;
        }
    }
    
    *head_out = head;
    return 0;
}
        

void usage(const char *name)
{
    fprintf(stderr,
"Usage: %s [-f <file>|-] [-r <txhash>] [-R <rpcurl>]\n"
"\n"
"Parameter:\n"
"-f <file>|-            Offline mode. Read transactions from file, line by line.\n"
"                       If \"-\" was specified, data is read from standard input.\n"
"-r <txhash>            Online mode. Communicates with the bitcoind RPC daemon.\n"
"                       Extracts data starting with specified head tx, successively\n"
"                       fetching relevant tx's from the deamon.\n"
"-R <rpcurl>            Use specified bitcoind deamon endpoint, in the form\n"
"                       http://user:password@ipaddr:port/\n", name);
}

int main(int argc, char *argv[])
{
    char *rpcurl = "http://127.0.0.1:8332/";
    FILE *infile = NULL;
    char *headtxhash = NULL;

    int opt;
    while ((opt = getopt(argc, argv, ":h?:f:r:R:")) != -1) {
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
            case 'r':
                headtxhash = optarg;
                break;
            case 'R':
                rpcurl = optarg;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (infile != NULL) {

        tx_chain_el *head;
        if (read_tx_list(&head, infile))
            return 1;

        tx_chain_metadata chain_metadata;
        if (read_tx_chain_metadata(head->tx, &chain_metadata))
            return 1;

        if (tx_chain_write_payload(head, &chain_metadata, stdout))
            return 1;

    } else if (headtxhash != NULL) {

        int outlen;
        uint256 txhash_reversed;
        uint256 txhash;
        if (strlen(headtxhash) != 64) {
            fprintf(stderr, "Specified tx hash is not a valid 64-character long hex string, aborting\n");
            return 1;
        }
        utils_hex_to_bin(headtxhash, txhash_reversed, 64, &outlen);
        // reverse hash
        for (int i = 0; i < 32; i++) txhash[i] = txhash_reversed[31-i];


        tx_chain_metadata chain_metadata;
        tx_chain_el *head;
        if (fetch_tx_list(rpcurl, &head, &chain_metadata, txhash))
            return 1;

        if (tx_chain_write_payload(head, &chain_metadata, stdout))
            return 1;

    } else {
        fprintf(stderr, "One of -f or -r must be specified");
        usage(argv[0]);
        return 1;
    }

}
