#define TESTBIT(A,k)    ( A[((k)/8)] &  (1 <<  (7-(k)%8)) )
#define SETBIT(A,k)     ( A[((k)/8)] |= (1 <<  (7-(k)%8)) )
#define CLEARBIT(A,k)   ( A[((k)/8)] &= ~(1 << (7-(k)%8)) )

#include "util.h"
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

unsigned char * get_payload(btc_tx_out *out)
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
        default:
            fprintf(stderr, "warning: recognzied malformed output %s\n", btc_tx_out_type_to_str(type));
            return NULL;
    }

    return (unsigned char*) out->script_pubkey->str + offset;
    
}

int main(int argc, char *argv[])
{

    FILE *infile = NULL;
    if (argc < 2 || strcmp(argv[1], "-") == 0) {
        infile = stdin;
    } else {
        infile = fopen(argv[1], "r");
        if (!infile) {
            fprintf(stderr,
                "Could not open %s: %s\n",
                argv[1], strerror(errno));
            return 1;
        }
    }

    // collect tx
    vector *tx_chain_el_list = vector_new(1, NULL);

    char *line = NULL;
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
        btc_tx_deserialize((unsigned char*) txbuf->str, txbuf->len, el->tx, NULL, false);
        vector_add(tx_chain_el_list, el);
    }
    fclose(infile);
    fprintf(stderr, "Read %d transactions\n", tx_chain_el_list->len);

    // build graph
    uint256 tx_hashes[tx_chain_el_list->len];
    for (int i = 0; i < tx_chain_el_list->len; i++) {
        tx_chain_el *el = (tx_chain_el*) vector_idx(tx_chain_el_list, i);
        btc_tx_hash(el->tx, tx_hashes[i]);
    }

    tx_chain_el *head = NULL;
    for (int i = 0; i < tx_chain_el_list->len; i++) {
        tx_chain_el *el = (tx_chain_el*) vector_idx(tx_chain_el_list, i);

        if (el->tx->vin->len == 0) {
            if (head == NULL) {
                head = el;
                continue;
            } else {
                // more than one head? Hmm
                fprintf(stderr, "More than one head in tx chain found, aborting\n");
                return 1;
            }
        }

        uint256 backward_hash;
        btc_hash_set(backward_hash, (((btc_tx_in*) vector_idx(el->tx->vin, 0))->prevout).hash);
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
        } else {
            fprintf(stderr, "hmm..\n");
            // TODO notify
        }
    }

    int prefix_bits;
    int data_len;
    int tx_num;

    // verify header
    btc_tx_out *metadata = (btc_tx_out*) vector_idx(head->tx->vout, 0);
    unsigned char *data = (unsigned char*) metadata->script_pubkey->str + 2; // skipping OP_0 and pushdata byte
    if (metadata->script_pubkey->len < 17 || memcmp(data, "hidedata", 8) != 0) {
        fprintf(stderr, "Nonstandard header, aborting\n");
        return 1;
    }
    tx_num |=  data[8] & 0xFF;
    tx_num |= (data[9] & 0xFF) << 8;
    prefix_bits = data[10];
    data_len |=  data[11] & 0xFF;
    data_len |= (data[12] & 0xFF) << 8;
    data_len |= (data[13] & 0xFF) << 16;
    data_len |= (data[14] & 0xFF) << 24;

    fprintf(stderr, "tx num: %d, prefix bits: %d, data length: %d\n", tx_num, prefix_bits, data_len);


    // iterate over tx chain
    int tx_ctr = 0;
    int byte_ctr = 0;
    unsigned char carry = 0;
    int carry_pos = 0;
    for (tx_chain_el *cur = head->next; cur != NULL && tx_ctr <= tx_num; cur = cur->next) {
        tx_ctr++;
        int outnum = cur->tx->vout->len;
        if (cur->next != NULL) outnum--; // i.e. last output is link

        for (int i = 0; i < outnum; i++) {
            unsigned char *payload = get_payload((btc_tx_out*) vector_idx(cur->tx->vout, i));

            for (int byte = 0; byte*8 < prefix_bits; byte++) {
                carry &= ~(0xFF >> carry_pos);
                carry |= payload[byte] >> carry_pos;

                if (carry_pos + prefix_bits - byte*8 >= 8) {
                    fputc(carry, stdout);
                    byte_ctr++;
                    carry = payload[byte] << (8-carry_pos);
                }

                if (byte_ctr >= data_len) goto end;
            }

            carry_pos += prefix_bits%8;
            carry_pos %= 8;
        }
    }

end:

    if (tx_ctr < tx_num) {
        fprintf(stderr, "Premature end of tx chain\n");
        return 1;
    }

    if (byte_ctr < data_len) {
        fprintf(stderr, "Premature end of file\n");
        return 1;
    }

}
