#ifndef __UTIL_H__
#define __UTIL_H__ 1

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "libbtc/include/btc/tx.h"

typedef struct tx_chain_el_ {
    btc_tx *tx;
    tx_chain_el_ *prev;
    tx_chain_el_ *next;
} tx_chain_el;

void fdumphex(FILE *f, unsigned char *src, int len);
tx_chain_el* util_construct_txs(unsigned char **scripts, int *scripts_len, int script_num, int prefix_len, int data_len, int fee);


#endif
