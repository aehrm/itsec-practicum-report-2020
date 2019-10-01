#ifndef __UTIL_H__
#define __UTIL_H__ 1

typedef struct {
    int len;
    unsigned char *tx;
    tx_chain_el *prev;
    tx_chain_el *next;
} tx_chain_el;

char* buftohex(unsigned char *src, int len);
tx_chain_el* util_construct_txs(unsigned char *scripts, int *scripts_length, int script_num)


#endif
