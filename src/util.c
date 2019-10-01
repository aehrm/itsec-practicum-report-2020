#include "util.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

#define NONDUST 576

char* buftohex(unsigned char *src, int len)
{
    char buffer[2];
    char *string = (char*) malloc((2*len+1) * sizeof (char));
    for (int i = 0; i < len; i++) {
        sprintf(buffer, "%.2X", src[i]);
        memcpy(string+2*i, buffer, 2);
    }
    string[2*len] = '\0';
    return string;
}

tx_chain_el* util_construct_txs(unsigned char *scripts, int *scripts_length, int script_num, int prefix_len)
{
}
