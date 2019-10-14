#include "util.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>


void fdumphex(FILE *f, unsigned char *src, int len)
{
    for (int i = 0; i < len; i++) {
        fprintf(f, "%.2x", src[i]);
    }
}

void util_print_results(hash_engine *engine)
{
    fprintf(stderr, "Generated hash/preimage pairs\n");
    for (int i = 0; i < engine->results_num; i++) {
        result_element res = engine->results[i];
        fdumphex(stdout, res.hash, res.hash_len);
        fprintf(stdout, " ");
        fdumphex(stdout, res.preimage, res.preimage_len);
        fprintf(stdout, "\n");
    }

}
