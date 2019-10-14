#ifndef __UTIL_H__
#define __UTIL_H__ 1

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "hash_engine.h"

void fdumphex(FILE *f, unsigned char *src, int len);
void util_print_results(hash_engine *engine, char* method, int data_len, int prefix_len);


#endif
