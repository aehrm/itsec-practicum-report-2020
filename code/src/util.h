#ifndef __UTIL_H__
#define __UTIL_H__ 1

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "hash_engine.h"

void fdumphex(FILE *f, unsigned char *src, int len);
char * bintohex(unsigned char* bin_in, size_t inlen);
void hextobin(unsigned char* out, const char* str, int inLen);
unsigned char* util_read_file(FILE *f, int *size);
void util_print_results(hash_engine *engine, char* method, int data_len, int prefix_len);
void util_read_results(char *in, result_element **results, int *results_num, char **hash_method, int *data_size, int *bits);


#endif
