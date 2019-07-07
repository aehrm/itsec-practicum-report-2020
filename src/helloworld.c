typedef int int128_t __attribute__((mode(TI)));
typedef unsigned int uint128_t __attribute__((mode(TI)));

#include <limits.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>



#define USE_FIELD_5X52
#define USE_NUM_GMP
#define USE_FIELD_INV_NUM
#define USE_SCALAR_4X64
#define USE_SCALAR_INV_NUM
#define ECMULT_WINDOW_SIZE 24
#include "secp256k1.h"
#include "num.h"
#include "num_impl.h"
#include "num_gmp_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "hash_result.h"
#include "scalar_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"


void handler(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}


unsigned char* get_prefix(unsigned char *pubkey)
{
    return pubkey;
}

void bruteforce(result_container *container)
{ 
    container->hash_len = 32;
    container->preimage_len = 32;
    container->get_prefix = &get_prefix;

    secp256k1_scalar ONE;
    secp256k1_scalar_set_int(&ONE, 1);

    unsigned char b32[32];
    int j;

    unsigned long expected = container->results_num * (((unsigned long) 1) << (container->prefix_len * 8));

    int found_num = 0;
    int progress = 0;
    int last_print = 0;
    double starttime = omp_get_wtime();
    # pragma omp parallel for
    for (int i = 0; i < container->results_num; i++) {
        int this_thread = omp_get_thread_num();
        hash_result *res = container->results[i];
        unsigned char *prefix = res->prefix;

        secp256k1_scalar d;
        arc4random_buf(b32, sizeof b32);
        secp256k1_scalar_set_b32(&d, b32, NULL);
        
        secp256k1_gej point;
        secp256k1_ecmult_const(&point, &secp256k1_ge_const_g, &d, 256);

        secp256k1_ge r;
        unsigned char privkey[32], pubkey[32];

        printf("Starting thread %d\n", this_thread);

        for (unsigned long i = 0; ; i++) {
            secp256k1_ge_set_gej_var(&r, &point);
            secp256k1_fe_get_b32(pubkey, &(r.x));
            secp256k1_scalar_get_b32(privkey, &d);

            unsigned char* prefix_b = container->get_prefix(pubkey);
            int eq = 1;
            for (int i = 0; i < container->prefix_len; i++) {
                eq = (prefix[i] == prefix_b[i]);
                if (eq == 0) break;
            }

            if (eq) {
                found_num++;
                res->hash = (unsigned char*) malloc(container->hash_len * sizeof(unsigned char));
                memcpy(res->hash, pubkey, container->hash_len);
                res->preimage = (unsigned char*) malloc(container->preimage_len * sizeof(unsigned char));
                memcpy(res->preimage, privkey, container->preimage_len);
                break;
            }

            secp256k1_gej_add_ge(&point, &point, &secp256k1_ge_const_g);
            secp256k1_scalar_add(&d, &d, &ONE);

            #pragma omp atomic
            progress += 1;

            if (i>0 && i % 1000 == 0) {
                double now = omp_get_wtime();
                if (now - last_print > 1) {
                    float z = (now - starttime);
                    printf("\rHashrate: %.2fk/sec  Percentile of expected hashes: %.2f%%  Found %d/%d", progress/z/1000, (float) progress/expected*100, found_num, container->results_num);
                    fflush (stdout);
                    last_print = now;
                }
            }
        }
    }

    printf("\nTotal time: %.3fs\n", (double) (omp_get_wtime() - starttime));



}

int main(int argc, char *argv[])
{
    signal(SIGSEGV, handler);

    unsigned char data[100] = "Lorem ipsum dolor sit amet";
    result_container container;
    container.prefix_len = 3;
    container_init(&container, data, strlen((const char*) data));

    bruteforce(&container);

    printf("\n");
    for (int i = 0; i < container.results_num; i++) {
        hash_result *res = container.results[i];
        for (int j = 0; j < container.hash_len; j++) printf("%02X", res->hash[j]);
        printf(" ");
        for (int j = 0; j < container.preimage_len; j++) printf("%02X", res->preimage[j]);
        printf("\n");
    }
}
