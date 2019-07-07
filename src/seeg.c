#include <limits.h>
#include <string.h>
#include <omp.h>
#include <time.h>

#define USE_FIELD_10X26
#define USE_NUM_NONE
#define USE_FIELD_INV_BUILTIN
#include "secp256k1.h"
#include "field_impl.h"
#include "group_impl.h"

int main(int argc, char *argv[])
{
    secp256k1_fe ONE;
    secp256k1_fe_set_int(&ONE, 1);

    unsigned char b32[32];
    int j;

    unsigned const char data[32] = "rnd";
    int len = strlen((const char*)data);
    int expected = (1 << (len * 8));

    srand(time(NULL));
    secp256k1_fe startkey;
    for (j = 0; j < 32; j++) b32[j] = rand() & 0xFF;
    secp256k1_fe_set_b32(&startkey, b32);
    
    secp256k1_gej startpoint;
    secp256k1_gej_set_ge(&startpoint, &secp256k1_ge_const_g);

    int found = 0;
    secp256k1_fe privkey;
    secp256k1_ge pubkey;

    int progress = 0;
    time_t starttime = clock();

    # pragma omp parallel
    {

        unsigned char b32[32];
        int j;


        int num_threads = omp_get_num_threads();
        int this_thread = omp_get_thread_num();

        printf("Starting thread at %d with step %d\n", this_thread, num_threads);

        secp256k1_gej offset;
        secp256k1_gej_set_ge(&offset, &secp256k1_ge_const_g);
        for (j = 0; j < num_threads; j++) {
            secp256k1_gej_add_ge(&offset, &offset, &secp256k1_ge_const_g);
        }
        secp256k1_fe keyoffset;
        secp256k1_fe_set_int(&keyoffset, num_threads);

        secp256k1_fe d = startkey;
        secp256k1_gej point = startpoint;
        for (j = 0; j < this_thread; j++) {
            secp256k1_gej_add_ge(&point, &point, &secp256k1_ge_const_g);
            secp256k1_fe_add(&d, &ONE);
        }


        secp256k1_ge r;

        for (unsigned long i = 0; !found; i++) {
            secp256k1_ge_set_gej(&r, &point);

            /*# pragma omp critical
            {
            secp256k1_fe_get_b32(b32, &(r.x));
            printf("Thread %d: ", this_thread);
            for (j = 0; j < 32; j++) printf("%02X", b32[j]);
            printf(" ");
            secp256k1_fe_get_b32(b32, &d);
            for (j = 0; j < 32; j++) printf("%02X", b32[j]);
            printf("\n");
            }*/

            secp256k1_fe_get_b32(b32, &(r.x));
            int match = 1;
            for (int k = 0; k < len; k++) match = match && (b32[k] == data[k]);

            if (match) {
                found = 1;
                privkey = d;
                pubkey = r;
            }

            secp256k1_gej_add_var(&point, &point, &offset, NULL);
            secp256k1_fe_add(&d, &keyoffset);

            #pragma omp atomic
            progress += 1;

            if (i>0 && i % 10000 == 0) {

                if (this_thread == 0) {
                    time_t now = clock();
                    float z = (now - starttime)/CLOCKS_PER_SEC;
                    printf("\rHashrate: %.2fk/sec  Percentile of expected hashes: %.2f%%", progress/z/1000, (float) progress/expected*100);
                    fflush (stdout);
                }
            }
        }

    }

    printf("\nTarget prefix is: ");
    for (j = 0; j < len; j++) printf("%02X", data[j]);
    printf("\n");
    printf("Pubkey: ");
    printf("04 ");
    secp256k1_fe_get_b32(b32, &(pubkey.x));
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf(" ");
    secp256k1_fe_get_b32(b32, &(pubkey.y));
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf("\n");
    printf("Privkey: ");
    secp256k1_fe_get_b32(b32, &privkey);
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf("\n");


}

