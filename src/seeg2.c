#include <limits.h>
#include <string.h>
#include <omp.h>
#include <time.h>

#define USE_FIELD_10X26
#define USE_NUM_NONE
#define USE_FIELD_INV_BUILTIN
#define USE_SCALAR_8X32
#define USE_SCALAR_INV_BUILTIN
#define ECMULT_WINDOW_SIZE 24
#include "secp256k1.h"
#include "scratch_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "scalar_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"

int main(int argc, char *argv[])
{

    unsigned char b32[32];
    int j;

    unsigned const char data[32] = "Eth";
    int len = strlen((const char*)data);

    printf("Target prefix is: ");
    for (j = 0; j < len; j++) printf("%02X", data[j]);
    printf("\n");

    unsigned long d = 1;
    int found = 0;
    int privkey;
    secp256k1_ge pubkey;

    int progress = 0;
    time_t starttime = clock();

    secp256k1_gej point;
    secp256k1_gej_set_ge(&point, &secp256k1_ge_const_g);
    secp256k1_ge r;
    secp256k1_scalar sc;

    for (unsigned long i = 0; i < UINT_MAX; i++) {
        secp256k1_ge_set_gej(&r, &point);
        secp256k1_fe_get_b32(b32, &(r.x));


        /*for (j = 0; j < 32; j++) printf("%02X", b32[j]);*/
        /*printf(" %d\n", d);*/

        int match = 1;
        for (int k = 0; k < len; k++) match = match && (b32[k] == data[k]);

        if (match) {
            found = 1;
            privkey = d;
            pubkey = r;
        }

        if (found) break;

        progress++;
        d += 1;
        secp256k1_scalar_set_int(&sc, d);
        secp256k1_ecmult_const(&point, &secp256k1_ge_const_g, &sc, 256);

        if (i>0 && i % 1000 == 0) {
            time_t now = clock();
            float z = (now - starttime)/CLOCKS_PER_SEC;
            printf("\rHashrate: %.2fk/sec  Progress: %.2e", progress/z/1000, (float) progress);
            fflush (stdout);
        }
    }

    printf("\nTarget prefix is: ");
    for (j = 0; j < len; j++) printf("%02X", data[j]);
    printf("\n");
    printf("Privkey: %d\n", privkey);
    printf("Pubkey: ");
    printf("04 ");
    secp256k1_fe_get_b32(b32, &(pubkey.x));
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf(" ");
    secp256k1_fe_get_b32(b32, &(pubkey.y));
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf("\n");


}

