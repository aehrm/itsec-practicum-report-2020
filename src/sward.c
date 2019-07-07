#define USE_FIELD_10X26
#define USE_NUM_NONE
#define USE_FIELD_INV_BUILTIN
#include "secp256k1.h"
#include "field_impl.h"
#include "group_impl.h"

int main(int argc, char *argv[])
{
    unsigned char data[32] = "Lorem ipsum dolor sit amet abcd";
    data[32] = 0;

    unsigned char b32[32];
    int j;


    secp256k1_fe one;
    secp256k1_fe_set_int(&one, 1);

    printf("%s\n", &data);
    secp256k1_fe x;
    secp256k1_fe_clear(&x);
    secp256k1_fe_set_b32(&x, data);


    secp256k1_fe y;
    int found = 0;

    for (int i = 0; i < 256; i++) {


        printf("For x=");
        secp256k1_fe_get_b32(b32, &x);
        for (j = 0; j < 32; j++) printf("%02X", b32[j]);
        printf(" is\nx^3+7=");

        secp256k1_fe x2, x3, c;
        secp256k1_fe_sqr(&x2, &x);
        secp256k1_fe_mul(&x3, &x, &x2);
        secp256k1_fe_set_int(&c, CURVE_B);
        secp256k1_fe_add(&c, &x3);


        secp256k1_fe_get_b32(b32, &c);
        for (j = 0; j < 32; j++) printf("%02X", b32[j]);
        printf(" ");

        if (secp256k1_fe_sqrt(&y, &c)) {
            printf("quadratic residual\n\n");
            found = 1;
            break;
        } else {
            printf("no quadratic residual\n");
        }

        secp256k1_fe_add(&x, &one);
    }

    if (!found) {
        return 1;
    }

    printf("04 ");
    secp256k1_fe_get_b32(b32, &x);
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf(" ");
    secp256k1_fe_get_b32(b32, &y);
    for (j = 0; j < 32; j++) printf("%02X", b32[j]);
    printf(" is a point in secp256k1\n");

    secp256k1_ge point;
    secp256k1_ge_set_xy(&point, &x, &y);

    printf("secp256k1_ge_is_valid_var = %d\n", secp256k1_ge_is_valid_var(&point));

    return 0;

}

