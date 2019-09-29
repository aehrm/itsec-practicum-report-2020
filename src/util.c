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

int varint_size(int x)
{
    if (x <= 0xFD) return 1;
    if (x <= 0xFFFF) return 3;
    return 5;
    /*if (x <= 0xFFFFFFFF) return 5;*/
    /*return 9;*/
}

int write_varint(int x, unsigned char* buf)
{
    if (x <= 0xFD) {
        buf[0] = (unsigned char) x;
        return 1;
    }

    if (x <= 0xFFFF) {
        buf[0] = 0xFD;
        buf[1] = (unsigned char) (0xFF & x);
        buf[2] = (unsigned char) (0xFF & (x >> 8));
        return 3;
    }

    /*if (x <= 0xFFFFFFFF) {*/
        buf[0] = 0xFE;
        buf[1] = (unsigned char) (0xFF & x);
        buf[2] = (unsigned char) (0xFF & (x >> 8));
        buf[3] = (unsigned char) (0xFF & (x >> 16));
        buf[4] = (unsigned char) (0xFF & (x >> 24));
        return 5;
    /*}*/

    /*buf[0] = 0xFF;
    buf[1] = (unsigned char) (0xFF & x);
    buf[2] = (unsigned char) (0xFF & (x >> 8));
    buf[3] = (unsigned char) (0xFF & (x >> 16));
    buf[4] = (unsigned char) (0xFF & (x >> 24));
    buf[5] = (unsigned char) (0xFF & (x >> 32));
    buf[6] = (unsigned char) (0xFF & (x >> 40));
    buf[7] = (unsigned char) (0xFF & (x >> 48));
    buf[8] = (unsigned char) (0xFF & (x >> 56));
    return 9;*/

}

int util_construct_tx(unsigned char *scripts, int script_length, int script_num, unsigned char* buf)
{
    int size = 4 // version
            + 1 // varint #inputs
            + varint_size(script_num) // varint #outputs
            + (8 + varint_size(script_length) + script_length) * script_num // n*txout
            + 4; // locktime

    if (buf == NULL) return size;

    // version
    buf[0] = 0x02;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf += 4;

    // varint #inputs
    buf[0] = 0x00;
    buf++;

    // varint #outputs
    buf += write_varint(script_num, buf);

    unsigned long long spent = NONDUST;

    for (int i = 0; i < script_num; i++) {
        buf[0] = (unsigned char) (0xFF &  spent);
        buf[1] = (unsigned char) (0xFF & (spent >> 8));
        buf[2] = (unsigned char) (0xFF & (spent >> 16));
        buf[3] = (unsigned char) (0xFF & (spent >> 24));
        buf[4] = (unsigned char) (0xFF & (spent >> 32));
        buf[5] = (unsigned char) (0xFF & (spent >> 40));
        buf[6] = (unsigned char) (0xFF & (spent >> 48));
        buf[7] = (unsigned char) (0xFF & (spent >> 56));

        buf += 8;
        // length of script
        buf += write_varint(script_length, buf);
        // script
        memcpy(buf, scripts + (script_length * i), script_length);
        buf += script_length;
    }

    // lock time
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    return size;
}
