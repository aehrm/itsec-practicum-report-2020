#ifndef __UTIL_H__
#define __UTIL_H__ 1

char* buftohex(unsigned char *src, int len);
int varint_size(int x);
int write_varint(int x, unsigned char* buf);
int util_construct_tx(unsigned char *scripts, int script_length, int script_num, unsigned char* buf);


#endif
