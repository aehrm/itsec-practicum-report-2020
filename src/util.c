#include "util.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "cjson/cJSON.h"

#define BUFFER_SIZE 1024

void fdumphex(FILE *f, unsigned char *src, int len)
{
    for (int i = 0; i < len; i++) {
        fprintf(f, "%.2x", src[i]);
    }
}

char * bintohex(unsigned char* bin_in, size_t inlen)
{
    char * hex_out = (char*) malloc(sizeof(char) * (2*inlen + 1));
    static char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < inlen; i++) {
        hex_out[i * 2] = digits[(bin_in[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = digits[bin_in[i] & 0xF];
    }
    hex_out[inlen * 2] = '\0';

    return hex_out;
}

void hextobin(unsigned char* out, const char* str, int inLen)
{
    int bLen = inLen / 2;
    uint8_t c;
    int i;
    memset(out, 0, bLen);
    for (i = 0; i < bLen; i++) {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') {
            *out = (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') {
            *out = (10 + str[i * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') {
            *out = (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
            *out |= (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') {
            *out |= (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') {
            *out |= (10 + str[i * 2 + 1] - 'A');
        }
        out++;
    }
}

unsigned char* util_read_file(FILE *f, int *size)
{
    int result_size = 0;
    unsigned char* result = NULL;
    unsigned char buffer[BUFFER_SIZE];
    int read;

    while (!feof(f)) {
        read = fread(buffer, 1, BUFFER_SIZE, f);

        int new_size = result_size + read;
        result = (unsigned char*) realloc(result, new_size * sizeof(unsigned int));
        memcpy(result + result_size, buffer, read);
        result_size = new_size;
    }

    fclose(f);

    *size = result_size;
    return result;
}

void util_print_results(hash_engine *engine, char *method, int data_len, int prefix_len)
{
    cJSON *output = cJSON_CreateObject();
    cJSON *metadata = cJSON_AddObjectToObject(output, "metadata");
    cJSON_AddStringToObject(metadata, "method", method);
    cJSON_AddNumberToObject(metadata, "data_len", data_len);
    cJSON_AddNumberToObject(metadata, "prefix_len", data_len);

    cJSON *keypairs = cJSON_AddArrayToObject(output, "keypairs");

    for (int i = 0; i < engine->results_num; i++) {
        result_element res = engine->results[i];

        char *hash_str = bintohex(res.hash, res.hash_len);
        char *preimage_str = bintohex(res.preimage, res.preimage_len);

        char *strs[2];
        strs[0] = hash_str;
        strs[1] = preimage_str;
        cJSON *p = cJSON_CreateStringArray((const char**) strs, 2);
        cJSON_AddItemToArray(keypairs, p);

        free(hash_str); free(preimage_str);
    }

    fprintf(stderr, "Generated hash/preimage pairs\n");
    char *out = cJSON_Print(output);
    fprintf(stdout, "%s\n", out);
    free(out);

    cJSON_Delete(output);

}

void util_read_results(char *in, result_element **results, int *results_num, char **hash_method, int *data_size, int *bits)
{
    *results = NULL;

    cJSON *json = cJSON_Parse(in);
    cJSON *keypair, *keypairs, *method_str, *prefix_len_num, *data_len_num, *metadata;
    int i;

    if (json == NULL) {
        fprintf(stderr, "Parse error: %s\n", cJSON_GetErrorPtr());
        return;
    }

    metadata = cJSON_GetObjectItem(json, "metadata");
    if (!cJSON_IsObject(metadata)) goto structerr;

    method_str = cJSON_GetObjectItem(metadata, "method");
    if (!cJSON_IsString(method_str)) goto structerr;
    *hash_method = strdup(method_str->valuestring);

    data_len_num = cJSON_GetObjectItem(metadata, "data_len");
    if (!cJSON_IsNumber(data_len_num)) goto structerr;
    *data_size = data_len_num->valueint;

    prefix_len_num = cJSON_GetObjectItem(metadata, "prefix_len");
    if (!cJSON_IsNumber(prefix_len_num)) goto structerr;
    *bits = prefix_len_num->valueint;

    i = 0;
    keypairs = cJSON_GetObjectItem(json, "keypairs");

    *results_num = cJSON_GetArraySize(keypairs);
    *results = (result_element *) malloc(sizeof(result_element) * (*results_num));

    cJSON_ArrayForEach(keypair, keypairs)
    {
        if (!cJSON_IsArray(keypair)) goto structerr;
        if (!cJSON_IsString(cJSON_GetArrayItem(keypair, 0))) goto structerr;
        if (!cJSON_IsString(cJSON_GetArrayItem(keypair, 1))) goto structerr;

        result_element el;

        char * hash_hex = cJSON_GetArrayItem(keypair, 0)->valuestring;
        el.hash_len = strlen(hash_hex)/2;
        el.hash = (unsigned char*) malloc(sizeof(unsigned char) * el.hash_len);
        hextobin(el.hash, hash_hex, strlen(hash_hex));

        char * preimage_hex = cJSON_GetArrayItem(keypair, 1)->valuestring;
        el.preimage_len = strlen(preimage_hex)/2;
        el.preimage = (unsigned char*) malloc(sizeof(unsigned char) * el.preimage_len);
        hextobin(el.preimage, preimage_hex, strlen(preimage_hex));

        (*results)[i++] = el;
    }

    cJSON_Delete(json);
    return;

structerr:
    fprintf(stderr, "Wrong structure in input JSON\n");
    return;
}
