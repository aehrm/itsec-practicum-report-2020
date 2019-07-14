#include "hash_method.h"
#include "hash_engine.h"

#include <limits.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>
#include <cerrno>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>

#define BUFFER_SIZE 1024

void handler(int sig)
{
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}

unsigned char* read_file(FILE *f, int *size)
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

void usage(const char *name)
{
    fprintf(stderr,
"Usage: %s -s <strategy> [-X <strategy-option>] [-n <prefix-length>] [-f <file>|-] [-i <data>]\n"
"\n"
"Parameter:\n"
"-s <strategy>          Use specified Strategy to hide supplied data. One of \"p2pk\", \"p2pkh\",\n"
"                       \"p2sh\".\n"
"-X <strategy-option>   Supply additional options to specified strategy. Option string is in the\n"
"                       form <key>=<value>. Strategy \"p2sh\" is the only one accepting options,\n"
"                       and requires a 33-byte or 65-byte long public key via -Xpubkey=<hexstr>.\n"
"-n <prefix-length>     Use prefixes of specified bitlength.\n"
"-i <data>              Hide following data, interpreted literal.\n"
"-f <file>|-            Read data to hide from file. If \"-\" was specified, data is read from\n"
"                       standard input.\n", name);
}

int main(int argc, char *argv[])
{
    /*signal(SIGSEGV, handler);*/

    char *strategy = NULL;
    char *strategy_options[20] = {NULL};
    int strategy_options_num = 0;
    FILE *infile = NULL;
    char *instr = NULL;
    int bits = -1;


    int opt;
    while ((opt = getopt(argc, argv, ":h?:s:X:i:f:n:")) != -1) {
        switch (opt) {
            case 's':
                strategy = optarg;
                break;
            case 'X':
                strategy_options[2*strategy_options_num] = strtok(optarg, "=");
                strategy_options[2*strategy_options_num+1] = strtok(NULL, "=");
                strategy_options_num++;
                break;
            case 'i':
                instr = optarg;
                break;
            case 'f':
                if (strcmp(optarg, "-") == 0) {
                    infile = stdin;
                } else {
                    infile = fopen(optarg, "r");
                    if (!infile) {
                        fprintf(stderr,
                            "Could not open %s: %s\n",
                            optarg, strerror(errno));
                        return 1;
                    }
                }
                break;
            case 'n':
                bits = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (infile != NULL && instr != NULL) {
        fprintf(stderr, "Options -i and -f cannot be specified simultaneously.\n");
        return 1;
    }
    if (infile == NULL && instr == NULL) {
        fprintf(stderr, "One of -i <str> or -f <file> must be specified.\n");
        usage(argv[0]);
        return 1;
    }

    unsigned char *data;
    int data_size;

    if (infile != NULL) {
        data = read_file(infile, &data_size);
    } else {
        data = (unsigned char*) instr;
        data_size = strlen(instr);
    }

    hash_method *method;
    if (strcmp(strategy, "p2pk") == 0) {
        method = hash_method_p2pk();
        if (bits == -1) bits = 16;
    } else if (strcmp(strategy, "p2pkh") == 0) {
        method = hash_method_p2pkh();
        if (bits == -1) bits = 16;
    } else if (strcmp(strategy, "p2sh") == 0) {
        unsigned char* pubkey = NULL;
        int pubkey_len;
        for (int i = 0; i < strategy_options_num; i++) {
            if (strcmp(strategy_options[2*i], "pubkey") == 0) {
                char *hexstr = strategy_options[2*i+1];
                pubkey_len = strlen(hexstr)/2;
                pubkey = (unsigned char*) malloc(pubkey_len);

                for (int j = 0; j < pubkey_len; j++) {
                    sscanf(hexstr, "%2hhx", &pubkey[j]);
                    hexstr += 2;
                }

                break;
            }
        }

        if (pubkey == NULL) {
            fprintf(stderr, "Strategy p2sh requires strategy option \"pubkey\". Supply hex-encoded public key with option -Xpubkey=<hexstr>.\n");
            return 1;
        }

        if (pubkey_len != 33 && pubkey_len != 65) {
            fprintf(stderr, "Supplied public key needs to be 33 or 65 bytes long.\n");
            return 1;
        }

        method = hash_method_p2sh(pubkey, pubkey_len);
        if (bits == -1) bits = 24;
    } else {
        fprintf(stderr, "Option -s <strategy> must be specified. Available strategies are \"p2pk\", \"p2pkh\", \"p2sh\".\n");
        return 1;
    }

    hash_engine engine;
    hash_engine_init(&engine, method, data, data_size * 8, bits);
    hash_engine_run(&engine);

    fprintf(stderr, "\n");
    for (int i = 0; i < engine.results_num; i++) {
        result_element res = engine.results[i];
        printf("%s %s\n", res.hash_str, res.preimage_str);
    }
}
