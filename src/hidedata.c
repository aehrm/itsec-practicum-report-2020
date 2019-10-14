#include "hash_method.h"
#include "hash_engine.h"
#include "util.h"
#include "libbtc/include/btc/tx.h"

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

int hash_engine_run(hash_engine *engine, hash_method *method)
{
    fprintf(stderr, "Starting engine\n");

    unsigned long progress = 0;
    unsigned long last_progress = 0;
    unsigned long last_found = 0;
    double last_print = 0;
    double starttime = omp_get_wtime();
    double stop = false;
    # pragma omp parallel
    {
        fprintf(stderr, "Starting thread %d\n", omp_get_thread_num());

        int prefix_bits = hash_method_max_prefix_bits(method);
        int prefix_bytes = (int) ceil((double) prefix_bits/8);
        int batch_size = hash_method_batch_size(method);
        unsigned char *prefix_container = (unsigned char*) calloc(batch_size * prefix_bytes, sizeof(unsigned char));
        unsigned char *prefixes[batch_size];
        for (int i = 0; i < batch_size; i++)
            prefixes[i] = prefix_container + i * prefix_bytes;

        hash_context *hash_ctx = hash_context_alloc(method);
        hash_context_rekey(method, hash_ctx);
        hash_context_next_result(method, hash_ctx);

        while (!stop && rb_tree_size(engine->rb_tree) > 0) {
            hash_context_get_prefixes(method, hash_ctx, prefix_bits, prefixes);

            # pragma omp critical
            {
                for (int i = 0; i < batch_size; i++) {
                    result_element *node = hash_engine_search(engine, prefixes[i], prefix_bits);
                    progress++;

                    if (node != NULL) {
                        hash_context_write_result(method, hash_ctx, i, node);
                        hash_context_rekey(method, hash_ctx);

                        rb_tree_remove(engine->rb_tree, node);
                        break;
                    }
                }
            }

            if (hash_context_next_result(method, hash_ctx) == 0) {
                stop = true;
                break; // TODO notify threads
            }

            double now = omp_get_wtime();
            if (now - last_print > 1) {
                int found = engine->results_num - rb_tree_size(engine->rb_tree);
                double delta = now - last_print;
                double hashrate = (double) (progress - last_progress)/delta;
                double foundrate = (double) (found - last_found)/delta;
                print_statusline(engine, progress, hashrate, foundrate);
                last_print = now;
                last_progress = progress;
                last_found = found;
            }
        }
    }

    return 1;
}

void usage(const char *name)
{
    fprintf(stderr,
"Usage: %s -s <strategy> [-X <strategy-option>] [-n <prefix-length>] [-F <fee>] [-f <file>|-] [-i <data>]\n"
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
"                       standard input.\n"
"-F <fee>               Use <fee> sat/B as transaction fee.\n", name);
}

int main(int argc, char *argv[])
{
    signal(SIGSEGV, handler);

    char *strategy = NULL;
    char *strategy_options[20] = {NULL};
    int strategy_options_num = 0;
    FILE *infile = NULL;
    char *instr = NULL;
    int bits = -1;
    int fee = 20;


    int opt;
    while ((opt = getopt(argc, argv, ":h?:s:X:i:f:n:F:")) != -1) {
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
            case 'F':
                fee = atoi(optarg);
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

    hash_method *method = NULL;
    if (strategy == NULL) {
        // break
    } else if (strcmp(strategy, "p2pk") == 0) {
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
    }
    
    if (method == NULL) {
        fprintf(stderr, "Option -s <strategy> must be specified. Available strategies are \"p2pk\", \"p2pkh\", \"p2sh\".\n");
        return 1;
    }

    if (bits > hash_method_max_prefix_bits(method)) {
        fprintf(stderr, "Prefix too long. Method supports prefix no longer than %d bits.\n", hash_method_max_prefix_bits(method));
        return 1;
    }

    hash_engine engine;
    hash_engine_init(&engine, data, data_size * 8, bits);
    hash_engine_run(&engine, method);

    fprintf(stderr, "\n");
    util_print_results(&engine);
    util_print_txs(&engine, method, bits, data_size, fee);


}

