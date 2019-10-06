#include "util.h"
#include "hash_method.h"
#include "hash_engine.h"
#include "hash_engine_ocl.h"

#include <limits.h>
#include <string.h>
#include <time.h>
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

hash_engine_ocl *ocl_engine;

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
    int bits = 24;
    int fee = 20;

    int platformidx = -1;
    int deviceidx = -1;
    int verify_mode = 0;
    int safe_mode = 0;
    int nthreads = 0;
    int worksize = 0;
    int nrows = 0, ncols = 0;
    int invsize = 0;
    char *devstr;

    int opt;
    // TODO VG parameters
    while ((opt = getopt(argc, argv, ":h?:i:f:n:")) != -1) {
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


    // TODO implement methods
    hash_method *method = hash_method_p2pkh();
    ocl_engine = (hash_engine_ocl*) malloc(sizeof(hash_engine_ocl));

    if (devstr != NULL) {
        hash_engine_ocl_init_from_devstr(ocl_engine, devstr, safe_mode, verify_mode, data, data_size * 8, bits);
    } else {
        hash_engine_ocl_init(ocl_engine, platformidx, deviceidx, safe_mode, verify_mode, worksize, nthreads, nrows, ncols, invsize, data, data_size * 8, bits);
    }

    if (!hash_engine_ocl_run(ocl_engine)) {
        // TODO report error
        return 1;
    }

    fprintf(stderr, "\n");
    util_print_results(ocl_engine->base);
    util_print_txs(ocl_engine->base, method, bits, data_size, fee);
}

int vcp_test_func(vg_exec_context_t *vxcp)
{
    // 1: found, rekey
    // 2: found, terminate
    // 0: no match

    int ret = 0;

    unsigned char *hash = vxcp->vxc_binres + 1;
    result_element *node = hash_engine_search(ocl_engine->base, hash, 8*20);
    if (node != NULL) {
        ret = 1;
        rb_tree_remove(ocl_engine->base->rb_tree, node);

        node->hash_len = 20;
        node->hash = (unsigned char*) malloc(20 * sizeof(unsigned char));
        memcpy(node->hash, hash, 20);

        node->preimage = (unsigned char*) malloc(32 * sizeof(unsigned char));
        node->preimage_len = BN_bn2bin(EC_KEY_get0_private_key(vxcp->vxc_key), node->preimage);

        vxcp->vxc_vc->vc_pattern_generation++;
    }

    if (rb_tree_size(ocl_engine->base->rb_tree) == 0)
        ret = 2;

    return ret;
}

int vcp_hash160_sort_func(vg_context_t *vcp, void *buf)
{
    unsigned char *cbuf = (unsigned char *) buf;
    int npfx = 0;

    struct rb_tree *tree = ocl_engine->base->rb_tree;
    struct rb_iter *iter = rb_iter_create();
    if (!iter) return 0;


    for (result_element *re = (result_element*) rb_iter_first(iter, tree); re; re = (result_element*) rb_iter_next(iter)) {
        npfx++;
        if (!buf) continue;

        unsigned char *data = re->prefix;
        memset(cbuf, 0, 20);
        for (int i = 0; i <= re->prefix_bits; i++) {
            if (TESTBIT(data, i)) SETBIT(cbuf, i);
        }
        cbuf += 20;

        memset(cbuf, 255, 20);
        for (int i = 0; i <= re->prefix_bits; i++) {
            if (!TESTBIT(data, i)) CLEARBIT(cbuf, i);
        }
        cbuf += 20;

    }
    rb_iter_dealloc(iter);


    return npfx;
}

void vcp_timing_func(vg_context_t *vcp, double count, unsigned long long rate, unsigned long long total)
{
    print_statusline(ocl_engine->base, total, (double) rate);
}
