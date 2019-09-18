#include "hash_engine_ocl.h"

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

hash_engine_ocl engine;
double ocl_starttime;
unsigned long ocl_progress;
unsigned long ocl_last_progress;
double ocl_last_print;

int vocp_test_func(vg_exec_context_t *vxcp) {
    // 1: found, rekey
    // 2: found, terminate
    // 0: no match
    
    double now = omp_get_wtime();
    if (now - ocl_last_print > 1) {
        print_statusline(engine.base, ocl_starttime, ocl_progress, ocl_last_print, ocl_last_progress);
        ocl_last_print = now;
        ocl_last_progress = ocl_progress;
    }

    return 0;
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
    signal(SIGSEGV, handler);

    char *strategy = NULL;
    char *strategy_options[20] = {NULL};
    int strategy_options_num = 0;
    FILE *infile = NULL;
    char *instr = NULL;
    int bits = -1;

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

    // TODO implement methods

    if (devstr != NULL) {
        hash_engine_ocl_init_from_devstr(&engine, devstr, safe_mode, verify_mode, data, data_size * 8, bits);
    } else {
        hash_engine_ocl_init(&engine, platformidx, deviceidx, safe_mode, verify_mode, worksize, nthreads, nrows, ncols, invsize, data, data_size * 8, bits);
    }

    ocl_starttime = omp_get_wtime();
    ocl_progress = 0;
    ocl_last_progress = 0;
    ocl_last_print = 0;
    if (!hash_engine_ocl_run(&engine, vocp_test_func)) {
        // TODO report error
        return 1;
    }

    fprintf(stderr, "\n");
    for (int i = 0; i < engine.base->results_num; i++) {
        result_element res = engine.base->results[i];
        printf("%s %s\n", res.hash_str, res.preimage_str);
    }
}
