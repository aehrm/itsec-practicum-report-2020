#include "hash_method.h"
#include "hash_engine.h"

#include <limits.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <unistd.h>
#include <math.h>

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

int main(int argc, char *argv[])
{
    signal(SIGSEGV, handler);

    unsigned char data[100] = "Lorem ipsum dolor sit amet";
    hash_engine engine;
    hash_engine_init(&engine, &hash_method_p2pk, data, strlen((const char*) data)*8, 24);
    hash_engine_run(&engine);

    printf("\n");
    for (int i = 0; i < engine.results_num; i++) {
        result_element res = engine.results[i];
        printf("%s %s\n", res.hash_str, res.preimage_str);
    }
}
