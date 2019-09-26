#ifndef __HASH_ENGINE_OCL_H__
#define __HASH_ENGINE_OCL_H__ 1

#include "hash_engine.h"
#include "vanitygen/oclengine.h"
#include "vanitygen/pattern.h"
#include "vanitygen/util.h"

typedef struct {
    hash_engine *base;
    vg_ocl_context_t *vocp;
    // TODO strategy
} hash_engine_ocl;

int hash_engine_ocl_init_from_devstr(hash_engine_ocl *engine, char *devstr, int safe_mode, int verify, unsigned char *data, int data_bits, int prefix_bits);
int hash_engine_ocl_init(hash_engine_ocl *engine,
    int platformidx, int deviceidx,
	int safe_mode, int verify,
	int worksize, int nthreads, int nrows, int ncols,
	int invsize,
    unsigned char *data, int data_bits, int prefix_bits);
int hash_engine_ocl_run(hash_engine_ocl *engine);

int vcp_test_func(vg_exec_context_t *vxcp);
int vcp_hash160_sort_func(vg_context_t *vcp, void *buf);
void vcp_timing_func(vg_context_t *vcp, double count, unsigned long long rate, unsigned long long total);


#endif
