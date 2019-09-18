#include "hash_engine.h"
#include "hash_engine_ocl.h"

#include "vanitygen/oclengine.c"

#include <cstring>


void vg_drop_timing_fn(vg_context_t *vcp, double count, unsigned long long rate, unsigned long long total)
{
}

vg_context_t* vg_context_new()
{
    vg_context_t *vcp = NULL;

    vcp = (vg_context_t *) malloc(sizeof(*vcp));
    memset(vcp, 0, sizeof(*vcp));
    vcp->vc_addrtype = 0;
    vcp->vc_privtype = 128;
    vcp->vc_npatterns = 0;
    vcp->vc_npatterns_start = 0;
    vcp->vc_found = 0;
    vcp->vc_chance = 0.0;
    vcp->vc_free = NULL;
    vcp->vc_add_patterns = NULL;
    vcp->vc_clear_all_patterns = NULL;
    /*vcp->vc_test = vocp_test_func;*/
    vcp->vc_hash160_sort = NULL;
    vcp->vc_verbose = 2;
    vcp->vc_result_file = NULL;
    vcp->vc_remove_on_match = 0;
    vcp->vc_only_one = 0;
    vcp->vc_pubkeytype = 0;
    vcp->vc_pubkey_base = NULL;
    vcp->vc_output_timing = vg_drop_timing_fn;

    return vcp;
}

int hash_engine_ocl_init_from_devstr(hash_engine_ocl *engine, char *devstr, int safe_mode, int verify, unsigned char *data, int data_bits, int prefix_bits)
{
    vg_context_t *vcp = vg_context_new();
    vg_ocl_context_t *vocp = vg_ocl_context_new_from_devstr(vcp, devstr, safe_mode, verify);

    if (!vocp) {
		vg_ocl_enumerate_devices();
		return 0;
    }

    engine->base = (hash_engine*) malloc(sizeof (hash_engine));
    hash_engine_init(engine->base, data, data_bits, prefix_bits);
    engine->vocp = vocp;

    return 1;
}

int hash_engine_ocl_init(hash_engine_ocl *engine,
    int platformidx, int deviceidx,
	int safe_mode, int verify,
	int worksize, int nthreads, int nrows, int ncols,
	int invsize,
    unsigned char *data, int data_bits, int prefix_bits)
{
    vg_context_t *vcp = vg_context_new();
    vg_ocl_context_t *vocp = vg_ocl_context_new(vcp, platformidx, deviceidx, safe_mode, verify, worksize, nthreads, nrows, ncols, invsize);

    if (!vocp) {
		vg_ocl_enumerate_devices();
		return 0;
    }

    engine->base = (hash_engine*) malloc(sizeof (hash_engine));
    hash_engine_init(engine->base, data, data_bits, prefix_bits);
    engine->vocp = vocp;

    return 1;
}

int hash_engine_ocl_run(hash_engine_ocl *engine, vg_test_func_t test_func)
{
    vg_ocl_context_t *vocp = engine->vocp;
    vg_context_t *vcp = vocp->base.vxc_vc;
    vcp->vc_test = test_func;

    if (vg_context_start_threads(vcp))
        return 0;

    vg_context_wait_for_completion(vcp);
    vg_ocl_context_free(vocp);

    return 1;
}
