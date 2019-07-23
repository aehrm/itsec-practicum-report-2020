#define TESTBIT(A,k)    ( A[((k)/8)] &  (1 <<  ((k)%8)) )
#define SETBIT(A,k)     ( A[((k)/8)] |= (1 <<  ((k)%8)) )
#define CLEARBIT(A,k)   ( A[((k)/8)] &= ~(1 << ((k)%8)) )

#include "hash_engine.h"
#include "secp256k1.h"
#include <math.h>
#include <sys/param.h>
#include <omp.h>

int result_el_rb_insert_cmp(rb_tree *tree, rb_node *node_a, rb_node *node_b) {
    int ret;
    result_element *result_a = (result_element*) node_a->value;
    result_element *result_b = (result_element*) node_b->value;

    if (result_a == result_b) return 0;
    
    int prefix_bits = MIN(result_a->prefix_bits, result_b->prefix_bits);
    for (int i = 0; i < prefix_bits; i++) {
        ret = (TESTBIT(result_a->prefix, i) != 0) - (TESTBIT(result_b->prefix, i) != 0);
        if (ret != 0) return ret;
    }

    ret = (result_a->prefix_bits > result_b->prefix_bits) - (result_a->prefix_bits < result_b->prefix_bits);
    if (ret != 0)
        return ret;
    else
        return 1;
}

int result_el_rb_test_cmp(rb_tree *tree, rb_node *node_a, rb_node *node_b) {
    int ret;
    result_element *result_a = (result_element*) node_a->value;
    result_element *result_b = (result_element*) node_b->value;

    int prefix_bits = MIN(result_a->prefix_bits, result_b->prefix_bits);
    for (int i = 0; i < prefix_bits; i++) {
        ret = (TESTBIT(result_a->prefix, i) != 0) - (TESTBIT(result_b->prefix, i) != 0);
        if (ret != 0) return ret;
    }

    return 0;
}

void hash_engine_init(hash_engine *engine, hash_method *method, unsigned char *data, int data_bits, int prefix_bits)
{
    engine->method = method;
    engine->results_num = ceil((double) data_bits / prefix_bits);
    engine->results = (result_element*) malloc(engine->results_num * sizeof(result_element));
    engine->rb_tree = rb_tree_create(&result_el_rb_insert_cmp);

    fprintf(stderr, "Partition program:\n");
    int split_index = 0;
    for (int i = 0; i < engine->results_num; i++) {
        int portion_bits = (data_bits - split_index) / (engine->results_num - i);

        result_element *el = engine->results + i;
        el->prefix_bits = portion_bits;
        el->prefix = (unsigned char*) malloc(ceil((double) portion_bits/8) * sizeof (unsigned char));

        for (int j = 0; j < portion_bits; j++) {
            if (TESTBIT(data, split_index+j) != 0)
                SETBIT(el->prefix, j);
            else
                CLEARBIT(el->prefix, j);
        }

        split_index += portion_bits;
        rb_tree_insert(engine->rb_tree, el);

        fprintf(stderr, "#%d: 0x", i);
        for (int k = 0; k < ceil((double) portion_bits/8); k++) {
            fprintf(stderr, "%02x", el->prefix[k]);
        }
        printf(", %d bits\n", el->prefix_bits);
    }
}

void print_statusline(hash_engine *engine, double starttime, unsigned long median, unsigned long progress, double last_print, unsigned long last_progress)
{
    double delta = omp_get_wtime() - last_print;
    double rate = (double) (progress - last_progress)/delta;

    char *remtarget = "median";
    if (progress > median) {
        remtarget = "90\% percentile";
        median = median / (-log(2)) * (log(0.1));
    }
    if (progress > median) {
        remtarget = "99.99\% percentile";
        median = median / (log(0.1)) * (log(0.0001));
    }

    double remtime = (median - progress)/rate;
    char *remunit = "s";
    if (remtime > 60) {
        remtime /= 60;
        remunit = "min";
        if (remtime > 60) {
            remtime /= 60;
            remunit = "h";
            if (remtime > 24) {
                remtime /= 24;
                remunit = "d";
            }
        }
    }


    fprintf(stderr, "\r[%.3fMkeys/sec] [%.2f%s until %s] [%d/%d found]", rate/1000000, remtime, remunit, remtarget, engine->results_num - rb_tree_size(engine->rb_tree), engine->results_num);
    fflush(stderr);

}

int hash_engine_run(hash_engine *engine)
{
    fprintf(stderr, "Starting engine\n");
    unsigned long median = 0;
    for (int i = 0; i < engine->results_num; i++) {
        int bits = engine->results[i].prefix_bits;
        unsigned long pow = (((unsigned long) 1) << bits);
        median += log(2) / (log(pow)-log(pow-1));
    }

    unsigned long progress = 0;
    unsigned long last_progress = 0;
    double last_print = 0;
    double starttime = omp_get_wtime();
    # pragma omp parallel
    {
        fprintf(stderr, "Starting thread %d\n", omp_get_thread_num());

        result_element search_el;
        search_el.prefix_bits = hash_method_max_prefix_bits(engine->method);
        search_el.prefix = (unsigned char*) calloc(ceil((double) search_el.prefix_bits/8), sizeof(unsigned char));
        hash_context *hash_ctx = hash_context_alloc(engine->method);
        hash_context_rekey(engine->method, hash_ctx);
        hash_context_next_result(engine->method, hash_ctx);

        for (int i = 0; rb_tree_size(engine->rb_tree) > 0; i++) {
            hash_context_get_prefix(engine->method, hash_ctx, search_el.prefix_bits, search_el.prefix);
            result_element *node = (result_element*) rb_tree_find(engine->rb_tree, &search_el, &result_el_rb_test_cmp);

            if (node != NULL) {
                serialize_result(engine->method, hash_ctx, &(node->hash_str), &(node->preimage_str));
                hash_context_rekey(engine->method, hash_ctx);
                rb_tree_remove(engine->rb_tree, node);
            }

            progress++;
            if (hash_context_next_result(engine->method, hash_ctx) == 0)
                break; // TODO notify threads
            
            if (i>0 && i % 1000 == 0) {
                double now = omp_get_wtime();
                if (now - last_print > 1) {
                    print_statusline(engine, starttime, median, progress, last_print, last_progress);
                    last_print = now;
                    last_progress = progress;
                }
            }
        }
    }

    return 1;
}
