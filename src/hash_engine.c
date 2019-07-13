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
    }
}

void print_statusline(hash_engine *engine, int progress, double starttime, int expected)
{
    double delta = omp_get_wtime() - starttime;
    printf("\r[%.2fMkeys/sec] [%.2f%% trials relative to mean] [%d/%d found]", progress/delta/1000000, (float) progress/expected*100, engine->results_num - rb_tree_size(engine->rb_tree), engine->results_num);
    fflush (stdout);

}

int hash_engine_run(hash_engine *engine)
{
    unsigned long expected = 0;
    for (int i = 0; i < engine->results_num; i++) expected += (((unsigned long) 1) << (engine->results[i].prefix_bits));

    int progress = 0;
    double last_print = 0;
    double starttime = omp_get_wtime();
    # pragma omp parallel
    {
        printf("Starting thread %d\n", omp_get_thread_num());

        result_element search_el;
        search_el.prefix_bits = engine->method->max_prefix_bits;
        search_el.prefix = (unsigned char*) malloc(engine->method->max_prefix_bits/8 * sizeof(unsigned char));
        hash_context hash_ctx;
        engine->method->hash_context_alloc(&hash_ctx);
        // TODO add "target suggestion" for Sward-keys
        engine->method->hash_context_rekey(&hash_ctx);

        for (int i = 0; rb_tree_size(engine->rb_tree) > 0; i++) {
            engine->method->hash_context_get_prefix(&hash_ctx, engine->method->max_prefix_bits/8, search_el.prefix);
            result_element *node = (result_element*) rb_tree_find(engine->rb_tree, &search_el, &result_el_rb_test_cmp);

            if (node != NULL) {
                engine->method->serialize_result(&hash_ctx, &(node->hash_str), &(node->preimage_str));
                engine->method->hash_context_rekey(&hash_ctx);
                rb_tree_remove(engine->rb_tree, node);
            }

            progress++;
            if (engine->method->hash_context_next_result(&hash_ctx) == 0) {
                break; // TODO notify threads
            }
            
            if (i>0 && i % 1000 == 0) {
                double now = omp_get_wtime();
                if (now - last_print > 1) {
                    print_statusline(engine, progress, starttime, expected);
                    last_print = now;
                }
            }
        }
    }

    return 1;
}
