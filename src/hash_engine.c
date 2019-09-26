#include "hash_engine.h"
#include <math.h>
#include <sys/param.h>
#include <omp.h>
#include <time.h>

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

void hash_engine_init(hash_engine *engine, unsigned char *data, int data_bits, int prefix_bits)
{
    engine->results_num = ceil((double) data_bits / prefix_bits);
    engine->results = (result_element*) malloc(engine->results_num * sizeof(result_element));
    engine->rb_tree = rb_tree_create(&result_el_rb_insert_cmp);

    fprintf(stderr, "Partition program:\n");
    int split_index = 0;
    for (int i = 0; i < engine->results_num; i++) {
        int portion_bits = (data_bits - split_index) / (engine->results_num - i);

        result_element *el = engine->results + i;
        el->prefix_bits = portion_bits;
        el->prefix = (unsigned char*) calloc(ceil((double) portion_bits/8), sizeof (unsigned char));

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

void print_statusline(hash_engine *engine, unsigned long progress, double rate)
{
    unsigned long median = 0;
    for (int i = 0; i < engine->results_num; i++) {
        int bits = engine->results[i].prefix_bits;
        unsigned long pow = (((unsigned long) 1) << bits);
        median += log(2) / (log(pow)-log(pow-1));
    }

    char const *remtarget = "median";
    if (progress > median) {
        remtarget = "90\% percentile";
        median = median / (-log(2)) * (log(0.1));
    }
    if (progress > median) {
        remtarget = "99.99\% percentile";
        median = median / (log(0.1)) * (log(0.0001));
    }

    double remtime = (median - progress)/rate;
    char const *remunit = "s";
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

result_element* hash_engine_search(hash_engine *engine, unsigned char *prefix, int prefix_bits)
{
    result_element search_el;
    search_el.prefix_bits = prefix_bits;
    search_el.prefix = prefix;

    return (result_element*) rb_tree_find(engine->rb_tree, &search_el, &result_el_rb_test_cmp);
}
