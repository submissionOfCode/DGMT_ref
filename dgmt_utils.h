/*Created by:*/

#ifndef DGMT_UTILS_H
#define DGMT_UTILS_H

#include <stdint.h>
#include "smt.h"

#define allot_node_size SMT_N

typedef struct{
    uint32_t    l;
    unsigned char value[allot_node_size];
}allot;


/*
 * Comapers two strings in1 and in2 of length len bytes
 * outputs 1  if in1 > in2
 *         0  if in1 = in2
 *         -1 if in1 < in2
*/

int compare_node(unsigned char *in1, unsigned char *in2, int len);

int swap_allot_node(allot *in1, allot *in2);

void sort_allot_node(allot in[], uint32_t f, uint32_t l, uint32_t len);

void merge(allot in[], uint32_t f, uint32_t m, uint32_t l, uint32_t len);
#endif

