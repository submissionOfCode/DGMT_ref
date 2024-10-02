#include <stdint.h>

void set_layer_addr(uint32_t addr[8], uint32_t layer)
{
    addr[0] = layer;
}

void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
    addr[1] = (uint32_t) (tree >> 32);
    addr[2] = (uint32_t) tree;
}

void set_type(uint32_t addr[8], uint32_t type)
{
    addr[3] = type;
}

void set_key_and_mask(uint32_t addr[8], uint32_t key_and_mask)
{
    addr[7] = key_and_mask;
}

void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
}

/* These functions are used for OTS addresses. */

void set_ots_addr(uint32_t addr[8], uint32_t ots)
{
    addr[4] = ots;
}

void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    addr[5] = chain;
}

void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
    addr[6] = hash;
}

/* This function is used for L-tree addresses. */

void set_ltree_addr(uint32_t addr[8], uint32_t ltree)
{
    addr[4] = ltree;
}

/* These functions are used for hash tree addresses. */

void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
    addr[5] = tree_height;
}

void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
    addr[6] = tree_index;
}


/* These functions are used for smt tree addresses. 
 * Created by:
*/
void set_smt_tree_addr(uint32_t addr[8], uint32_t chain[4])
{
    addr[0] = chain[0]; //Leaf index of SMT top layer
    addr[1] = chain[1]; //instance of the SMT associated a particular IMT node
    addr[2] = chain[2];//Position of the IMT node in a particular layer
    addr[3] = chain[3]; //height of the IMT node
}


