/*Created By: */

#ifndef IMT_H
#define IMT_H

#include <stdint.h>
#include "params.h"


/*
 1. change imt_tree_height based on the requirement
 2. Consequently change the value of internal_imt_nodes
    by the formula given in comment
*/

#define imt_node_len 32		    //output length of SHA256 in bytes
#define imt_tree_height 4	    //height of the IMT tree
#define internal_imt_nodes 30   //((1<<(imt_tree_height+1))-2)

typedef struct imt_node{
	//unsigned char	h;		        //node position layer; root is 0
	//unsigned char	l;		        //node position in a layer from left
	unsigned char 	value[imt_node_len];	//node value
}imt_node;


imt_node *imt_setup(const xmss_params *params, const unsigned char *inseed, 
                    const unsigned char *pub_seed, uint32_t addr[8]);


#endif
