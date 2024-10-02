/*Created By: */
/*This code constructs the IMT tree from a seed*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#include "imt.h"
#include "hash.h"
#include "hash_address.h"
#include "utils.h"
#include "params.h"
#include "fips202.h"


imt_node *imt_setup(const xmss_params *params, const unsigned char *inseed, 
                    const unsigned char *pub_seed, uint32_t addr[8]){
    uint64_t        l = 1<<imt_tree_height;
	uint64_t        total_imt_nodes = (l<<1)-1;
	uint64_t        i,j,k;
	unsigned char   buf[32];
	unsigned int    parent_nodes;
	imt_node        *imt_head;
	
	//printf("Total number of nodes in the IMT tree of height %d = %d\n",imt_tree_height,total_imt_nodes);

	imt_head = (imt_node *)malloc(total_imt_nodes*sizeof(imt_node));

    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    	
	for(i=0; i<l; i++){
	    set_chain_addr(addr, i);
        addr_to_bytes(buf, addr);
	    prf(params, imt_head[i].value, buf, inseed);
	}
    
    
    k = 0;
    for(i=0;i<imt_tree_height;i++){
        parent_nodes = l>>1;
        for(j=0;j<parent_nodes;j++){
        	memset(addr,0,8*sizeof(uint32_t));
        	set_tree_height(addr, imt_tree_height-1-i);
            set_tree_index(addr, j);
            thash_h_m(params, imt_head[k+l+j].value, imt_head[k+2*j].value,
                    imt_head[k+2*j+1].value, pub_seed, addr);
        }
        k = k + l;
        l = l>>1;
    }

	return imt_head;
}
