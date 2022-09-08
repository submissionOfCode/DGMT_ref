/*Created By: */
/*Here we sets the parameters of SMT and create the public file
 *containing the fallback keys.
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "params.h"
#include "smt.h"
#include "xmss_core.h"
#include "hash.h"
#include "hash_address.h"
#include "utils.h"
#include "params.h"
#include "fips202.h"


int smt_params_initialization(xmss_params *params){
    params->func = SMT_FUNC;
    params->n = SMT_N;
    params->padding_len = SMT_PADDING_LEN;
    params->wots_w = SMT_WOTS_W;
    params->full_height = SMT_FULL_HEIGHT;
    params->d = SMT_D;
    params->bds_k = SMT_BDS_K;
    
    //next part of the code is adopted from XMSS code
    params->tree_height = params->full_height  / params->d;
    if (params->wots_w == 4) {
        params->wots_log_w = 2;
        params->wots_len1 = 8 * params->n / params->wots_log_w;
        /* len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1 */
        params->wots_len2 = 5;
    }
    else if (params->wots_w == 16) {
        params->wots_log_w = 4;
        params->wots_len1 = 8 * params->n / params->wots_log_w;
        /* len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1 */
        params->wots_len2 = 3;
    }
    else if (params->wots_w == 256) {
        params->wots_log_w = 8;
        params->wots_len1 = 8 * params->n / params->wots_log_w;
        /* len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1 */
        params->wots_len2 = 2;
    }
    else {
        return -1;
    }
    params->wots_len = params->wots_len1 + params->wots_len2;
    params->wots_sig_bytes = params->wots_len * params->n;

    if (params->d == 1) {  // Assume this is XMSS, not XMSS^MT
        /* In XMSS, always use fixed 4 bytes for index_bytes */
        params->index_bytes = 4;
    }
    else {
        /* In XMSS^MT, round index_bytes up to nearest byte. */
        params->index_bytes = (params->full_height + 7) / 8;
    }
    params->sig_bytes = (params->index_bytes + params->n
                         + params->d * params->wots_sig_bytes
                         + params->full_height * params->n);
    
    params->pk_bytes = 2 * params->n;
    params->sk_bytes = xmss_xmssmt_core_sk_bytes(params);

    return 0;
}


int create_fallback_keys(const xmss_params *params, imt_node *head, const unsigned char *inseed){
    int				fd;
    unsigned char   smt_pk[params->pk_bytes];
    unsigned char   smt_sk[params->sk_bytes];
    unsigned char   smt_seed[3 * params->n];
    unsigned char   buf[32];
    uint32_t        addr[8] = {0};
    uint32_t        smt_addr[4] = {0};
    unsigned char	fallbackkey[2*AES_BLOCK_SIZE];
    AES_KEY         dec_key;
    
    //imt_i0 for height of the imt internal nodes
    //imt_i1 for the position of the imt internal nodes from left at height imt_i0
    //smt_j for the smt instance for the imt internal node indicated by (imt_i0,imt_i1)    
    uint32_t    imt_i0, imt_i1, smt_j; 
    uint32_t    l,i0i1=0;
    
    
    if((fd = open("./dgmt/fallback/FallBackKeys", O_WRONLY | O_CREAT | O_TRUNC, 0660))==-1){
            printf("\n\tFile: ./dgmt/fallback/FallBackKeys creation error from create_fallback_keys");
            exit(0);
    }else{
		for(imt_i0 = imt_tree_height; imt_i0>0; imt_i0--){ 
		    l = 1 << imt_i0;    //computes total number of nodes at height imt_i0
		    for(imt_i1 = 0; imt_i1<l; imt_i1++){
		        for(smt_j = 0; smt_j<SMT_PER_IMT_NODE; smt_j++){
		            //Create the SMT upper layer's root
		        	set_hash_addr(addr, 0);
					set_key_and_mask(addr, 0);
		            smt_addr[0] = 0;
		            smt_addr[1] = smt_j;
		            smt_addr[2] = imt_i1;
		            smt_addr[3] = imt_i0;
		            set_smt_tree_addr(addr, smt_addr);
		        
		            set_chain_addr(addr, 1);
		            addr_to_bytes(buf, addr);
		            prf(params, smt_seed, buf, inseed);

		            set_chain_addr(addr, 2);
		            addr_to_bytes(buf, addr);
		            prf(params, smt_seed+params->n, buf, inseed);

		            set_chain_addr(addr, 3);
		            addr_to_bytes(buf, addr);
		            prf(params, smt_seed+2 * params->n, buf, inseed);
		            
		            xmssmt_core_seed_keypair(params, smt_pk, smt_sk, smt_seed);
		            
		            //Set the SMT upper layer's root as AES decryption key	            
		            AES_set_decrypt_key(smt_pk, 256, &dec_key);
		            
		            
		            //head[i0i1] is the fallback node of length 32 bytes
		            //As AES encrypt-decrypt block size is 16 bytes:
		            //first AES call decrypts the first 16 bytes of head[i0i1] and
		            //stores in the first 16 bytes of fallbackkey
		            //second AES call decrypts the last 16 bytes of head[i0i1] and
		            //stores in the last 16 bytes of fallbackkey

		            //Decrypt the IMT internal node
		            AES_decrypt(head[i0i1].value, fallbackkey, &dec_key);
		            AES_decrypt(head[i0i1].value+AES_BLOCK_SIZE, fallbackkey+AES_BLOCK_SIZE, &dec_key);
		            
		            if(write(fd, fallbackkey,2*AES_BLOCK_SIZE)!=(2*AES_BLOCK_SIZE)){
                		printf("\n\tFile: ./dgmt/fallback/FallBackKeys writing error: (i0:%u, i1:%u,j:%u)",imt_i0,imt_i1,smt_j);
                		exit(0);
            		}
		        }
		        i0i1++;
		    }
		}
		close(fd);
    }
    
    printf("\tCreation of FallBack Keys is done.\n");
    return 0;
}

















