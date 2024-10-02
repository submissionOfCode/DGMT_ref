#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>


#include "../wots.h"
#include "../randombytes.h"
#include "../params.h"
#include "../imt.h"
#include "../smt.h"
#include "../xmss_core.h"
#include "../dgmt.h"

int main()
{
    xmss_params imt_params;
    uint32_t oid = 0x00000001; //for IMT
    xmss_parse_oid(&imt_params, oid);       //initialize IMT params
    
	xmss_params smt_params;
	smt_params_initialization(&smt_params); //initialize SMT params

	uint64_t    request_number[MAX_GROUP_MEMBER];
	uint32_t	last_member;
	uint8_t		member_status[MAX_GROUP_MEMBER];
    
    unsigned char   pub_seed_imt[imt_params.n];
    unsigned char   manager_key[32];
    unsigned char   imt_seed[imt_params.n];
    unsigned char   imt_root[imt_node_len];
    unsigned char   smtU_seed[3 * smt_params.n];
    unsigned char   smtL_seed[3 * smt_params.n];
    unsigned char   select_imt_node_seed[smt_params.n];
    unsigned char   allocate_seed[smt_params.n];
    uint32_t        addr[8] = {0};
    imt_node	    *imt_head=NULL;
    
    uint32_t        id;
    uint32_t	    isRequest;
    unsigned char	sm[2*(smt_params.sig_bytes + smt_params.pk_bytes) + XMSS_MLEN + 2*smt_params.index_bytes + imt_tree_height*imt_node_len + smt_params.n + AES_BLOCK_SIZE];
    unsigned char   m[XMSS_MLEN];

    
    printf("\nStarting Setup...\n");

    dgmt_setup(request_number, &last_member, member_status);
    
    //Creation of the IMT Tree
	randombytes(imt_seed, imt_params.n);                                        //randomly choose IMT Seed
	randombytes(pub_seed_imt, imt_params.n);                                    //randomly choose IMT Public Seed
	imt_head = imt_setup(&imt_params,imt_seed,pub_seed_imt,addr);               //Create IMT tree
	memcpy(imt_root,imt_head[(1<<(imt_tree_height+1))-2].value,imt_node_len);   //Keep the root value of the IMT tress
    printf("\tCreation of IMT tree is done.\n");

    //Creation of Fallback Keys	
    randombytes(smtU_seed, 3 * smt_params.n);                                   //randomly choose SMT upper layers' Seed
    randombytes(smtL_seed, 3 * smt_params.n);                                   //randomly choose SMT lowest layer's Seed
    create_fallback_keys(&smt_params, imt_head, smtU_seed);                     //create all the fallback keys
    
    randombytes(select_imt_node_seed, imt_params.n);                            //randomly choose a seed to choose a internal node of IMT
    randombytes(allocate_seed, smt_params.n);                                   //randomly choose a seed to shuffle the leaves of SMT lowest layer
    randombytes(manager_key, 32);                                               //randomly choose Group manager's enc-dec key
    
    printf("DGMT Setup Complete.\n");
    
    for(id = 0; id<INITIAL_GROUP_MEMBER; id++){
       key_distribute(&smt_params, imt_head, smtU_seed, smtL_seed, select_imt_node_seed, allocate_seed, pub_seed_imt,manager_key, id,request_number);
    }
    printf("Key distribution to initial group members is done\n");
    
//    id = 1;
//    if(member_status[id] == 0){
//        printf("\t\tInactive member\n");
//    } else if(member_status[id] == 1){    
//    	key_distribute(&smt_params, imt_head, smtU_seed, smtL_seed, select_imt_node_seed, allocate_seed, pub_seed_imt,manager_key, id);
//    }else if (member_status[id] == 2){
//    	printf("\t\tRevoked member\n");
//    }

    id = 1; //sample id
    randombytes(m, XMSS_MLEN);
    isRequest = sign_dgmtU(&smt_params, sm, m, id);
    printf("\tVerified without any revocation = %u\n",verify_dgmtU(&imt_params, &smt_params, sm, imt_root));

    //if one active user exhausts all the siging key, then new keys must be distributed to him/her if possible
    if(isRequest){
        if(member_status[id] == 0){
            printf("\t\tInactive member\n");
        } else if(member_status[id] == 1){    
        	key_distribute(&smt_params, imt_head, smtU_seed, smtL_seed, select_imt_node_seed, allocate_seed, pub_seed_imt,manager_key, isRequest-1,request_number);
        }else if (member_status[id] == 2){
        	printf("\t\tRevoked member\n");
        }
    }
    
    printf("\tUser's id after open = %u\n",open_dgmt(&smt_params, sm, manager_key));
    
    revocation(2, manager_key, member_status);
    printf("\tVerified after revocation of user 2 = %u\n",verify_dgmtU(&imt_params, &smt_params, sm, imt_root));
    
    revocation(1, manager_key, member_status);
    printf("\tVerified after revocation of user 1 = %u\n",verify_dgmtU(&imt_params, &smt_params, sm, imt_root));
    
    id = join(&smt_params, imt_head, smtU_seed, smtL_seed, select_imt_node_seed, allocate_seed, pub_seed_imt,manager_key, member_status, &last_member, request_number);
    printf("\tNew member joined with id = %u\n",id);
    
    return 0;
}
