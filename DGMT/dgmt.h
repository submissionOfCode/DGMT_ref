/*
 * Created by: 
*/


#ifndef DGMT_H
#define DGMT_H

#include <stdint.h>

#include "dgmt_utils.h"
#include "smt.h"
#include "params.h"
#include "randombytes.h"

#define XMSS_MLEN 32

#define MAX_GROUP_MEMBER        (1<<6)
#define INITIAL_GROUP_MEMBER    (MAX_GROUP_MEMBER/2)

#define B_KEYS_PER_USER         (1<<3)
#define KEYS_PER_USER_PER_TREE  (SMT_LEAF_NODES/MAX_GROUP_MEMBER)
#define DGMT_MLEN 32

#define DIGITS_USER         8
#define DIGITS_IMT_HEIGHT   3
#define DIGITS_IMT_LAYER    7
#define DIGITS_SMT_PER_IMT  5
#define DIGITS_SMT_LEAF     7
#define FILENAME_LEN  (DIGITS_IMT_HEIGHT + DIGITS_IMT_LAYER + DIGITS_SMT_PER_IMT + DIGITS_SMT_LEAF)
#define MANAGER_PERMISSION 0660
#define USER_PERMISSION 0600
#define VERIFIER_PERMISSION 0600

#define MAX_UINT32_T_STRING_LEN 10

#define MAX_REQUEST ((internal_imt_nodes*SMT_PER_IMT_NODE*SMT_LEAF_NODES*KEYS_PER_USER_PER_TREE)/B_KEYS_PER_USER)

/*Required Directory*/
#define DIR_M_USER      "./dgmt/manager/m_user/"
#define DIR_SMTU        "./dgmt/manager/smt/smtU/"
#define DIR_SMTD        "./dgmt/manager/smt/smtD/"
#define DIR_USER        "./dgmt/user/"
#define DIR_FALLBACK    "./dgmt/fallback/"

//uint32_t    smt_instance[internal_imt_nodes];



void dgmt_setup(uint64_t  *request_number, uint32_t	*last_member, uint8_t	*member_status);

void create_allocation_list(const xmss_params *params, uint32_t lp[],
                            uint32_t i0, uint32_t i1, uint32_t j,
                            uint32_t k, const unsigned char   *inseed);

void create_m_user(uint32_t id);

void create_smtu_keypair(const xmss_params *params, const unsigned char *inseedU, uint32_t i0, uint32_t i1, uint32_t j);

void create_smtu_nextkey(const xmss_params *params, uint32_t i0, uint32_t i1, uint32_t j, uint32_t k);
                 
void create_smtd(const xmss_params *params, const unsigned char *inseedL, const unsigned char *alloc_seed, 
                const unsigned char *manager_key, uint32_t i0, uint32_t i1, uint32_t j, uint32_t k);
                            
void key_distribute(const xmss_params *params, imt_node *head, const unsigned char *inseedU, 
            const unsigned char *inseedL, const unsigned char   *select_imt_node_seed, const unsigned char   *alloc_seed,
            unsigned char *pub_seed_imt, unsigned char *manager_key, uint32_t   id, uint64_t    *request_number);
            
void sign_dgmtM(const xmss_params *params, imt_node *head, 
                     unsigned char *pub_seed_imt, uint32_t   id, uint64_t i0, uint64_t i1,
                     uint64_t j, uint64_t k, unsigned char *sm);
            
uint32_t sign_dgmtU(const xmss_params *params, unsigned char *sm, unsigned char *m, uint32_t id);

int verify_dgmtU(const xmss_params *imt_params, const xmss_params *smt_params, unsigned char *sm, unsigned char *imt_root);
            
void create_user_filename(char filename[], uint32_t id);

void create_smt_filename(char filename[], uint32_t i0, 
                     uint32_t i1, uint32_t j, uint32_t k);
                     
uint32_t open_dgmt(const xmss_params *params, const unsigned char *sm, unsigned char *manager_key);

void revocation(uint32_t id, unsigned char *manager_key, uint8_t *member_status);

int is_revoked(unsigned char *enc_label);

uint32_t join(const xmss_params *params, imt_node *head, const unsigned char *inseedU, 
            const unsigned char *inseedL, const unsigned char   *select_imt_node_seed, const unsigned char   *alloc_seed,
            unsigned char *pub_seed_imt, unsigned char *manager_key, uint8_t *member_status,uint32_t	*last_member, uint64_t  *request_number);


//void request_keys(uint32_t id);
#endif
