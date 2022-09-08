/*Created By: */

#ifndef SMT_H
#define SMT_H

#include <stdint.h>

#include "params.h"
#include "imt.h"

#define SMT_FUNC XMSS_SHA2
#define SMT_N 32
#define SMT_PADDING_LEN 32
#define SMT_WOTS_W 16
#define SMT_FULL_HEIGHT 8
#define SMT_D 1
#define SMT_BDS_K 0

#define SMT_LEAF_NODES (1<<SMT_FULL_HEIGHT)

#define SMT_PER_IMT_NODE (1<<2)

/*Set the parameters for SMT*/
int smt_params_initialization(xmss_params *params);

/*Inputs: IMT tree, params of SMT and seed of the topmost layers of SMTs
**Output: A global file call FallBackKeys
*/
int create_fallback_keys(const xmss_params *params, imt_node *head, const unsigned char *inseed);



#endif
