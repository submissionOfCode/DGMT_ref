/*Created by: */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "dgmt_utils.h"

int compare_node(unsigned char *in1, unsigned char *in2, int len){
    int i=len-1;
    
    while((in1[i]==in2[i]) && i>=0)
        i--;
        
    if(i>=0){
        if(in1[i]>in2[i])
            return 1;
        else return -1;
    }else return 0;
}

int swap_allot_node(allot *in1, allot *in2){
    allot   t;
    
    t = *in1;
    *in1 = *in2;
    *in2 = t;
 
    return 0;   
}


void sort_allot_node(allot in[], uint32_t f, uint32_t l, uint32_t len){
    uint32_t m;
    
    if(f<l){
        m = (f+l)/2;
        sort_allot_node(in, f, m, len);
        sort_allot_node(in, m+1, l, len);
        merge(in, f, m, l, len);
    }
    
    return;
}

void merge(allot in[], uint32_t f, uint32_t m, uint32_t l, uint32_t len){
    allot       temp[l-f+1];
    uint32_t    i,j,k;
    int         comp;
    
    k=0;
    i = f;
    j = m+1;
    while((i<=m) && (j<=l)){
        comp = compare_node(in[i].value, in[j].value, len);
    
        if((comp == -1) || (comp == 0)){
            temp[k]=in[i];
            i++; k++;
        }else{
            temp[k] = in[j];
            j++; k++;
        }
    }
    
    while(i<=m){
        temp[k]=in[i];
        i++; k++;
    }

    while(j<=l){
        temp[k]=in[j];
        j++; k++;
    }
    
    k=0;
    for(i=f; i<=l; i++){
        in[i] = temp[k];
        k++;
    }

}
