/*
 * @author: chonepieceyb 
 * example for adding a new bpf struct op hook 
 */

#ifndef _EBPF_KERN_DEMOS_STRUCT_OP_HOOK_H
#define _EBPF_KERN_DEMOS_STRUCT_OP_HOOK_H 

#include <linux/types.h> 

#define ST_DEMO_OPS_NAME_MAX 16

struct st_demo_ctx {
    u64 first_val;
};

struct st_demo_ops {
    int (*first_func)(struct st_demo_ctx *ctx);
    char name[ST_DEMO_OPS_NAME_MAX];
};

#endif 

