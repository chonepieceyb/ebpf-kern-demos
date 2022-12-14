/*
 * @author chonepieceyb
 * testing BPF_STRUCT_OP for my st_demo 
 */
#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ST_DEMO_OPS_NAME_MAX 16 


char _license[] SEC("license") = "GPL";

#define bpfprintk(fmt, ...)                    \
({                                              \
    char ____fmt[] = fmt;                       \
    bpf_trace_printk(____fmt, sizeof(____fmt),  \
             ##__VA_ARGS__);                    \
})


struct st_demo_ctx {
    __u64 first_val;
};

struct st_demo_ops {
    int (*first_func)(struct st_demo_ctx *ctx);
    char name[ST_DEMO_OPS_NAME_MAX];
};

SEC("struct_ops/bpf_first_func")
int BPF_PROG(bpf_first_func, struct st_demo_ctx *c)
{
    bpfprintk("get st_demo_ctx->first_val: %d\n", c->first_val);
    c->first_val = 101;
    return 0;
}

SEC(".struct_ops")
struct st_demo_ops test_st_op = {
	.first_func     = (void *)bpf_first_func,
	.name		= "test_st_op",
};
