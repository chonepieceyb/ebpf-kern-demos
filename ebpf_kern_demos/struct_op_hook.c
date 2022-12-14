/*
 * @author: chonepieceyb 
 * example for adding a new bpf struct op hook 
 */

#include <linux/printk.h> 
#include <linux/spinlock.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/rcupdate.h>
#include <linux/lockdep.h>

#include <ebpf_kern_demos/struct_op_hook.h> 

extern struct bpf_struct_ops bpf_st_demo_ops;

static DEFINE_SPINLOCK(st_demo_op_mutex);

/*
 *step1 : defeined your onw module interface, eg. struct st_demo_ops here 
 */
static struct st_demo_ops __rcu *st_demo_op = NULL;

const struct st_demo_ops* get_st_demo(void)
{
	rcu_read_lock();
	return rcu_dereference(st_demo_op);
}
EXPORT_SYMBOL(get_st_demo);

void put_st_demo(void) 
{
	rcu_read_unlock();
}
EXPORT_SYMBOL(put_st_demo);

static const struct btf_type *st_demo_ctx_type;

static int register_st_demo_op(struct st_demo_ops *new_op) 
{
	int ret = 0;
	const struct st_demo_ops *old_op;

        if (new_op->first_func == NULL) {
	        pr_err("%s does not supply required ops\n", new_op->name);
	        return -EINVAL;
        }

        spin_lock(&st_demo_op_mutex);
        old_op = rcu_dereference_protected(st_demo_op, lockdep_is_held(&st_demo_op_mutex));

        if (old_op != NULL) {
	        pr_notice("%s already registered for st_demo_op\n", new_op->name);
	        spin_unlock(&st_demo_op_mutex);       
	        return -EEXIST;
        }	  
    
        rcu_assign_pointer(st_demo_op, new_op);

        spin_unlock(&st_demo_op_mutex);

        synchronize_rcu();

        pr_debug("register_st_demo_op finish\n");
        return ret;
}

static void unregister_st_demo_op(struct st_demo_ops *op) 
{
        const struct st_demo_ops *old_op;

        spin_lock(&st_demo_op_mutex);

        old_op = rcu_dereference_protected(st_demo_op, lockdep_is_held(&st_demo_op_mutex));

        if (old_op != op) {
	        /*compare addrress not the same op should not happen*/
	        WARN_ONCE(1, "old_op: %llx not equal to op: %llx\n", (u64)old_op, (u64)op);
	        spin_unlock(&st_demo_op_mutex);
	        return;
        }

        rcu_assign_pointer(st_demo_op, NULL);

        spin_unlock(&st_demo_op_mutex);

        synchronize_rcu();
        pr_debug("unregister_st_demo_op finish\n");
        return;
}

/* 
 * step2: implement struct bpf_verifier_ops
 */

static const struct bpf_func_proto *
bpf_st_demo_get_func_proto(enum bpf_func_id func_id,
			   const struct bpf_prog *prog) 
{
        /* just return the base helper functions set */
        const struct bpf_func_proto *proto;
        proto = bpf_base_func_proto(func_id); 

        pr_debug("st_demo get_func_proto finish, func_id: %d\n", func_id);
        return proto;
}

static bool bpf_st_demo_is_valid_access(int off, int size, enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
    /* ctx of BPF_PROG_STRUCT_OP */
         int ret = 0;
        ret = bpf_tracing_btf_ctx_access(off, size, type, prog, info);

        pr_debug("st_demo is_valid_access finish\n");
        return ret;
}


static int bpf_st_demo_btf_struct_access(struct bpf_verifier_log *log,
					 const struct btf *btf,
					 const struct btf_type *t, int off, int size,
					 enum bpf_access_type atype,
					 u32 *next_btf_id, enum bpf_type_flag *flag) 
{
        size_t end; 
        if (atype == BPF_READ)
	        return btf_struct_access(log, btf, t, off, size, atype, next_btf_id, flag);
    
        if (t != st_demo_ctx_type) {
	        bpf_log(log, "only write for st_demo_ctx is supported\n");
	        return -EACCES;
        }
    
        switch (off) {
        case offsetof(struct st_demo_ctx, first_val):
	        end = offsetofend(struct st_demo_ctx, first_val);
	        break;
        default:
	        bpf_log(log, "no write support to st_demo_ctx at off %d\n", off);
	        return -EACCES;
        }
        if (off + size > end) {
	        bpf_log(log, "write at off: %d, size : %d for st_demo_ctx is supported\n", off, size);
	        return -EACCES;
        }
    
        pr_debug("st_demo btf_struct_access at off: %d, size : %d, atype: %d success\n", off, size, atype);

        return 0;
}

static const struct bpf_verifier_ops bpf_st_demo_verifier_ops = {
	.get_func_proto		= bpf_st_demo_get_func_proto,
	.is_valid_access	= bpf_st_demo_is_valid_access,
	.btf_struct_access	= bpf_st_demo_btf_struct_access,
};


/*
 * step3: implement struct bpf_struct_ops : 
 * 1. init 
 * 2. reg
 * 3. unreg 
 * 4. check_member
 * 5. init_member 
 * 6. set name to your module interface name, eg st_demo_ops here 
 * 7. set verifier_ops
 */

static int bpf_st_demo_init(struct btf *btf)
{
        s32 type_id;
        type_id = btf_find_by_name_kind(btf, "st_demo_ctx", BTF_KIND_STRUCT);
        if (type_id < 0)
	        return -EINVAL;

    /* init st_demo_ctx_type */
        st_demo_ctx_type = btf_type_by_id(btf, type_id);
    
        pr_debug("st_demo init finish, st_demo_ctx btf id: %d\n", type_id);

        return 0;
}
    
static int bpf_st_demo_check_member(const struct btf_type *t,
				    const struct btf_member *member)
{
        u32 moff; 
        moff = __btf_member_bit_offset(t, member) / 8;
        switch (moff) {
        case offsetof(struct st_demo_ops, first_func):
	        /* allow to set first_func */
	        break;
        case offsetof(struct st_demo_ops, name): 
	        /* allow to set name */
	        break;
        default: 
	        return -ENOTSUPP;
        }
    
        pr_debug("st_demo check_member success, moff: %d\n", moff);
        return 0;
}

static int bpf_st_demo_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct st_demo_ops *uop;
	struct st_demo_ops *op;
	int prog_fd;
	u32 moff;

	uop = (const struct st_demo_ops *)udata;
	op = (struct st_demo_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
        /* set regular member */
	case offsetof(struct st_demo_ops, name):
		if (bpf_obj_name_cpy(op->name, uop->name, sizeof(op->name)) <= 0)
		return -EINVAL;
		goto regular_member;
	}   
    
	switch (moff) {
        /*check function member */
	case offsetof(struct st_demo_ops, first_func):
		goto func_member;
	default:
		return -EINVAL;
	}

/*
    if (!btf_type_resolve_func_ptr(btf_vmlinux, member->type, NULL))
	return 0;
*/
    /* Ensure bpf_prog is provided for compulsory func ptr */
    
regular_member:
	pr_debug("st_demo init regular member success, moff: %d\n", moff);
	return 1;	   
    
func_member:
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	if (!prog_fd)
		return -EINVAL;

	pr_debug("st_demo init function member success, moff: %d\n, progfd: %d", moff, prog_fd);
	return 0;
}

static int  bpf_st_demo_reg(void *kdata)
{
	return register_st_demo_op(kdata);
}

static void bpf_st_demo_unreg(void *kdata) 
{
	return unregister_st_demo_op(kdata);
}

struct bpf_struct_ops bpf_st_demo_ops = {
	.verifier_ops = &bpf_st_demo_verifier_ops,
	.reg = bpf_st_demo_reg,
	.unreg = bpf_st_demo_unreg,
	.check_member = bpf_st_demo_check_member,
	.init_member = bpf_st_demo_init_member,
	.init = bpf_st_demo_init,
	.name = "st_demo_ops",
};

