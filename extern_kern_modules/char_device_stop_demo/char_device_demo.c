/*
 * lkm example from : https://zhuanlan.zhihu.com/p/420194002
 */

#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/uaccess.h> 
#include <ebpf_kern_demos/struct_op_hook.h>


#define DEVICE_NAME "char_device_demo"
#define EXAMPLE_MSG "Hello, World!\n"
#define MSG_BUFFER_LEN 15

/* Prototypes for device functions */
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
               
extern const struct st_demo_ops* get_st_demo(void);
extern void put_st_demo(void); 

static int major_num;
static int device_open_count = 0;  
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;
               
/* This structure points to all of the device functions */
static struct file_operations file_ops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};
               
/* When a process reads from our device, this gets called. */
static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
    int bytes_read = 0;
    struct st_demo_ctx ctx;
    const struct st_demo_ops *st_op;

    /* If we’re at the end, loop back to the beginning */
    if (*msg_ptr == 0) {
        msg_ptr = msg_buffer;
    }
    /* Put data in the buffer */
    while (len && *msg_ptr) {
        /* 
         * Buffer is in user data, not kernel, so you can’t just reference
         * with a pointer. The function put_user handles this for us 
         **/
        //pr_info("lkm: flip: %lx, buffer: %lx, len: %lx, offset: %lx",flip,buffer,len,offset);
        put_user(*(msg_ptr++), buffer++);
        len--;
        bytes_read++;
    }
    
    /* test st_op demo*/
    st_op = get_st_demo();
    if (st_op != NULL) {
        st_op->first_func(&ctx);
        pr_info("st ctx first_val :%llu\n", ctx.first_val);
    }
    put_st_demo();
    return bytes_read;
}

/* Called when a process tries to write to our device */
static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset) {
    /* This is a read-only device */
    pr_info("This operation is not supported.\n");
    return -EINVAL;
}
         
/* Called when a process opens our device */
static int device_open(struct inode *inode, struct file *file) {
    /* If device is open, return busy */
    if (device_open_count) {
        return -EBUSY;
    }
    device_open_count++;
    try_module_get(THIS_MODULE);
    return 0;
}
         
/* Called when a process closes our device */
static int device_release(struct inode *inode, struct file *file) {
    /* 
     * Decrement the open counter and usage count. Without this, the module would not unload. 
     **/
    device_open_count--;
    module_put(THIS_MODULE);
    return 0;
}
         
static int __init lkm_example_init(void) {
    /* Fill buffer with our message */
    strncpy(msg_buffer, EXAMPLE_MSG, MSG_BUFFER_LEN);
    /* Set the msg_ptr to the buffer */
    msg_ptr = msg_buffer;
    /* Try to register character device */
    major_num = register_chrdev(0, "lkm_example", &file_ops);
    if (major_num < 0) {
        pr_info( "Could not register device: %d\n", major_num);
        return major_num;
    } else {
        pr_info("lkm_example module loaded with device major number %d\n", major_num);
        return 0;
    }
}

static void __exit lkm_example_exit(void) {
    /* Remember — we have to clean up after ourselves. Unregister the character device. */
    unregister_chrdev(major_num, DEVICE_NAME);
    pr_info("Goodbye, World!\n");
}

/* Register module functions */
module_init(lkm_example_init);
module_exit(lkm_example_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert W. Oliver II && chonepieceyb");
MODULE_DESCRIPTION("A simple example Linux module with add BPF struct op hook.");
MODULE_VERSION("0.01");
