#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/kernel.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Davidr");
MODULE_DESCRIPTION("make processs unkillable");
MODULE_VERSION("0.01");

struct sighand_struct {
	atomic_t		count;
	struct k_sigaction	action[64];
	spinlock_t		siglock;
	wait_queue_head_t	signalfd_wqh;
};

#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = current ; (p = next_task(p)) != current ; )

static void print_task_info(struct task_struct * t) {
   printk(KERN_INFO "proc: %s %d \n", t->comm, t->pid);
}
static void protect_process1(struct task_struct * t) {    
    t->sighand->action[8] = t->sighand->action[7]; 
}

static void protect_process2(struct task_struct *t) {
    t->signal->flags |= SIGNAL_GROUP_EXIT;
}

static struct task_struct * find_target_process_by_name(char * name) {
    struct task_struct * iter;
    for_each_process(iter) {
        if(strcmp(name, iter->comm) == 0)
            return iter;
    }
    return NULL;
}

static struct task_struct * find_target_process_by_pid(pid_t pid){
    return pid_task(find_vpid(pid), PIDTYPE_PID)
}

static int __init proc_prot_init(void) {
    struct task_struct *this;
    this = find_target_process_by_pid(33214);
    if (NULL == this) {
        printk("pid not found\n");
        return 0;
    }
    print_task_info(this);
    protect_process2(this);

    return 0;
}
static void __exit proc_prot_exit(void) {
}
module_init(proc_prot_init);
module_exit(proc_prot_exit);