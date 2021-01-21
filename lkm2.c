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

struct signal_struct {
	atomic_t		sigcnt;
	atomic_t		live;
	int			nr_threads;
	struct list_head	thread_head;

	wait_queue_head_t	wait_chldexit;	/* for wait4() */

	/* current thread group signal load-balancing target: */
	struct task_struct	*curr_target;

	/* shared signal handling: */
	struct sigpending	shared_pending;

	/* thread group exit support */
	int			group_exit_code;
	/* overloaded:
	 * - notify group_exit_task when ->count is equal to notify_count
	 * - everyone except group_exit_task is stopped during signal delivery
	 *   of fatal signals, group_exit_task processes the signal.
	 */
	int			notify_count;
	struct task_struct	*group_exit_task;

	/* thread group stop support, overloads group_exit_code too */
	int			group_stop_count;
	unsigned int		flags; /* see SIGNAL_* flags below */
};

#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = current ; (p = next_task(p)) != current ; )

#define LOGCALL(func, ...) \
    printk(KERN_INFO "calling " #func "\n"); \
    func(__VA_ARGS__);

static void print_task_info(struct task_struct * t) {
   printk(KERN_INFO "proc: %s %d \n", t->comm, t->pid);
}
static void protect_process1(struct task_struct * t) {
    // The original process must first create a handler for all of his signals,
    // then we will copy it to the kill signal action    
    t->sighand->action[8] = t->sighand->action[7];
}

static void protect_process2(struct task_struct *t) {
    // this makes a maske on all signals
    t->blocked.sig[0] = -1;
}
static void protect_process3(struct task_struct *t) {
#define SIGNAL_UNKILLABLE 0x40
    // i think this might work on older kernel versions - there it won't  even queue the signal
    // if proc is unkillable
    t->signal->flags |= SIGNAL_UNKILLABLE;
    printk(KERN_INFO "done protect_process3 \n");
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
    return pid_task(find_vpid(pid), PIDTYPE_PID);
}

static int __init proc_prot_init(void) {
    struct task_struct *this;
    // this = find_target_process_by_name("main");
    this = find_target_process_by_pid(19275);
    if (NULL == this) {
        printk("pid not found\n");
        return 0;
    }
    print_task_info(this);
    LOGCALL(protect_process3,this);

    return 0;
}
static void __exit proc_prot_exit(void) {
}
module_init(proc_prot_init);
module_exit(proc_prot_exit);