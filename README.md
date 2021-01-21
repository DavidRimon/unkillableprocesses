## Make an unkillable program

Exercise: make an unkillable program.

Note: this was maked with ubuntu 18 kernel 4.15. it  should work though on other kernels as well

### Getting started

First we want to know how `kill` works.

For this we will use  `trace-cmd` which internally uses `ftrace`, a OS tracing mechanism. (https://jvns.ca/blog/2017/03/19/getting-started-with-ftrace is a nice guide )

We will create 3 bash shells:

1. `killer` bash
2. `killed`  task
3. `tracer` bash

we will use the `tracer` bash to trace the `killer` and `killed` bashes.

First lets see what happens in the kernel when you do `kill -9 $pid`.

1. get pid of `killed` and `killer` bashes (by typing `$$` in it)

   for me i got `killer` =`16796`, and `killed` = `21444`

2.  Run in `tracer` bash:

```bash
sudo trace-cmd record -P 16796 -p function_graph -e signal_generate -o killer.dat
```
Wait for it to initialize

3. Then in the `killer` bash:

```bash
sudo kill -9 21444
```

4. hit `crtl+c` in the `tracer` bash to stop the tracing.

5. run

   ```bash
   sudo trace-cmd report -i killer.dat > killer.txt
   ```


Greate! now lets see what we got.
let us look inside the file. look for `kill` phrase

```
do_syscall_64() {
    sys_kill() { <----- enter kill syscall
        ...
      find_vpid(); <---- find task struct by pid
      kill_pid_info() {
        pid_task();
        group_send_sig_info() {
          ...
          }
          do_send_sig_info() {
            ...
            send_signal() {
              ...
              __send_signal() { <---- send the signal
                prepare_signal(); <--- prepare the signal before being sent
                ...
                complete_signal() { < --- complete signal sending
                  ...
                  signal_wake_up_state() {
                    wake_up_state() {
                      try_to_wake_up() {
                      ...
                      }
                    }
                  }
                }
                     sig=9 errno=0 code=0 comm=main pid=29469 grp=1 res=0
              }         ^^^ SIGKILL
            }
            ...
          }
        }
}
```

`trace-cmd` with `function-graph` plugin shows a graph of function calles, in there order.
The `-e` switch also follows even, and here we asked for `signal_generate` event type

This  will help us get better aim while reading the source.

Basicly we can see what happening: `do_syscall_64` -> `sys_kill` -> `find_vpid` -> `kill_pid_info` -> `group_send_sig_info` -> `do_send_sig_info` -> `send_signal` -> `__send_signal` -> `prepare_signal` -> `complete_signal` -> `end`

We will go over theae functions soom.

Now lets wee what happens to the `killed` process.
This time, we will make our own simple program, so its easier to see what going on.

Here is our simple program:

```c
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
void my_handler(int signum) {
    printf("I get %d signum, and i'm not going anywhere!!\n" , signum);
}
void setup_signal(int signum) {
    struct sigaction act = {0};
    memset(&act, 0, sizeof(act));
    act.sa_handler = my_handler;
    if (0 != sigaction(signum, &act, NULL)) {
        printf("I have failed setting handler for signum: %d. DAMN THE BASTERDS!!!\n", signum);
    }
}
void main() {
    for (size_t i = 0; i < 64; i++)
        setup_signal(i);
    printf("hello world, my pid is: %d\n", getpid());
    while(1) sleep(100);
}
```

compile and run:

```bash
gcc -o main main.c && ./main
```

now, with the killer process we will send two signals: first we will send `3` and then `9` (`SIGKILL`)

To trace, this time we will also trace the `signal_deliver` event 

```bash
sudo trace-cmd record -P 27967 -p function_graph -e signal_deliver -o killed.dat
```

here is the output from our main:

```
david@ubuntu:~/Projects/lkm$ ./main
I have failed setting handler for signum: 0. DAMN THE BASTERDS!!!
I have failed setting handler for signum: 9. DAMN THE BASTERDS!!!
I have failed setting handler for signum: 19. DAMN THE BASTERDS!!!
I have failed setting handler for signum: 32. DAMN THE BASTERDS!!!
I have failed setting handler for signum: 33. DAMN THE BASTERDS!!!
hello world, my pid is: 24174
I get 3 signum, and i'm not going anywhere!!
Killed
```

Now lets see what happend in the kernel side of our `main` program:

```
exit_to_usermode_loop() { <---- the task gets `kicked` from kernel,
                            and its now going over its signal qeueue
   do_signal() {
     get_signal() { <---- get the signal from the task
        ...
       dequeue_signal() { <----- dequeue signal from queue
        ...
       }
     sig=3 errno=0 code=0 sa_handler=55e37d36d7da sa_flags=4000000
     }
    ...
   }
 }
 do_syscall_64() {
   SyS_write() { <---- the printf from signal handler in usermode
     ...
   }
 }
 do_syscall_64() {
   sys_rt_sigreturn() { <--- return from signal handler back to kernel
       ...
   }
 }
 do_syscall_64() {
   SyS_nanosleep() { <--- continue sleeping
       ...
   }
   exit_to_usermode_loop() { <---- got kicked again because we are sending another signal
     do_signal() {
       get_signal() { <---- get the signal
            ...
        sig=9 errno=0 code=0 sa_handler=0 sa_flags=0
            ... 
         smp_irq_work_interrupt() {
          ...
         }
         smp_apic_timer_interrupt() {
           ...
         }
         do_group_exit() { <---- SIGKILL - get lost!
           do_exit() {
             profile_task_exit() {
               blocking_notifier_call_chain();
             }
             ...
```

see  the full trace in `killer1.txt` and `killed1.txt` attached files.

Lets try blocking the signals in a few ways:

1. block SIGKILL from every being sent
2. block SIGKILL from being recived
3. handle SIGKILL even though you cant

#### Method 1

Let's take a look at `__send_signal` function - https://elixir.bootlin.com/linux/v4.15/source/kernel/signal.c#L994

we see this:

```c
static int __send_signal(int sig, struct siginfo *info, struct task_struct *t,
			int group, int from_ancestor_ns)
{
	...
	result = TRACE_SIGNAL_IGNORED;
	if (!prepare_signal(sig, t,
			from_ancestor_ns || (info == SEND_SIG_FORCED)))
		goto ret;
		...
	result = TRACE_SIGNAL_DELIVERED;
	...

out_set:
...
	complete_signal(sig, t, group);
ret:
	trace_signal_generate(sig, info, t, group, result);
	return ret;
}
```

if `prepare_signal` fails the signal won't be sent. Lets see that function...
Most of the function deals with special cases about signal delivery (like kernel signals, continue signal, sending SIGKILL to a dying process)

```c
return !sig_ignored(p, sig, force);
```

again at the end of `sig_ignored` we see

```c
return sig_task_ignored(t, sig, force);
```

This is where its interesting. function source:
https://elixir.bootlin.com/linux/v4.15/source/kernel/signal.c#L74

```c
static int sig_task_ignored(struct task_struct *t, int sig, bool force)
{
	void __user *handler;

	handler = sig_handler(t, sig);

	if (unlikely(t->signal->flags & SIGNAL_UNKILLABLE) &&
	    handler == SIG_DFL && !(force && sig_kernel_only(sig)))
		return 1;

	return sig_handler_ignored(handler, sig);
}
```

If `t->signal->flags` has `SIGNAL_UNKILLABLE` it won't be killed (unless a kernel signal was forced apon)

what is `SIGNAL_UNKILLABLE`? 
see here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/sched/signal.h#L242

```c
#define SIGNAL_UNKILLABLE	0x00000040 /* for init: ignore fatal signals */
```

This flag was orignaly made for the `init` task, so you won't  be able to kill it even by mistake.

It used to be set on `init` task untill `v3.7.10` but seince then  I don't know how are they making `init` unkillable.

```c
static int __ref kernel_init(void *unused)
{
	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	free_initmem();
	mark_rodata_ro();
	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	current->signal->flags |= SIGNAL_UNKILLABLE;
	flush_delayed_fput();
```

from https://elixir.bootlin.com/linux/v3.7.10/source/init/main.c#L815

Anyway, that shouldn't stop us right? all we have to do is set  out target signal flags with `SIGNAL_UNKILLABLE` and it will be undead!

Here is the function graph from the `killer` process, after we set the target process with `SIGNAL_UNKILLABLE` 

I sent  first signum `3`,  and then signum `9` (`SIGKILL`) so its easy to compare:

```c
  do_syscall_64() {
    sys_kill() {
        ...
      find_vpid();
      kill_pid_info() {
        pid_task();
        group_send_sig_info() {
          check_kill_permission() {
          }
          do_send_sig_info() {
            ...
            send_signal() {
                ...
              __send_signal() {
                prepare_signal();
                ...
                complete_signal() {
                  signal_wake_up_state() {
                    wake_up_state() {
                      try_to_wake_up() {
                        ...
                          }
                        }
                        ...
                      }
                    }
                  }
                }
                sig=3 errno=0 code=0 comm=main pid=34804 grp=1 res=0 <---- signal was deliverd!
              }
            }
            _raw_spin_unlock_irqrestore();
          }
        }
      }
    }
  }
 
  do_syscall_64() {
   sys_kill() {
        ...
     find_vpid();
     kill_pid_info() {
       pid_task();
       group_send_sig_info() {
         check_kill_permission() {
            ...
         }
         do_send_sig_info() {
            ...
           send_signal() {
            ...
             __send_signal() {
               prepare_signal();
               <------------ no complete_signal here!
                    sig=9 errno=0 code=0 comm=main pid=34804 grp=1 res=1 < ---  TRACE_SIGNAL_IGNORED 
             }
           }
           _raw_spin_unlock_irqrestore();
         }
       }
     }
   }
 }
```

Notice how for signum `9` there is no execution of `complete_signal` and `res=1` which is `TRACE_SIGNAL_IGNORED`, because we jumped straight to the end. 

If you look at the `killed` task trace, you'll se that only signum `3` was deliverd.

You can see the `killed` and the `killer` traces in `killer2.txt` and `killed2.txt`

#### Method2

this time we will block the `SIGKILL` in the signal mask.

signals are  getting pulled from the signal queue in `__dequeue_signal` https://elixir.bootlin.com/linux/v4.15/source/kernel/signal.c#L560

```c
static int __dequeue_signal(struct sigpending *pending, sigset_t *mask,
			siginfo_t *info, bool *resched_timer)
{
	int sig = next_signal(pending, mask);

	if (sig)
		collect_signal(sig, pending, info, resched_timer);
	return sig;
}
```

masked signals won't return from `next_signal`

normally, to mask signals we will use `sigprocmask`, but the syscall will not let us set the `SIGKILL` in the mask:

https://elixir.bootlin.com/linux/v4.15/source/kernel/signal.c#L3352

```c
SYSCALL_DEFINE3(sigprocmask, int, how, old_sigset_t __user *, nset,
		old_sigset_t __user *, oset)
{
	old_sigset_t old_set, new_set;
	sigset_t new_blocked;

	old_set = current->blocked.sig[0];

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(*nset)))
			return -EFAULT;
		new_blocked = current->blocked;
		switch (how) {
		case SIG_BLOCK:
			sigaddsetmask(&new_blocked, new_set);
			break;
		case SIG_UNBLOCK:
			sigdelsetmask(&new_blocked, new_set);
			break;
		case SIG_SETMASK:
			new_blocked.sig[0] = new_set;
			break;
		default:
			return -EINVAL;
		}
		set_current_blocked(&new_blocked);
	}
	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(*oset)))
			return -EFAULT;
	}
	return 0;
}
```

see that call to `set_current_blocked`? 
https://elixir.bootlin.com/linux/v4.15/source/kernel/signal.c#L2506

```c
void set_current_blocked(sigset_t *newset)
{
	sigdelsetmask(newset, sigmask(SIGKILL) | sigmask(SIGSTOP));
	__set_current_blocked(newset);
}
```

it won't let us set the mask with the syscall. 

So we will  do it in a kernel module!

you can take a look in `killer3.txt` and `killed3.txt` and see the results.

Note that `killed3.txt` is empty because our `killed` task masked all incomming signals, so there was  no reason for it to wake up and enter the kernel!

#### method 3

overwrite the `SIGKILL` handler.



here is  our full kernel module:

```c
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

// we need the structs here becasue they are not in the headers
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
    t->blocked.sig[0] = (unsigned long) -1;
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
    this = find_target_process_by_pid(42319);
    if (NULL == this) {
        printk("pid not found\n");
        return 0;
    }
    print_task_info(this);
    LOGCALL(protect_process2,this);

    return 0;
}
static void __exit proc_prot_exit(void) {
}
module_init(proc_prot_init);
module_exit(proc_prot_exit);
```





