// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/module.h>
#include <linux/proc_fs.h>

#define PROC_FILE_NAME "kprobe_target"

unsigned long noinline kprobe_target_func(unsigned long arg);
unsigned long noinline kprobe_target_func_irq(unsigned long arg);

enum kprobe_target_cmd {
	KPROBE_TARGET_RUN_FUNC		= 1313ULL,
	KPROBE_TARGET_RUN_FUNC_IRQ	= 1314ULL,
};



/* Defined as global to force standard calling convention */
unsigned long noinline kprobe_target_func(unsigned long arg)
{
	barrier();
	return arg;
}

/* Defined as global to force standard calling convention */
unsigned long noinline kprobe_target_func_irq(unsigned long arg)
{
	barrier();
	task_pid_vnr(current);
	return arg;
}

static long target_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KPROBE_TARGET_RUN_FUNC:
		return kprobe_target_func(arg);
	case KPROBE_TARGET_RUN_FUNC_IRQ:
		return kprobe_target_func_irq(arg);
	default:
		return -ENOSYS;
	}
}

struct proc_ops target_ops  = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_ioctl = target_ioctl,
};

static int __init target_init(void)
{
	if (!proc_create(PROC_FILE_NAME, 0600, NULL, &target_ops))
		return -ENOMEM;

	return 0;
}

static void __exit target_exit(void)
{
	remove_proc_entry(PROC_FILE_NAME, NULL);
}

module_init(target_init)
module_exit(target_exit)
MODULE_LICENSE("GPL");
