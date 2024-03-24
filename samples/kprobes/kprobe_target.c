// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/module.h>
#include <linux/proc_fs.h>

#define PROC_FILE_NAME "kprobe_target"

enum kprobe_target_cmd {
	KPROBE_TARGET_RUN_FUNC = 1313ULL,
};

int noinline kprobe_target_func(void)
{
	return 0;
}

static long target_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KPROBE_TARGET_RUN_FUNC:
		kprobe_target_func();
		return 0;
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
