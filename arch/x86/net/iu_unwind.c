/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bug.h>
#include <linux/compiler_types.h>
#include <linux/percpu.h>
#include <linux/printk.h>

DEFINE_PER_CPU(unsigned long, iu_sp);
DEFINE_PER_CPU(unsigned long, iu_fp);

__nocfi noinline void notrace __noreturn iu_landingpad(char *msg)
{
	/* Report error */
	pr_warn("Panic from inner-unikernel prog: %s\n", msg);
	dump_stack();

	/* Jump to trampoline */
	asm volatile(
		"jmp iu_panic_trampoline"
	);

	/* Unreachable, noreturn */
	BUG();
}
