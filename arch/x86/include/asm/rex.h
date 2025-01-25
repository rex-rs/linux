/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_REX_UNWIND_H
#define _ASM_X86_REX_UNWIND_H

#include <linux/linkage.h>
#include <linux/percpu.h>

#ifndef __ASSEMBLY__

/*
 * Total stack is 8 pages (32k) large. 4 pages are reserved for kernel helpers/
 * Therefore, the actual usable stack is 4 pages.
 */
#define REX_STACK_ORDER 3
#define REX_STACK_SIZE (PAGE_SIZE << REX_STACK_ORDER)

struct bpf_prog;
struct bpf_insn;

DECLARE_PER_CPU(unsigned char, rex_termination_state);
DECLARE_PER_CPU(void *, rex_stack_ptr);

extern asmlinkage unsigned int rex_dispatcher_func(
	const void *ctx,
	const struct bpf_prog *prog,
	unsigned int (*bpf_func)(const void *,
				 const struct bpf_insn *));

int arch_init_rex_stack(void);

static __always_inline bool arch_on_rex_stack(struct pt_regs *regs)
{
	unsigned long sp = regs->sp;
	u64 rex_tos = (u64)this_cpu_read_stable(rex_stack_ptr);
	return sp >= (rex_tos + 8 - REX_STACK_SIZE) && sp < (rex_tos + 8);
}

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_REX_UNWIND_H */
