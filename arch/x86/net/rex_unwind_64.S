/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/* Dispatcher func for Rex */
SYM_FUNC_START(rex_dispatcher_func)
	/* save the callee-saved registers */
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	/* Save bpf func */
	movq %rdx, PER_CPU_VAR(rex_curr_prog)

	/* save rsp and rbp */
	movq %rsp, PER_CPU_VAR(rex_old_sp)
	movq %rbp, PER_CPU_VAR(rex_old_fp)

	/* switch stack */
	movq PER_CPU_VAR(rex_stack_ptr), %rsp
	movq PER_CPU_VAR(rex_stack_ptr), %rbp

	movq jiffies(%rip), %r11
	movq %r11, PER_CPU_VAR(rex_prog_start_time)

	/* invoke bpf func */
	call *%rdx

/* Exit path: rex_landingpad also redirects the control flow here */
SYM_INNER_LABEL(rex_exit, SYM_L_GLOBAL)
	/* reset rsp and rbp based on saved value */
	movq PER_CPU_VAR(rex_old_sp), %rsp
	movq PER_CPU_VAR(rex_old_fp), %rbp

	/* Reset bpf func */
	movq $0, PER_CPU_VAR(rex_curr_prog)

	/* restore the callee-saved registers */
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx

	/* Return */
	RET

SYM_FUNC_END(rex_dispatcher_func)
EXPORT_SYMBOL(rex_dispatcher_func)
