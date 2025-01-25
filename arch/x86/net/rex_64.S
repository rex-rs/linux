/* SPDX-License-Identifier: GPL-2.0 */
/*
 * X86 asm for Rex support
 */
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/* Dispatcher func for Rex */
SYM_FUNC_START(rex_dispatcher_func)
	/* save the callee-saved registers and the frame pointer*/
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	/* switch stack and save old rsp*/
	movq PER_CPU_VAR(rex_stack_ptr), %rbp
	movq %rsp, (%rbp)
	movq %rbp, %rsp

	/* record start time */
	movq jiffies(%rip), %r11
	movq %r11, PER_CPU_VAR(rex_prog_start_time)

	/* let the timer know we are in */
	movq %rsi, PER_CPU_VAR(rex_curr_prog)

	/* invoke bpf func */
	call *%rdx

/* Exit path: rex_landingpad also redirects the control flow here */
SYM_INNER_LABEL(rex_exit, SYM_L_GLOBAL)
	/* let the timer know we are out */
	movq $0, PER_CPU_VAR(rex_curr_prog)

	/* pop old stack pointer into rsp */
	popq %rsp

	/* restore the callee-saved registers and the frame pointer */
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp

	/* return */
	RET
SYM_FUNC_END(rex_dispatcher_func)
EXPORT_SYMBOL(rex_dispatcher_func)
