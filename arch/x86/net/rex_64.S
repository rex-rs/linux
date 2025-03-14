/* SPDX-License-Identifier: GPL-2.0 */
/*
 * X86 asm for Rex support
 */
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/nospec-branch.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/*
 * Dispatcher func for Rex
 *
 * %rdi: ctx argument of the Rex program
 * %rsi: pointer to the Rex program struct
 * %rdx: fucntion pointer to the entry of the Rex program
 */
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
	CALL_NOSPEC rdx

/* 
 * Exit path: rex_landingpad also redirects the control flow here
 *
 * %rax: program return value or default return value in case of a panic
 * %rsp: top entry of the Rex stack
 */
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

/*
 * Low-level fixups for Rust panics
 */
SYM_FUNC_START(rex_landingpad_asm)
	/* set an return value of 0 */
	movq $0, %rax

	/* reset stack */
	movq PER_CPU_VAR(rex_stack_ptr), %rsp

	/* jump to exit path */
	jmp rex_exit
SYM_FUNC_END(rex_landingpad_asm)
STACK_FRAME_NON_STANDARD(rex_landingpad_asm);
