/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/* Dispatcher func for inner-unikernel */
SYM_FUNC_START(iu_dispatcher_func)
	/* save the callee-saved registers */
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	/* save rsp and rbp */
	movq %rsp, PER_CPU_VAR(iu_old_sp)
	movq %rbp, PER_CPU_VAR(iu_old_fp)

	/* switch stack */
	movq PER_CPU_VAR(iu_stack_ptr), %rsp
	movq PER_CPU_VAR(iu_stack_ptr), %rbp

	/* invoke bpf func */
	call *%rdx

/* Exit path */
iu_exit:
	/* reset rsp and rbp based on saved value */
	movq PER_CPU_VAR(iu_old_sp), %rsp
	movq PER_CPU_VAR(iu_old_fp), %rbp

	/* restore the callee-saved registers */
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx

	/* Return */
	RET

/* Rust panic path */
SYM_INNER_LABEL(iu_panic_trampoline, SYM_L_GLOBAL)
	/* Give a EINVAL as return value */
	movq $(-EINVAL), %rax

	/* Exit */
	jmp iu_exit

SYM_FUNC_END(iu_dispatcher_func)
