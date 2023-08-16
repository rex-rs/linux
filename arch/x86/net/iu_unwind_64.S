/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/* Dispatcher func for inner-unikernel */
SYM_FUNC_START(iu_dispatcher_func)
	/* save rsp and rbp */
	movq %rsp, PER_CPU_VAR(iu_sp)
	movq %rbp, PER_CPU_VAR(iu_fp)

	/* invoke bpf func */
	call *%rdx

/* Exit path */
SYM_INNER_LABEL(iu_exit, SYM_L_LOCAL)
	RET

/* Rust panic path */
SYM_INNER_LABEL(iu_panic_trampoline, SYM_L_GLOBAL)
	/* reset rsp and rbp based on saved value */
	movq PER_CPU_VAR(iu_sp), %rsp
	movq PER_CPU_VAR(iu_fp), %rbp

	/* Give a EINVAL as return value */
	movq $(-EINVAL), %rax

	/* Exit */
	jmp iu_exit

SYM_FUNC_END(iu_dispatcher_func)
