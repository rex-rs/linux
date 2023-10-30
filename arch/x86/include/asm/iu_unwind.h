/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_IU_UNWIND_H
#define _ASM_X86_IU_UNWIND_H

#include <linux/linkage.h>

#ifndef __ASSEMBLY__

struct bpf_insn;

extern asmlinkage unsigned int iu_dispatcher_func(
	const void *ctx,
	const struct bpf_insn *insnsi,
	unsigned int (*bpf_func)(const void *,
				 const struct bpf_insn *));

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_IU_UNWIND_H */