// SPDX-License-Identifier: GPL-2.0-only
#include <linux/filter.h>

/* used by rex_terminate to check for BPF's IP before issuing termination */
DEFINE_PER_CPU(unsigned char, rex_termination_state);

void rex_terminate(void *data)
{
	struct termination_data *term_data = data;
	struct pt_regs *regs = term_data->regs;
	struct bpf_prog *kill_prog = term_data->prog;
	int cpu_id = raw_smp_processor_id();
	int prog_id = kill_prog->aux->id;
	printk("rex_terminate invoked for prog:%d\n", prog_id);

	if (per_cpu(rex_termination_state, cpu_id) == 0) {
		printk("Program not in any helper/panic.\n");
		regs->ip = kill_prog->saved_state->unwinder_insn_off;
	} else {
		printk("Program in helper/panic.\n");
		per_cpu(rex_termination_state, cpu_id) = 2;
	}
}
