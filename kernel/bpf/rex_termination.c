// SPDX-License-Identifier: GPL-2.0-only

#include <linux/filter.h>

/* Set watchdog period to 20s */
#define WATCHDOG_PERIOD_MS 20000U

/* used by rex_terminate to check for BPF's IP before issuing termination */
DEFINE_PER_CPU(unsigned char, rex_termination_state);

static struct timer_list watchdog_timer;

static void watchdog_timer_fn(struct timer_list *timer)
{
	printk("rex_watchdog triggered\n");
	mod_timer(timer, jiffies + msecs_to_jiffies(WATCHDOG_PERIOD_MS));
}

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

static int __init init_rex_termination(void)
{
	timer_setup(&watchdog_timer, watchdog_timer_fn, 0);
	printk("Initialize rex_watchdog\n");
	return mod_timer(&watchdog_timer,
			 jiffies + msecs_to_jiffies(WATCHDOG_PERIOD_MS));
}

module_init(init_rex_termination);