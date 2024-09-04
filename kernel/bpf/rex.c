// SPDX-License-Identifier: GPL-2.0-only
/*
 * Architecture-independent code for Rex support
 */
#define pr_fmt(fmt) "rex: " fmt

#include <linux/filter.h>

/* Set watchdog period to 20s */
#define WATCHDOG_PERIOD_MS 20000U

/* used by rex_terminate to check for BPF's IP before issuing termination */
DEFINE_PER_CPU(unsigned char, rex_termination_state);

/* Keeps track of prog start time */
DEFINE_PER_CPU(unsigned long, rex_prog_start_time);

/* Current program on this CPU */
DEFINE_PER_CPU(const struct bpf_prog *, rex_curr_prog);

static struct timer_list watchdog_timer;

static void check_running_progs(unsigned int cpu)
{
	unsigned long start_time;
	const struct bpf_prog *prog = per_cpu(rex_curr_prog, cpu);

	/* Program not running on this CPU */
	if (!prog || !prog->no_bpf)
		return;

	start_time = per_cpu(rex_prog_start_time, cpu);

	/* Not reaching timeout */
	if (time_is_after_jiffies(start_time +
				  msecs_to_jiffies(WATCHDOG_PERIOD_MS)))
		return;

	/* Send an IPI to the cpu the program runs on */
	if (cpu != raw_smp_processor_id()) {
		smp_call_function_single(cpu, rex_terminate, (void *)prog, 0);
	} else {
		/* No-op: wait for next timer invocation on the next CPU */
	}
}

static void watchdog_timer_fn(struct timer_list *timer)
{
	int i, next_cpu;
	printk("rex_watchdog triggered\n");

	for_each_online_cpu(i)
		check_running_progs(i);

	/* Setup timer on next CPU */
	del_timer(timer);
	next_cpu = cpumask_next(raw_smp_processor_id(), cpu_online_mask);
	if (next_cpu >= nr_cpu_ids)
		next_cpu = cpumask_first(cpu_online_mask);
	timer->expires = jiffies + msecs_to_jiffies(WATCHDOG_PERIOD_MS);
	add_timer_on(timer, next_cpu);
}

void rex_terminate(void *data)
{
	struct termination_data *term_data = data;
	struct pt_regs *regs = term_data->regs;
	const struct bpf_prog *kill_prog = term_data->prog;
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

static int init_rex_watchdog(void)
{
	pr_info("Initialize rex_watchdog\n");

	struct timer_list *timer = &watchdog_timer;
	timer_setup(timer, watchdog_timer_fn, 0);
	timer->expires = jiffies + msecs_to_jiffies(WATCHDOG_PERIOD_MS);
	add_timer_on(timer, cpumask_first(cpu_online_mask));

	return 0;
}

static int __init init_rex(void)
{
	int ret = arch_init_rex_stack();
	return ret ?: init_rex_watchdog();
}

module_init(init_rex);
