// SPDX-License-Identifier: GPL-2.0-only
/*
 * Architecture-independent code for Rex support
 */
#define pr_fmt(fmt) "rex: " fmt

#include <linux/filter.h>
#include <linux/hrtimer.h>

#include <asm/irq_regs.h>

/* Set watchdog period to 20s */
#define WATCHDOG_PERIOD_MS 20000U

/* used by rex_terminate to check for BPF's IP before issuing termination */
DEFINE_PER_CPU(unsigned char, rex_termination_state);

/* Keeps track of prog start time */
DEFINE_PER_CPU(unsigned long, rex_prog_start_time);

/* Current program on this CPU */
DEFINE_PER_CPU(const struct bpf_prog *, rex_curr_prog);
EXPORT_SYMBOL(rex_curr_prog);

DEFINE_PER_CPU(struct hrtimer, rex_timer);

static void check_running_progs(void)
{
	unsigned long start_time;
	const struct bpf_prog *prog = this_cpu_read_stable(rex_curr_prog);

	/* Program not running on this CPU */
	if (!prog || !prog->no_bpf)
		return;

	start_time = this_cpu_read_stable(rex_prog_start_time);

	/* Not reaching timeout */
	if (time_is_after_jiffies(start_time +
				  msecs_to_jiffies(WATCHDOG_PERIOD_MS)))
		return;

	/* The program times out */
	rex_terminate(prog);
}

void rex_terminate(const struct bpf_prog *prog)
{
	struct pt_regs *regs;
	int prog_id;

	/* The termination handler is only supposed to be called in hardirq */
	WARN_ON(!in_hardirq());

	regs = get_irq_regs();
	prog_id = prog->aux->id;
	pr_warn("Rex_terminate invoked for prog:%d\n", prog_id);

	if (this_cpu_read_stable(rex_termination_state) == 0) {
		pr_warn("Program not in any helper/panic.\n");
		regs->ip = prog->saved_state->unwinder_insn_off;
	} else {
		pr_warn("Program in helper/panic.\n");
		this_cpu_write(rex_termination_state, 2);
	}
}

static enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
	// pr_info("Rex_watchdog triggered\n");

	check_running_progs();

	/* Restart the timer */
	hrtimer_forward_now(timer, ms_to_ktime(WATCHDOG_PERIOD_MS));

	/* Return HRTIMER_NORESTART to stop the timer */
	return HRTIMER_RESTART;
}

static void start_timer_on_cpu(void *data __always_unused)
{
	struct hrtimer *local_timer = this_cpu_ptr(&rex_timer);

	hrtimer_init(local_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	local_timer->function = &timer_callback;

	/* boot the timer */
	hrtimer_start(local_timer, ms_to_ktime(WATCHDOG_PERIOD_MS),
		      HRTIMER_MODE_REL_PINNED);

	pr_info("Initialize time func on cpu %d\n", smp_processor_id());
	return;
}

static int init_rex_watchdog(void)
{
	int i, ret;
	pr_info("Initialize rex_watchdog\n");

	for_each_online_cpu(i) {
		ret = smp_call_function_single(i, start_timer_on_cpu, NULL,
					       true);
		if (ret) {
			pr_err("Failed to start timer on CPU %d\n", i);
			return ret;
		}
	}

	return 0;
}

static int __init init_rex(void)
{
	int ret = arch_init_rex_stack();
	return ret ?: init_rex_watchdog();
}

module_init(init_rex);
