// SPDX-License-Identifier: GPL-2.0-only
/*
 * Architecture-independent code for Rex support
 */
#define pr_fmt(fmt) "rex: " fmt

#include <linux/filter.h>
#include <linux/hrtimer.h>

/* Set watchdog period to 20s */
#define WATCHDOG_PERIOD_MS 20000U

/* used by rex_terminate to check for BPF's IP before issuing termination */
DEFINE_PER_CPU(unsigned char, rex_termination_state);

/* Keeps track of prog start time */
DEFINE_PER_CPU(unsigned long, rex_prog_start_time);

/* Current program on this CPU */
DEFINE_PER_CPU(const struct bpf_prog *, rex_curr_prog);

struct rex_timer_data {
	struct hrtimer timer;
	int cpu_id;
	/* milliseconds */
	ktime_t start_delay;
};

struct rex_timer_data rex_timer1;
struct rex_timer_data rex_timer2;

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
		pr_info("No-op: wait for next timer invocation on the next CPU\n");
	}
}

void rex_terminate(void *data)
{
	struct termination_data *term_data = data;
	struct pt_regs *regs = term_data->regs;
	const struct bpf_prog *kill_prog = term_data->prog;
	int cpu_id = raw_smp_processor_id();
	int prog_id = kill_prog->aux->id;
	pr_warn("Rex_terminate invoked for prog:%d\n", prog_id);

	if (per_cpu(rex_termination_state, cpu_id) == 0) {
		pr_warn("Program not in any helper/panic.\n");
		regs->ip = kill_prog->saved_state->unwinder_insn_off;
	} else {
		pr_warn("Program in helper/panic.\n");
		per_cpu(rex_termination_state, cpu_id) = 2;
	}
}

static enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
	int i;
	pr_info("Rex_watchdog triggered\n");

	for_each_online_cpu(i)
		check_running_progs(i);

	/* Restart the timer */
	hrtimer_forward_now(timer, ms_to_ktime(WATCHDOG_PERIOD_MS * 2));

	return HRTIMER_RESTART; // Return HRTIMER_NORESTART to stop the timer
}

static void timer_init_fn(struct rex_timer_data *rex_timer)
{
	pr_info("Init time func on cpu %d\n", rex_timer->cpu_id);
	hrtimer_init(&rex_timer->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_PINNED);
	rex_timer->timer.function = &timer_callback;
}

static void start_timer_on_cpu(void *data)
{
	struct rex_timer_data *timer_data = data;
	/* Check if CPU is online */
	if (!cpu_online(timer_data->cpu_id)) {
		pr_err("CPU %d is not online.\n", timer_data->cpu_id);
		return;
	}

	/* boot the timer */
	hrtimer_start(&timer_data->timer, ms_to_ktime(timer_data->start_delay),
		      HRTIMER_MODE_REL_PINNED);

	return;
}

#define INIT_REX_TIMER(timer, cpu, delay_ms)  \
	do {                                  \
		timer.cpu_id = cpu;           \
		timer.start_delay = delay_ms; \
		timer_init_fn(&timer);        \
	} while (0)

static int init_rex_watchdog(void)
{
	int ret;
	pr_info("Initialize rex_watchdog\n");

	INIT_REX_TIMER(rex_timer1, 0, 0);
	INIT_REX_TIMER(rex_timer2, 1, WATCHDOG_PERIOD_MS);

	ret = smp_call_function_single(rex_timer1.cpu_id, start_timer_on_cpu,
				       &rex_timer1, true);
	if (ret) {
		pr_err("Failed to start timer on CPU %d\n", rex_timer1.cpu_id);
		return ret;
	}

	ret = smp_call_function_single(rex_timer2.cpu_id, start_timer_on_cpu,
				       &rex_timer2, true);
	if (ret) {
		pr_err("Failed to start timer on CPU %d\n", rex_timer2.cpu_id);
		/* cancel hrtimer1 since hrtimer2 failed to start */
		hrtimer_cancel(&rex_timer1.timer);
		return ret;
	}

	return 0;
}

static int __init init_rex(void)
{
	int ret = arch_init_rex_stack();
	return ret ?: init_rex_watchdog();
}

module_init(init_rex);
