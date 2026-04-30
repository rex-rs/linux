// SPDX-License-Identifier: GPL-2.0-only
/*
 * Architecture-independent code for Rex support
 */
#define pr_fmt(fmt) "rex: " fmt

#include <linux/filter.h>
#include <linux/perf_event.h>
#include <linux/printk.h>
#include <linux/percpu.h>

#include <asm/irq_regs.h>

/* Per-cpu log buffer to format printk and panic messages */
DEFINE_PER_CPU(char[MAX_BPRINTF_BUF], rex_log_buf) = { 0 };

/* Set watchdog period to 20s */
#define WATCHDOG_PERIOD_MS 20000ULL

/* used by rex_terminate to check for BPF's IP before issuing termination */
DEFINE_PER_CPU(unsigned char, rex_termination_state);

/* Keeps track of prog start time */
DEFINE_PER_CPU(unsigned long, rex_prog_start_time);

/* Current program on this CPU */
DEFINE_PER_CPU(const struct bpf_prog *, rex_curr_prog);
EXPORT_SYMBOL(rex_curr_prog);

/* Per-CPU NMI watchdog event */
DEFINE_PER_CPU(struct perf_event *, rex_nmi_events);

void rex_terminate(const struct bpf_prog *prog, struct pt_regs *regs)
{
	int prog_id;

	/*
	 * Invoked from PMI overflow, which is delivered as NMI on x86. NMI
	 * is required so we can preempt programs running with IRQs disabled.
	 */
	WARN_ON(!in_nmi());

	/* We interrupted something that is not a rex program, probably some other softirq */
	if (!arch_on_rex_stack(regs)) {
		this_cpu_write(rex_termination_state, 2);
		return;
	}

	prog_id = prog->aux->id;
	printk_deferred(KERN_WARNING "rex_terminate invoked for prog:%d\n",
			prog_id);

	if (this_cpu_read_stable(rex_termination_state) == 0) {
		printk_deferred(KERN_WARNING
				"Program not in any helper/panic.\n");

		/*
		 * On x86_64, NMI uses two iret frames: the "outermost" frame
		 * mapped by pt_regs (which regs->ip writes to) is a backup,
		 * and a separate "iret" frame just above pt_regs that iretq
		 * actually pops. The asm copies outermost->iret BEFORE the C
		 * handler runs, so writing only regs->ip leaves iret stale and
		 * the CPU returns to the interrupted IP. We must patch both.
		 */
		regs->ip = prog->saved_state->unwinder_insn_off;
		if (in_nmi()) {
			/*
			* The NMI iret frame sits immediately after pt_regs on the stack.
			* See entry_64.S — search for "outermost RIP".
			*/
			unsigned long *iret_ip = (unsigned long *)(regs + 1);
			*iret_ip = prog->saved_state->unwinder_insn_off;
		}
	} else {
		printk_deferred(KERN_WARNING "Program in helper/panic.\n");
		this_cpu_write(rex_termination_state, 2);
	}
}

static void rex_nmi_overflow(struct perf_event *event,
			     struct perf_sample_data *data,
			     struct pt_regs *regs)
{
	printk_deferred(KERN_INFO "Program in helper/panic.\n");
	if (unlikely(!regs))
		return;

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
	rex_terminate(prog, regs);
}

static void rex_release_nmi_events(void)
{
	int cpu;

	/*
	* NOTE: need to check for this function if hotplug coverage becomes
	* required.
	*/
	for_each_online_cpu(cpu) {
		struct perf_event *e = per_cpu(rex_nmi_events, cpu);
		if (e) {
			perf_event_release_kernel(e);
			per_cpu(rex_nmi_events, cpu) = NULL;
		}
	}
}

static int init_rex_watchdog(void)
{
	/*
	* Period is derived from cpu_khz, which is calibrated at boot. TSC
	* scaling under turbo/idle states can drift the effective period by
	* a few percent; acceptable for a coarse 20s timeout. If tighter
	* accuracy is needed, switch to a fixed-rate reference clocksource
	* or recompute on cpufreq transitions.
	*/
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.size = sizeof(attr),
		.sample_period = (u64)cpu_khz * WATCHDOG_PERIOD_MS,
		.pinned = 1,
		.disabled = 1,
	};
	int cpu;

	pr_info("Initialize rex_watchdog (NMI)\n");

	for_each_online_cpu(cpu) {
		struct perf_event *e = perf_event_create_kernel_counter(
			&attr, cpu, NULL, rex_nmi_overflow, NULL);
		if (IS_ERR(e)) {
			pr_err("Failed to create NMI event on CPU %d: %ld\n",
			       cpu, PTR_ERR(e));
			rex_release_nmi_events();
			return PTR_ERR(e);
		}
		per_cpu(rex_nmi_events, cpu) = e;
		perf_event_enable(e);
		pr_info("NMI watchdog armed on CPU %d\n", cpu);
	}
	return 0;
}

static int __init init_rex(void)
{
	int ret = arch_init_rex_stack();
	return ret ?: init_rex_watchdog();
}

module_init(init_rex);
