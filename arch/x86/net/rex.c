/* SPDX-License-Identifier: GPL-2.0 */
/*
 * X86-specific code for Rex support
 */
#define pr_fmt(fmt) "rex: " fmt

#include <linux/bpf.h>
#include <linux/compiler_types.h>
#include <linux/module.h>
#include <linux/objtool.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/rex.h>

/* Align to page size, since the stack trace is broken anyway */
struct rex_stack {
	char stack[REX_STACK_SIZE];
} __aligned(PAGE_SIZE);

DEFINE_PER_CPU_PAGE_ALIGNED(struct rex_stack, rex_stack_backing_store)
__visible;
DECLARE_INIT_PER_CPU(rex_stack_backing_store);
DEFINE_PER_CPU(void *, rex_stack_ptr);

DECLARE_PER_CPU(const struct bpf_prog *, rex_curr_prog);

/*
 * Not supposed to be called by other kernel code, therefore keep prototype
 * private
 */
void rex_landingpad(char *msg) __noreturn;

static int map_rex_stack(unsigned int cpu)
{
	char *stack = (char *)per_cpu_ptr(&rex_stack_backing_store, cpu);
	struct page *pages[REX_STACK_SIZE / PAGE_SIZE];
	void *va;
	int i;

	for (i = 0; i < REX_STACK_SIZE / PAGE_SIZE; i++) {
		phys_addr_t pa = per_cpu_ptr_to_phys(stack + (i << PAGE_SHIFT));

		pages[i] = pfn_to_page(pa >> PAGE_SHIFT);
	}

	va = vmap(pages, REX_STACK_SIZE / PAGE_SIZE, VM_MAP, PAGE_KERNEL);
	if (!va)
		return -ENOMEM;

	/* Store actual TOS to avoid adjustment in the hotpath */
	per_cpu(rex_stack_ptr, cpu) = va + REX_STACK_SIZE - 8;

	pr_info("Initialize rex_stack on CPU %d at 0x%llx\n", cpu,
		((u64)va) + REX_STACK_SIZE);

	return 0;
}

int arch_init_rex_stack(void)
{
	int i, ret = 0;
	for_each_online_cpu(i) {
		ret = map_rex_stack(i);
		if (ret < 0) {
			pr_err("Failed to initialize rex stack on CPU %d\n", i);
			break;
		}
	}
	return ret;
}

void __noreturn rex_landingpad(char *msg)
{
	struct task_struct *loader;

	/* Report error */
	WARN(true, "Panic from Rex prog: %s\n", msg);

	loader = find_task_by_pid_ns(
		this_cpu_read_stable(rex_curr_prog)->saved_state->loader_pid,
		&init_pid_ns);

	/* Reuse the seccomp signal for now */
	if (loader)
		force_sig_fault_to_task(SIGSYS, SYS_SECCOMP, NULL, loader);

	/* Reset the rex_termination_state set in rex panic handler */
	this_cpu_write(rex_termination_state, 0);

	asm volatile("jmp rex_landingpad_asm");
	/* Unreachable, noreturn */
	unreachable();
}
