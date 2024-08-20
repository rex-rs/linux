/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/compiler_types.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/pgtable.h>

/*
 * Total stack is 8 pages (32k) large. 4 pages are reserved for kernel helpers/
 * Therefore, the actual usable stack is 4 pages.
 */
#define REX_STACK_ORDER 3
#define REX_STACK_SIZE (PAGE_SIZE << REX_STACK_ORDER)

// Align to page size, since the stack trace is broken anyway
struct rex_stack {
	char stack[REX_STACK_SIZE];
} __aligned(PAGE_SIZE);

DEFINE_PER_CPU_PAGE_ALIGNED(struct rex_stack, rex_stack_backing_store) __visible;
DECLARE_INIT_PER_CPU(rex_stack_backing_store);
DEFINE_PER_CPU(void *, rex_stack_ptr);

__nocfi noinline void notrace __noreturn rex_landingpad(char *msg);

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
	per_cpu(rex_stack_ptr, cpu) = va + REX_STACK_SIZE;

	printk("Initialize rex_stack on CPU %d at 0x%llx\n", cpu,
	       ((u64)va) + REX_STACK_SIZE);

	return 0;
}

static int __init init_rex_stack(void)
{
	int i, ret = 0;
	for_each_online_cpu (i) {
		ret = map_rex_stack(i);
		if (ret < 0)
			break;
	}
	return ret;
}

module_init(init_rex_stack);

DEFINE_PER_CPU(unsigned long, rex_old_sp);
DEFINE_PER_CPU(unsigned long, rex_old_fp);

__nocfi noinline void notrace __noreturn rex_landingpad(char *msg)
{
	/* Report error */
	WARN(true, "Panic from inner-unikernel prog: %s\n", msg);

	/* Set an return value of 0 and jump to trampoline */
	asm volatile(
		"movq $0,%%rax\n\t"
		"jmp rex_exit\n\t"
		: : :"rax"
	);

	/* Unreachable, noreturn */
	unreachable();
}
