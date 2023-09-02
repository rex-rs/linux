/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bug.h>
#include <linux/compiler_types.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/pgtable.h>


#define IU_STACK_ORDER 3
#define IU_STACK_SIZE (PAGE_SIZE << IU_STACK_ORDER)

struct iu_stack {
	char stack[IU_STACK_SIZE];
} __aligned(IU_STACK_SIZE);

DEFINE_PER_CPU_PAGE_ALIGNED(struct iu_stack, iu_stack_backing_store) __visible;
DECLARE_INIT_PER_CPU(iu_stack_backing_store);
DEFINE_PER_CPU(void *, iu_stack_ptr);

static int map_iu_stack(unsigned int cpu)
{
	char *stack = (char *)per_cpu_ptr(&iu_stack_backing_store, cpu);
	struct page *pages[IU_STACK_SIZE / PAGE_SIZE];
	void *va;
	int i;

	for (i = 0; i < IU_STACK_SIZE / PAGE_SIZE; i++) {
		phys_addr_t pa = per_cpu_ptr_to_phys(stack + (i << PAGE_SHIFT));

		pages[i] = pfn_to_page(pa >> PAGE_SHIFT);
	}

	va = vmap(pages, IU_STACK_SIZE / PAGE_SIZE, VM_MAP, PAGE_KERNEL);
	if (!va)
		return -ENOMEM;

	/* Store actual TOS to avoid adjustment in the hotpath */
	per_cpu(iu_stack_ptr, cpu) = va + IU_STACK_SIZE;
	return 0;
}

static int __init init_iu_stack(void)
{
	int i, ret = 0;
	for_each_online_cpu(i) {
		ret = map_iu_stack(i);
		if (ret < 0)
			break;

		printk("Initialize iu_stack on CPU %d\n", i);
	}
	return ret;
}

module_init(init_iu_stack);

DEFINE_PER_CPU(unsigned long, iu_sp);
DEFINE_PER_CPU(unsigned long, iu_fp);


__nocfi noinline void notrace __noreturn iu_landingpad(char *msg)
{
	/* Report error */
	pr_warn("Panic from inner-unikernel prog: %s\n", msg);
	dump_stack();

	/* Jump to trampoline */
	asm volatile(
		"jmp iu_panic_trampoline"
	);

	/* Unreachable, noreturn */
	BUG();
}
