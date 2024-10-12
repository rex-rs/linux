// Referenced from bpf/samples/hello_kern.c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

#define noinline __attribute__((__noinline__))

static __u32 n;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} prog_map SEC(".maps");

static noinline int purgatory(struct pt_regs *ctx)
{
	bpf_tail_call(ctx, &prog_map, 0);

	/* bpf_printk("tailcall failed in purgatory\n"); */
	return 0;
}

SEC("kprobe/")
int calculate_tail_factorial(struct pt_regs *ctx)
{
	/* Base case */
	if(!n)
		return 0;

	/* Else, make tail call */
	n -= 1;
	bpf_tail_call(ctx, &prog_map, 0);

	/* bpf_printk("tailcall failed in factorial\n"); */
	return 0;
}

SEC("kprobe/kprobe_target_func")
int bpf_recursive(struct pt_regs *ctx)
{
	int ret = 0;
	/* n = ctx->rdi */
	n = (__u32)ctx->di;

	__u64 start = bpf_ktime_get_ns();
	purgatory(ctx);
	__u64 stop = bpf_ktime_get_ns();

	bpf_printk("Time: %llu", stop - start);
	return 0;
}

char _license[] SEC("license") = "GPL";
