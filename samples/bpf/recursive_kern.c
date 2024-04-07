// Referenced from bpf/samples/hello_kern.c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

#define noinline __attribute__((__noinline__))

/* accum = state[63:32], n = state[31:0] */
static __u64 state;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} prog_map SEC(".maps");

static noinline int purgatory(struct pt_regs *ctx)
{
	bpf_tail_call(ctx, &prog_map, 0);

	bpf_printk("tailcall failed\n");
	return 0;
}

SEC("kprobe/")
int calculate_tail_factorial(struct pt_regs *ctx)
{
	/* Get the n and accum */
	__u32 accum = state >> 32;
	__u32 n = state & 0xFFFFFFFFULL;

	/* Base case */
	if(!n)
		return 0;

	/* Else, update accum and make tail call */
	accum += n;
	n -= 1;
	state = (((__u64)accum) << 32) | n;
	bpf_tail_call(ctx, &prog_map, 0);

	bpf_printk("tailcall failed\n");
	return 0;
}

SEC("kprobe/kprobe_target_func")
int bpf_recursive(struct pt_regs *ctx)
{
	int ret = 0;
	/* accum = 0, n = ctx->rdi */
	state = ctx->di & 0xFFFFFFFFULL;

	__u64 start = bpf_ktime_get_ns();
	ret = purgatory(ctx);
	__u64 stop = bpf_ktime_get_ns();

	bpf_printk("Time: %llu\n", stop - start);
	return 0;
}

char _license[] SEC("license") = "GPL";
