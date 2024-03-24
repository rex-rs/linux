#include <bpf/bpf_helpers.h>

SEC("kprobe/kprobe_target_func")
int bpf_prog1(struct pt_regs *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";