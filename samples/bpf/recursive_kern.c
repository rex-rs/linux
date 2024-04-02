// Referenced from bpf/samples/hello_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 3);
} data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} prog_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_execve(void *ctx)
{

	int pid = bpf_get_current_pid_tgid();

	// Checked that it's triggered by our own userspace proc
	__u32 pid_key = 0;
	__u32* pid_curr = (__u32*) bpf_map_lookup_elem(&data_map, &pid_key);
	if(pid_curr == 0 || *pid_curr != pid){
		return 0;
	}

	// Get the n and accum
	__u64 time = bpf_ktime_get_ns();
	bpf_printk("Time: %ul", time);
	__u32 n_key = 1;
	__u32 accum_key = 2;
	__u32* n_curr = (__u32*) bpf_map_lookup_elem(&data_map, &n_key);
	if(n_curr == 0){
		return 0;
	}
	__u32* accum_curr = (__u32*) bpf_map_lookup_elem(&data_map, &accum_key);
	if(accum_curr == 0){
		return 0;
	}

	__u32 accum = *accum_curr;
	__u32 n = *n_curr;
	bpf_printk("n: %d, accum: %d", n, accum);
	
	// Base case
	if(n == 1){
		__u64 time = bpf_ktime_get_ns();
		bpf_printk("Answer: %d, Time: %ul", accum, time);
		return 0;
	}

	// Else, update accum and make tail call
	accum *= n;
	n -= 1;
	bpf_map_update_elem(&data_map, &n_key, &n, BPF_ANY);
	bpf_map_update_elem(&data_map, &accum_key, &accum, BPF_ANY);
	bpf_tail_call(ctx, &prog_map, 0);
	// static long (*bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *) 12;

	return 0;
}

char _license[] SEC("license") = "GPL";
