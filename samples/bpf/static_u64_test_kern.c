
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __u64 global = 0;

int bpf_prog2(void)
{

    // Print the duration in nanoseconds
    global += 1;
    bpf_printk("Time elapsed: %llu", global);
    // bpf_printk("value: %u", lookup);
    return 0;
}

SEC("kprobe/kprobe_target_func")
int bpf_prog1(void)
{
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    __u64 val;

    // int value = bpf_get_prandom_u32();
    // bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);
    // global += 1;
    // asm volatile(""::: "memory");

    start_time = bpf_ktime_get_ns();
    val = global;
    end_time = bpf_ktime_get_ns();

    duration = end_time - start_time;

    // Print the duration in nanoseconds
    bpf_printk("Time elapsed: %llu %llu", duration, val);
    // bpf_printk("value: %u", lookup);
    return 0;
}
