
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000);
    __type(key, int);
    __type(value, int);
} my_map SEC(".maps");

SEC("kprobe/kprobe_target_func")
int bpf_prog1(void)
{
    int key = 2500;
    __u64 start_time;
    __u64 end_time;
    __u64 duration;

    int value = bpf_get_prandom_u32();
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    start_time = bpf_ktime_get_ns();
    bpf_map_lookup_elem(&my_map, &key);
    end_time = bpf_ktime_get_ns();

    duration = end_time - start_time;

    // Print the duration in nanoseconds
    bpf_printk("Time elapsed: %llu", duration);
    return 0;
}
