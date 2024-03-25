// SPDX-License-Identifier: GPL-2.0

#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct MapEntry {
	u64 data;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, MapEntry);
	__uint(max_entries, 256);
} map_array SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_dup")
int bpf_prog1(struct cpu_args *ctx)
{
	u64 start, end;
	u32 key = 0;
	struct MapEntry *entry = bpf_map_lookup_elem(&map_array, &key);

	if (entry) {
		start = bpf_ktime_get_ns();
		bpf_spin_lock(&entry->lock);
		bpf_spin_unlock(&entry->lock);
		end = bpf_ktime_get_ns();
		bpf_printk("Spinlock lock and unlock: %llu\n", end - start);
	} else {
		bpf_printk("Unable to look up map\n");
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
