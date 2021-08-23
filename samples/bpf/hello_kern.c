// SPDX-License-Identifier: GPL-2.0
/* Refer to samples/bpf/tcp_bpf.readme for the instructions on
 * how to run this sample program.
 */
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";

SEC("hello")
int _hello()
{
	bpf_printk("hello bpf\n");

	return 1;
}
