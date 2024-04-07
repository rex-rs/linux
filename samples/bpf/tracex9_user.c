// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <linux/types.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int ret;

	int interface_idx = atoi(argv[1]);
	unsigned int xdp_flags = 0;
	xdp_flags |= XDP_FLAGS_SKB_MODE;

	obj = bpf_object__open_file("tracex9_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		goto cleanup;
	}
	int xdp_main_prog_fd = bpf_program__fd(prog);

	if (bpf_set_link_xdp_fd(interface_idx, xdp_main_prog_fd, xdp_flags) < 0) {
		fprintf(stderr, "ERROR: xdp failed");
	}


cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
