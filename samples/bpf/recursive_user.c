// Referenced from bpf/samples/hello_user.c
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *prog_map;
	char buf[128] = { 0 };

	snprintf(buf, sizeof(buf), "%s_kern.o", argv[0]);
	obj = bpf_object__open(buf);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog_map = bpf_object__find_map_by_name(obj, "prog_map");
	if (libbpf_get_error(prog_map)) {
		fprintf(stderr, "ERROR: Could not find map: prog_map\n");
		goto cleanup;
	}

	int prog_map_fd = bpf_object__find_map_fd_by_name(obj, "prog_map");

	prog = bpf_object__find_program_by_name(obj, "calculate_tail_factorial");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}
	int prog_fd_idx = 0;
	int prog_fd = bpf_program__fd(prog);
	if (bpf_map_update_elem(prog_map_fd, &prog_fd_idx, &prog_fd, BPF_ANY) < 0) {
		fprintf(stderr, "ERROR: updating prog array failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_recursive");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	bpf_link__pin(link, "/sys/fs/bpf/recursive_link");
	bpf_object__pin(obj, "/sys/fs/bpf/recursive_obj");

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}

