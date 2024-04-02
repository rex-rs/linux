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
	struct bpf_map *data, *prog_map;

	obj = bpf_object__open_file("recursive_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	data = bpf_object__find_map_by_name(obj, "data_map");
	if (libbpf_get_error(data)) {
		fprintf(stderr, "ERROR: Could not find map: data_map\n");
		goto cleanup;
	}
	prog_map = bpf_object__find_map_by_name(obj, "prog_map");
	if (libbpf_get_error(prog_map)) {
		fprintf(stderr, "ERROR: Could not find map: prog_map\n");
		goto cleanup;
	}
	int data_map_fd = bpf_object__find_map_fd_by_name(obj, "data_map");
	int prog_map_fd = bpf_object__find_map_fd_by_name(obj, "prog_map");

	int pid_key = 0;
	int n_key = 1;
	int accum_key = 2;

	int pid = getpid();
	printf("PID: %d\n", pid);
	int n_init = 10;
	int accum_init = 1;
	bpf_map_update_elem(data_map_fd, &pid_key, &pid, BPF_ANY);
	bpf_map_update_elem(data_map_fd, &n_key, &n_init, BPF_ANY);
	bpf_map_update_elem(data_map_fd, &accum_key, &accum_init, BPF_ANY);

	prog = bpf_object__find_program_by_name(obj, "trace_enter_execve");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}
	int prog_fd_index = 0;
	int prog_fd = bpf_program__fd(prog);
	printf("Prog fd: %d\n", prog_fd);
	bpf_map_update_elem(prog_map_fd, &prog_fd_index, &prog_fd, BPF_ANY);

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	fprintf(stdout, "Triggered a write syscall\n");

	bpf_link__pin(link, "/sys/fs/bpf/recursive_link");

	scanf("Waiting...");

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}

