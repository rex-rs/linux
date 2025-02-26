
make = find_program('make')

kernel_config = custom_target(
  'kernel-config',
  output: ['.config'],
  command: [
    'cp', '@SOURCE_ROOT@/scripts/q-script/.config', '@OUTPUT@'
  ],
  console: true,
  build_by_default: false
)

build_dir = meson.current_build_dir()

kernel_build = custom_target(
  'kernel-build',
  output: ['vmlinux'],
  command: [
    'make', '-C','@SOURCE_ROOT@/linux','-kj', '32', 'O=' + build_dir
  ],
  env: ['LLVM=1'],
  console: true,
  depends: kernel_config,
  build_by_default: false
)

kernel_libbpf = custom_target(
  'kernel-libbpf',
  output: ['libbpf.so', 'bpf_helper_defs.h'],
  command: [
    make, '-C', '@SOURCE_ROOT@/linux/tools/lib/bpf/', '-kj', '32', 'O=' + build_dir
  ],
  env: ['LLVM=1'],
  console: true,
  depends: kernel_build,
  build_by_default: true,
)

subdir('usr')
subdir('tools')

kernel_dep = declare_dependency(
  include_directories: kernel_usr_inc
)

libbpf_dep = declare_dependency(
  link_with: kernel_libbpf[0],
  include_directories: kernel_toolslib_inc,
  sources: kernel_libbpf[1]
)
