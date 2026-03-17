# Makefile — build helpers for the eBPF/libbpf migration.
#
# Prerequisites:
#   bpftool  — generates vmlinux.h from the running kernel's BTF data
#   clang    — >= 10, to compile the BPF C program
#   go       — for `go build`
#
# Typical workflow on a Linux host:
#   make generate   # generate vmlinux.h then compile module.bpf.c → module.bpf.o
#   go build .      # build the Go binary (embeds no BPF code; loads .o at runtime)
#   BPF_OBJ_PATH=./kernel/module.bpf.o ./ebpf

VMLINUX_H  := kernel/vmlinux.h
BPF_SRC    := kernel/module.bpf.c
BPF_OBJ    := kernel/module.bpf.o

# Detect architecture for the correct clang -D flag.
ARCH       := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  ARCH_FLAG := -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
  ARCH_FLAG := -D__TARGET_ARCH_arm64
else
  ARCH_FLAG :=
endif

# BPF_CHUNK_SIZE_LIMIT mirrors the old Go env var; defaults to 4.
BPF_CHUNK_SIZE_LIMIT ?= 4

CLANG_FLAGS := -O2 -g -Wall -target bpf -I./kernel $(ARCH_FLAG) -DCHUNK_SIZE_LIMIT=$(BPF_CHUNK_SIZE_LIMIT)

.PHONY: all generate vmlinux bpf clean

all: generate

# Full pipeline: vmlinux.h → BPF object.
generate: vmlinux bpf

# Step 1: dump BTF from the running kernel into a C header.
vmlinux:
	@echo "Generating $(VMLINUX_H) from running kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "Done: $(VMLINUX_H)"

# Step 2: compile the BPF C program to a BPF ELF object.
bpf: $(VMLINUX_H)
	@echo "Compiling $(BPF_SRC) → $(BPF_OBJ) ..."
	clang $(CLANG_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "Done: $(BPF_OBJ)"

clean:
	rm -f $(VMLINUX_H) $(BPF_OBJ)
