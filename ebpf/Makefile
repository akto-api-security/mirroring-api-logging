# Makefile — build helpers for the eBPF/libbpf migration.
#
# CO-RE: build with a reference vmlinux.h; relocations apply at load against the
# host kernel BTF. Use either the running machine's BTF or a pinned BTF file.
#
#   make generate
#   VMLINUX_BTF=/path/to/vmlinux.btf make generate   # CI / reproducible builds
#
#   go build .   # loads kernel/module.bpf.o at runtime

VMLINUX_H  := kernel/vmlinux.h
BPF_SRC    := kernel/module.bpf.c
BPF_OBJ    := kernel/module.bpf.o

# Optional: reference vmlinux BTF when /sys/kernel/btf/vmlinux is unavailable.
VMLINUX_BTF ?=

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
	@echo "Generating $(VMLINUX_H)..."
ifeq ($(VMLINUX_BTF),)
	@test -r /sys/kernel/btf/vmlinux || (echo "No /sys/kernel/btf/vmlinux — set VMLINUX_BTF=/path/to/vmlinux.btf"; exit 1)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
else
	bpftool btf dump file $(VMLINUX_BTF) format c > $(VMLINUX_H)
endif
	@echo "Done: $(VMLINUX_H)"

# Step 2: compile the BPF C program to a BPF ELF object.
bpf: $(VMLINUX_H)
	@echo "Compiling $(BPF_SRC) → $(BPF_OBJ) ..."
	clang $(CLANG_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "Done: $(BPF_OBJ)"

clean:
	rm -f $(VMLINUX_H) $(BPF_OBJ)
