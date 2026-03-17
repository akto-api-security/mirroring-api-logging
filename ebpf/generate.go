// generate.go documents the build steps needed to compile the BPF program.
//
// Primary build path (required):
//
//	make generate
//
// This runs bpftool to produce kernel/vmlinux.h, then compiles
// kernel/module.bpf.c → kernel/module.bpf.o with clang.
// The Go binary loads the .o at runtime via ebpf.LoadCollectionSpec.
//
// Optional — typed Go wrappers via bpf2go (not required for the binary to run):
//
//	go generate ./...
//
// bpf2go reads the BPF source and generates module_bpfel.go with typed
// map/program accessors (ModuleObjects, ModuleMaps, …). These are useful
// for testing and IDE completion but are not used by main.go.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -I./kernel -DCHUNK_SIZE_LIMIT=4" -target amd64,arm64 Module ./kernel/module.bpf.c

package main
