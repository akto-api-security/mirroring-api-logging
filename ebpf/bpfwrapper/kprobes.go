package bpfwrapper

import (
	"log"
	"runtime"

	"github.com/iovisor/gobpf/bcc"
)

const (
	maxActiveConnections = 1024
)

// ProbeType represents whether the probe is an entry or a return.
type ProbeType int

const (
	EntryType ProbeType = iota
	ReturnType
	EntryType_Matching_Suf
	ReturnType_Matching_Suf_Addr
	EntryType_Matching_Pre
	ReturnType_Matching_Pre
)

// Kprobe represents a single Kprobe hook.
type Kprobe struct {
	// The name of the function to hook.
	FunctionToHook string
	// The name of the hook function.
	HookName string
	// Whether a Kprobe or ret-Kprobe.
	Type ProbeType
	// Whether the function to hook is syscall or not.
	IsSyscall bool
}

func PlatformPrefix() string {
	switch runtime.GOARCH {
	case "386":
		return "__ia32_"
	case "amd64", "amd64p32":
		return "__x64_"

	case "arm", "armbe":
		return "__arm_"
	case "arm64", "arm64be":
		return "__arm64_"

	case "mips", "mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le":
		return "__mips_"

	case "s390":
		return "__s390_"
	case "s390x":
		return "__s390x_"

	case "riscv", "riscv64":
		return "__riscv_"

	case "ppc":
		return "__powerpc_"
	case "ppc64", "ppc64le":
		return "__powerpc64_"

	default:
		return ""
	}
}

// AttachKprobes attaches the given Kprobe list.
func AttachKprobes(bpfModule *bcc.Module, kprobeList []Kprobe) error {
	for _, probe := range kprobeList {
		functionToHook := probe.FunctionToHook
		if probe.IsSyscall {
			functionToHook = PlatformPrefix() + "sys_" + probe.FunctionToHook
		}

		probeFD, err := bpfModule.LoadKprobe(probe.HookName)
		if err != nil {
			log.Printf("failed to load %q due to: %v, skipping", probe.HookName, err)
			continue
		}

		switch probe.Type {
		case EntryType:
			log.Printf("Loading %q for %q as kprobe\n", probe.HookName, functionToHook)
			if err = bpfModule.AttachKprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				log.Printf("failed to attach kprobe %q to %q due to: %v, skipping", probe.HookName, functionToHook, err)
			}
			continue
		case ReturnType:
			log.Printf("Loading %q for %q as kretprobe\n", probe.HookName, functionToHook)
			if err = bpfModule.AttachKretprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				log.Printf("failed to attach kretprobe %q to %q due to: %v, skipping", probe.HookName, functionToHook, err)
			}
			continue
		default:
			log.Printf("unknown Kprobe type %d given for %q, skipping", probe.Type, probe.HookName)
			continue
		}
	}
	return nil
}
