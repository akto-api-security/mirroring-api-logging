package bpfwrapper

import (
	"log/slog"
	"runtime"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
	// EntryType_Abs_Offset attaches an entry uprobe at an absolute ELF file offset
	// (stored in Addresses[0]) with no symbol name lookup. Use this when the symbol
	// is not in the standard .symtab but its file offset is known (e.g. from .gopclntab).
	EntryType_Abs_Offset
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

// AttachKprobes attaches the given kprobe list using cilium/ebpf's link package.
// The returned links must be closed by the caller when done.
func AttachKprobes(coll *ebpf.Collection, kprobeList []Kprobe) ([]link.Link, error) {
	var links []link.Link

	for _, probe := range kprobeList {
		functionToHook := probe.FunctionToHook
		if probe.IsSyscall {
			functionToHook = PlatformPrefix() + "sys_" + probe.FunctionToHook
		}

		prog, ok := coll.Programs[probe.HookName]
		if !ok {
			slog.Error("BPF program not found in collection", "hook", probe.HookName)
			continue
		}

		switch probe.Type {
		case EntryType:
			utils.PrintLog("Attaching kprobe", "hook", probe.HookName, "function", functionToHook)
			l, err := link.Kprobe(functionToHook, prog, nil)
			if err != nil {
				slog.Error("failed to attach kprobe", "hook", probe.HookName, "function", functionToHook, "error", err)
				continue
			}
			links = append(links, l)

		case ReturnType:
			utils.PrintLog("Attaching kretprobe", "hook", probe.HookName, "function", functionToHook)
			l, err := link.Kretprobe(functionToHook, prog, nil)
			if err != nil {
				slog.Error("failed to attach kretprobe", "hook", probe.HookName, "function", functionToHook, "error", err)
				continue
			}
			links = append(links, l)

		default:
			slog.Error("unknown Kprobe type", "type", probe.Type, "hook", probe.HookName)
		}
	}

	return links, nil
}
