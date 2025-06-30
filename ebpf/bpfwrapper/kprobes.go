package bpfwrapper

import (
	"log/slog"
	"runtime"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/iovisor/gobpf/bcc"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
)

const (
	maxActiveConnections = 1024
)



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
func AttachKprobes(bpfModule *bcc.Module, kprobeList []structs.Kprobe) error {
	for _, probe := range kprobeList {
		functionToHook := probe.FunctionToHook
		if probe.IsSyscall {
			functionToHook = PlatformPrefix() + "sys_" + probe.FunctionToHook
		}

		probeFD, err := bpfModule.LoadKprobe(probe.HookName)
		if err != nil {
			slog.Error("failed to load kprobe", "hook", probe.HookName, "error", err)
			continue
		}

		switch probe.Type {
		case structs.EntryType:
			utils.PrintLog("Loading kprobe", "hook", probe.HookName, "as kprobe", functionToHook)
			if err = bpfModule.AttachKprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				slog.Error("failed to attach kprobe", "hook", probe.HookName, "function", functionToHook, "error", err)
			}
			continue
		case structs.ReturnType:
			utils.PrintLog("Loading kretprobe", "hook", probe.HookName, "as kretprobe", functionToHook)
			if err = bpfModule.AttachKretprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				slog.Error("failed to attach kretprobe", "hook", probe.HookName, "function", functionToHook, "error", err)
			}
			continue
		default:
			slog.Error("unknown Kprobe type given for hook", "type", probe.Type, "hook", probe.HookName)
			continue
		}
	}
	return nil
}
