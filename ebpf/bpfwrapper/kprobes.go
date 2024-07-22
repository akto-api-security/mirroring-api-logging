package bpfwrapper

import (
	"log"

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

// AttachKprobes attaches the given Kprobe list.
func AttachKprobes(bpfModule *bcc.Module, kprobeList []Kprobe) error {
	for _, probe := range kprobeList {
		functionToHook := probe.FunctionToHook
		if probe.IsSyscall {
			functionToHook = bcc.GetSyscallFnName(probe.FunctionToHook)
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
				if probe.IsSyscall {
					log.Printf("Syscall loading failed, trying non-syscall loading %q for %q as kprobe", probe.HookName, probe.FunctionToHook)
					log.Printf("Loading %q for %q as kprobe\n", probe.HookName, probe.FunctionToHook)
					if err = bpfModule.AttachKprobe(probe.FunctionToHook, probeFD, maxActiveConnections); err != nil {
						log.Printf("failed to attach kprobe %q to %q due to: %v, skipping", probe.HookName, probe.FunctionToHook, err)
					}
				}
			}
			continue
		case ReturnType:
			log.Printf("Loading %q for %q as kretprobe\n", probe.HookName, functionToHook)
			if err = bpfModule.AttachKretprobe(functionToHook, probeFD, maxActiveConnections); err != nil {
				log.Printf("failed to attach kretprobe %q to %q due to: %v, skipping", probe.HookName, functionToHook, err)
				if probe.IsSyscall {
					log.Printf("Syscall loading failed, trying non-syscall loading %q for %q as kretprobe", probe.HookName, probe.FunctionToHook)
					log.Printf("Loading %q for %q as kretprobe\n", probe.HookName, probe.FunctionToHook)
					if err = bpfModule.AttachKretprobe(probe.FunctionToHook, probeFD, maxActiveConnections); err != nil {
						log.Printf("failed to attach kretprobe %q to %q due to: %v, skipping", probe.HookName, probe.FunctionToHook, err)
					}
				}
			}
			continue
		default:
			log.Printf("unknown Kprobe type %d given for %q, skipping", probe.Type, probe.HookName)
			continue
		}
	}
	return nil
}
