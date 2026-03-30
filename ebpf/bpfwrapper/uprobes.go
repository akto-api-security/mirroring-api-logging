package bpfwrapper

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Uprobe struct {
	FunctionToHook   string
	HookName         string
	Type             ProbeType
	Addresses        []uint64
	SymbolBaseOffset uint64
}

// AttachUprobes attaches a list of uprobes dynamically
func AttachUprobes(soPath string, pid int, coll *ebpf.Collection, uprobeList []Uprobe) ([]link.Link, error) {
	if pid == -1 {
		pid = 0
	}
	var links []link.Link
	for _, probe := range uprobeList {
		prog, ok := coll.Programs[probe.HookName]
		if !ok {
			return links, fmt.Errorf("BPF program %q not found", probe.HookName)
		}

		ex, err := link.OpenExecutable(soPath)
		if err != nil {
			return links, fmt.Errorf("failed to open executable %q: %v", soPath, err)
		}

		opts := &link.UprobeOptions{}
		if pid != 0 {
			opts.PID = pid
		}

		switch probe.Type {
		case EntryType:
			l, err := ex.Uprobe(probe.FunctionToHook, prog, opts)
			if err != nil {
				return links, fmt.Errorf("failed to attach uprobe: %v", err)
			}
			links = append(links, l)

		case ReturnType:
			l, err := ex.Uretprobe(probe.FunctionToHook, prog, opts)
			if err != nil {
				return links, fmt.Errorf("failed to attach uretprobe: %v", err)
			}
			links = append(links, l)

		case ReturnType_Matching_Suf_Addr:
			for _, add := range probe.Addresses {
				relOffset := add - probe.SymbolBaseOffset
				l, err := ex.Uprobe(probe.FunctionToHook, prog, &link.UprobeOptions{PID: pid, Offset: relOffset})
				if err != nil {
					slog.Error("failed to attach addr uprobe", "hook", probe.HookName, "offset", add, "error", err)
					continue
				}
				links = append(links, l)
			}

		default:
			return links, fmt.Errorf("unsupported probe type %d for %q", probe.Type, probe.HookName)
		}
	}
	return links, nil
}

// Helper to escape regex characters
func escapeRegexChars(input string) string {
	specialChars := []string{`\`, `.`, `^`, `$`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `|`}
	for _, char := range specialChars {
		if char == `\` {
			input = strings.ReplaceAll(input, char, `\\`)
		} else {
			input = strings.ReplaceAll(input, char, `\`+char)
		}
	}
	return input
}
