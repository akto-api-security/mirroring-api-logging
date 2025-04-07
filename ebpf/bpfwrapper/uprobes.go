package bpfwrapper

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/iovisor/gobpf/bcc"
)

// Uprobe represents a single uprobe hook.
type Uprobe struct {
	// The name of the function to hook.
	FunctionToHook string
	// The name of the hook function.
	HookName string
	// Whether an uprobe or ret-uprobe.
	Type ProbeType
	// Whether the function to hook is syscall or not.
	BinaryPath string
	Addresses  []uint64
}

var uprobeRegexp = regexp.MustCompile("[^a-zA-Z0-9_]")

// AttachUprobes attaches the given uprobe list.
func AttachUprobes(soPath string, pid int, bpfModule *bcc.Module, uprobeList []Uprobe) error {
	for _, probe := range uprobeList {
		functionToHook := probe.FunctionToHook

		probeFD, err := bpfModule.LoadUprobe(probe.HookName)
		if err != nil {
			return fmt.Errorf("failed to load %q due to: %v", probe.HookName, err)
		}

		switch probe.Type {
		case EntryType:
			slog.Debug("Loading uprobe", "hook name: ", probe.HookName, "function: ", functionToHook)
			if err = bpfModule.AttachUprobe(soPath, functionToHook, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach uprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case ReturnType:
			slog.Debug("Loading uretprobe", "hook name: ", probe.HookName, "function: ", functionToHook)
			if err = bpfModule.AttachUretprobe(soPath, functionToHook, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach uretprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case EntryType_Matching_Suf:
			slog.Debug("Loading matching uprobe", "hook name: ", probe.HookName, "function: ", functionToHook)
			regex := getSuffixRegex(functionToHook)

			if err = bpfModule.AttachMatchingUprobes(soPath, regex, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach matching uprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case ReturnType_Matching_Suf_Addr:
			for _, add := range probe.Addresses {
				slog.Debug("Loading matching uretprobe", "hook name: ", probe.HookName, "function: ", functionToHook, "with add", add)
				path, addr, err := bcc.ResolveSymbolPath(soPath, functionToHook, 0x0, pid)
				if err != nil {
					slog.Error("resolv error", "error", err)
					continue
				}
				finalAddr := addr + add
				evName := fmt.Sprintf("akto_p_%s_0x%x", uprobeRegexp.ReplaceAllString(path, "_"), finalAddr)
				if err = bpfModule.AttachUProbeInternal(evName, bcc.BPF_PROBE_ENTRY, path, finalAddr, probeFD, pid); err != nil {
					slog.Error("failed to attach matching uretprobe", "hook name: ", probe.HookName, "function: ", functionToHook, "error", err)
					continue
				}
			}
		case EntryType_Matching_Pre:
			slog.Debug("Loading matching uprobe", "hook name: ", probe.HookName, "function: ", functionToHook)
			regex := getPrefixRegex(functionToHook)

			if err = bpfModule.AttachMatchingUprobes(soPath, regex, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach pre matching uprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		case ReturnType_Matching_Pre:
			slog.Debug("Loading matching uretprobe", "hook name: ", probe.HookName, "function: ", functionToHook)
			regex := getPrefixRegex(functionToHook)

			if err = bpfModule.AttachMatchingUretprobes(soPath, regex, probeFD, pid); err != nil {
				return fmt.Errorf("failed to attach matching uprobe %q to %q due to: %v", probe.HookName, functionToHook, err)
			}
		default:
			return fmt.Errorf("unknown uprobe type %d given for %q", probe.Type, probe.HookName)
		}
	}
	return nil
}

func getSuffixRegex(input string) string {
	return ".*" + escapeRegexChars(input) + "$"
}

func getPrefixRegex(input string) string {
	return "^" + escapeRegexChars(input) + ".*"
}

func escapeRegexChars(input string) string {
	// List of regex special characters that need to be escaped,
	// with the backslash itself included properly.
	specialChars := []string{`\`, `.`, `^`, `$`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `|`}

	// Escape each special character found in the input.
	// Start with the backslash to avoid double escaping issues.
	for _, char := range specialChars {
		if char == `\` {
			input = strings.ReplaceAll(input, char, `\\`)
		} else {
			escapedChar := `\` + char
			input = strings.ReplaceAll(input, char, escapedChar)
		}
	}

	return input
}
