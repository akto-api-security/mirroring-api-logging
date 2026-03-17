package bpfwrapper

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

// AttachUprobes attaches the given uprobe list using cilium/ebpf's link package.
// Returns the created links so the caller can close them when done.
func AttachUprobes(soPath string, pid int, coll *ebpf.Collection, uprobeList []Uprobe) ([]link.Link, error) {
	// Convert BCC's "-1 = all PIDs" convention to cilium/ebpf's "0 = system-wide".
	if pid == -1 {
		pid = 0
	}

	var links []link.Link

	for _, probe := range uprobeList {
		prog, ok := coll.Programs[probe.HookName]
		if !ok {
			return links, fmt.Errorf("BPF program %q not found in collection", probe.HookName)
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
			slog.Debug("Attaching uprobe", "hook", probe.HookName, "function", probe.FunctionToHook)
			l, err := ex.Uprobe(probe.FunctionToHook, prog, opts)
			if err != nil {
				return links, fmt.Errorf("failed to attach uprobe %q to %q: %v", probe.HookName, probe.FunctionToHook, err)
			}
			links = append(links, l)

		case ReturnType:
			slog.Debug("Attaching uretprobe", "hook", probe.HookName, "function", probe.FunctionToHook)
			l, err := ex.Uretprobe(probe.FunctionToHook, prog, opts)
			if err != nil {
				return links, fmt.Errorf("failed to attach uretprobe %q to %q: %v", probe.HookName, probe.FunctionToHook, err)
			}
			links = append(links, l)

		case EntryType_Matching_Suf:
			slog.Debug("Attaching suffix-matching uprobes", "hook", probe.HookName, "suffix", probe.FunctionToHook)
			pattern := getSuffixRegex(probe.FunctionToHook)
			syms, err := findMatchingSymbols(soPath, pattern)
			if err != nil {
				return links, fmt.Errorf("failed to scan symbols in %q: %v", soPath, err)
			}
			for _, sym := range syms {
				l, err := ex.Uprobe(sym, prog, opts)
				if err != nil {
					slog.Error("failed to attach matching uprobe", "hook", probe.HookName, "symbol", sym, "error", err)
					continue
				}
				links = append(links, l)
			}

		case ReturnType_Matching_Suf_Addr:
			// Attach entry probes at specific offsets within a function (at each RET address).
			// probe.Addresses contains the byte offsets of RET instructions from the function start.
			slog.Debug("Attaching suffix-match addr uprobes", "hook", probe.HookName, "function", probe.FunctionToHook)
			for _, add := range probe.Addresses {
				addrOpts := &link.UprobeOptions{Offset: add}
				if pid != 0 {
					addrOpts.PID = pid
				}
				l, err := ex.Uprobe(probe.FunctionToHook, prog, addrOpts)
				if err != nil {
					slog.Error("failed to attach addr uprobe", "hook", probe.HookName, "function", probe.FunctionToHook, "offset", add, "error", err)
					continue
				}
				links = append(links, l)
			}

		case EntryType_Matching_Pre:
			slog.Debug("Attaching prefix-matching uprobes", "hook", probe.HookName, "prefix", probe.FunctionToHook)
			pattern := getPrefixRegex(probe.FunctionToHook)
			syms, err := findMatchingSymbols(soPath, pattern)
			if err != nil {
				return links, fmt.Errorf("failed to scan symbols in %q: %v", soPath, err)
			}
			for _, sym := range syms {
				l, err := ex.Uprobe(sym, prog, opts)
				if err != nil {
					slog.Error("failed to attach matching uprobe", "hook", probe.HookName, "symbol", sym, "error", err)
					continue
				}
				links = append(links, l)
			}

		case ReturnType_Matching_Pre:
			slog.Debug("Attaching prefix-matching uretprobes", "hook", probe.HookName, "prefix", probe.FunctionToHook)
			pattern := getPrefixRegex(probe.FunctionToHook)
			syms, err := findMatchingSymbols(soPath, pattern)
			if err != nil {
				return links, fmt.Errorf("failed to scan symbols in %q: %v", soPath, err)
			}
			for _, sym := range syms {
				l, err := ex.Uretprobe(sym, prog, opts)
				if err != nil {
					slog.Error("failed to attach matching uretprobe", "hook", probe.HookName, "symbol", sym, "error", err)
					continue
				}
				links = append(links, l)
			}

		default:
			return links, fmt.Errorf("unknown uprobe type %d for %q", probe.Type, probe.HookName)
		}
	}

	return links, nil
}

// findMatchingSymbols reads the ELF symbol table of path and returns all symbol
// names that match the given regex pattern.
func findMatchingSymbols(path, pattern string) ([]string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF %q: %v", path, err)
	}
	defer f.Close()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile regex %q: %v", pattern, err)
	}

	// Gather both static and dynamic symbol tables.
	syms, _ := f.Symbols()
	dynSyms, _ := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	seen := make(map[string]bool)
	var result []string
	for _, sym := range syms {
		if re.MatchString(sym.Name) && !seen[sym.Name] {
			seen[sym.Name] = true
			result = append(result, sym.Name)
		}
	}
	return result, nil
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
