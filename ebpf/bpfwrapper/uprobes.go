package bpfwrapper

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
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

// SetUprobeMultiAttachType upgrades all SEC("uprobe") programs in the spec to
// use BPF_TRACE_UPROBE_MULTI as their expected_attach_type, so they can be
// loaded and later attached via bpf(BPF_LINK_CREATE) instead of perf_event_open.
// This is a no-op if the kernel does not support uprobe_multi.
func SetUprobeMultiAttachType(spec *ebpf.CollectionSpec) {
	if features.HaveBPFLinkUprobeMulti() != nil {
		slog.Debug("kernel does not support uprobe_multi; using legacy perf-based uprobes")
		return
	}
	slog.Info("uprobe_multi supported; upgrading uprobe programs to BPF_TRACE_UPROBE_MULTI")
	for name, prog := range spec.Programs {
		if prog.Type == ebpf.Kprobe && prog.AttachType == 0 && prog.SectionName != "" &&
			(strings.HasPrefix(prog.SectionName, "uprobe") || strings.HasPrefix(prog.SectionName, "uretprobe")) {
			prog.AttachType = ebpf.AttachTraceUprobeMulti
			slog.Debug("upgraded program attach type", "name", name, "section", prog.SectionName)
		}
	}
}

// AttachUprobes attaches the given uprobe list using cilium/ebpf's link package.
// It prefers UprobeMulti (BPF_LINK_CREATE, no perf_event_open) when the kernel
// supports it, falling back to the legacy per-probe Uprobe path otherwise.
func AttachUprobes(soPath string, pid int, coll *ebpf.Collection, uprobeList []Uprobe) ([]link.Link, error) {
	if pid == -1 {
		pid = 0
	}

	useMulti := features.HaveBPFLinkUprobeMulti() == nil

	if useMulti {
		return attachUprobesMulti(soPath, pid, coll, uprobeList)
	}
	return attachUprobesLegacy(soPath, pid, coll, uprobeList)
}

// attachUprobesMulti uses UprobeMulti/UretprobeMulti which goes through
// bpf(BPF_LINK_CREATE) and does NOT call perf_event_open — so it is immune
// to perf_event_paranoid restrictions.
func attachUprobesMulti(soPath string, pid int, coll *ebpf.Collection, uprobeList []Uprobe) ([]link.Link, error) {
	ex, err := link.OpenExecutable(soPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable %q: %v", soPath, err)
	}

	multiOpts := &link.UprobeMultiOptions{
		PID: uint32(pid),
	}

	var links []link.Link

	for _, probe := range uprobeList {
		prog, ok := coll.Programs[probe.HookName]
		if !ok {
			return links, fmt.Errorf("BPF program %q not found in collection", probe.HookName)
		}

		isReturn := probe.Type == ReturnType || probe.Type == ReturnType_Matching_Pre

		switch probe.Type {
		case EntryType, ReturnType:
			syms := []string{probe.FunctionToHook}
			slog.Debug("Attaching uprobe-multi", "hook", probe.HookName, "function", probe.FunctionToHook, "return", isReturn)
			l, err := attachMultiLink(ex, syms, prog, multiOpts, isReturn)
			if err != nil {
				return links, fmt.Errorf("uprobe-multi %q to %q: %v", probe.HookName, probe.FunctionToHook, err)
			}
			links = append(links, l)

		case EntryType_Matching_Suf, EntryType_Matching_Pre:
			var pattern string
			if probe.Type == EntryType_Matching_Suf {
				pattern = getSuffixRegex(probe.FunctionToHook)
			} else {
				pattern = getPrefixRegex(probe.FunctionToHook)
			}
			syms, err := findMatchingSymbols(soPath, pattern)
			if err != nil {
				return links, fmt.Errorf("failed to scan symbols in %q: %v", soPath, err)
			}
			if len(syms) == 0 {
				continue
			}
			slog.Debug("Attaching uprobe-multi (pattern)", "hook", probe.HookName, "matches", len(syms))
			l, err := attachMultiLink(ex, syms, prog, multiOpts, false)
			if err != nil {
				slog.Error("uprobe-multi pattern attach failed", "hook", probe.HookName, "error", err)
				continue
			}
			links = append(links, l)

		case ReturnType_Matching_Pre:
			pattern := getPrefixRegex(probe.FunctionToHook)
			syms, err := findMatchingSymbols(soPath, pattern)
			if err != nil {
				return links, fmt.Errorf("failed to scan symbols in %q: %v", soPath, err)
			}
			if len(syms) == 0 {
				continue
			}
			slog.Debug("Attaching uretprobe-multi (pattern)", "hook", probe.HookName, "matches", len(syms))
			l, err := attachMultiLink(ex, syms, prog, multiOpts, true)
			if err != nil {
				slog.Error("uretprobe-multi pattern attach failed", "hook", probe.HookName, "error", err)
				continue
			}
			links = append(links, l)

		case ReturnType_Matching_Suf_Addr:
			// These are entry probes placed at specific RET instruction offsets
			// (to capture return values), NOT uretprobes.
			slog.Debug("Attaching uprobe-multi (addr offsets)", "hook", probe.HookName, "function", probe.FunctionToHook, "offsets", len(probe.Addresses))
			if len(probe.Addresses) == 0 {
				continue
			}
			syms := make([]string, len(probe.Addresses))
			offsets := make([]uint64, len(probe.Addresses))
			for i, addr := range probe.Addresses {
				syms[i] = probe.FunctionToHook
				offsets[i] = addr
			}
			optsWithOffsets := &link.UprobeMultiOptions{
				PID:     uint32(pid),
				Offsets: offsets,
			}
			l, err := attachMultiLink(ex, syms, prog, optsWithOffsets, false)
			if err != nil {
				slog.Error("uprobe-multi addr attach failed", "hook", probe.HookName, "error", err)
				continue
			}
			links = append(links, l)

		case EntryType_Abs_Offset:
			if len(probe.Addresses) == 0 {
				slog.Error("EntryType_Abs_Offset: no address provided", "hook", probe.HookName)
				continue
			}
			slog.Debug("Attaching uprobe-multi (abs offset)", "hook", probe.HookName, "offset", probe.Addresses[0])
			optsAbs := &link.UprobeMultiOptions{
				PID:       uint32(pid),
				Addresses: probe.Addresses[:1],
			}
			l, err := attachMultiLink(ex, nil, prog, optsAbs, false)
			if err != nil {
				slog.Error("uprobe-multi abs-offset attach failed", "hook", probe.HookName, "error", err)
				continue
			}
			links = append(links, l)

		default:
			return links, fmt.Errorf("unknown uprobe type %d for %q", probe.Type, probe.HookName)
		}
	}

	return links, nil
}

func attachMultiLink(ex *link.Executable, syms []string, prog *ebpf.Program, opts *link.UprobeMultiOptions, isReturn bool) (link.Link, error) {
	if opts == nil {
		opts = &link.UprobeMultiOptions{}
	}
	if isReturn {
		return ex.UretprobeMulti(syms, prog, opts)
	}
	return ex.UprobeMulti(syms, prog, opts)
}

// attachUprobesLegacy is the original per-probe attachment path using perf_event_open.
func attachUprobesLegacy(soPath string, pid int, coll *ebpf.Collection, uprobeList []Uprobe) ([]link.Link, error) {
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

		case EntryType_Abs_Offset:
			if len(probe.Addresses) == 0 {
				slog.Error("EntryType_Abs_Offset: no address provided", "hook", probe.HookName)
				continue
			}
			absOpts := &link.UprobeOptions{Offset: probe.Addresses[0]}
			if pid != 0 {
				absOpts.PID = pid
			}
			slog.Debug("Attaching abs-offset uprobe", "hook", probe.HookName, "offset", probe.Addresses[0])
			l, err := ex.Uprobe("", prog, absOpts)
			if err != nil {
				slog.Error("failed to attach abs-offset uprobe", "hook", probe.HookName, "offset", probe.Addresses[0], "error", err)
				continue
			}
			links = append(links, l)

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
	specialChars := []string{`\`, `.`, `^`, `$`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `|`}

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
