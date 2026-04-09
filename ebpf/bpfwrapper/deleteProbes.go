package bpfwrapper

import (
	"log/slog"
)

// DeleteExistingAktoKernelProbes is a no-op with cilium/ebpf link-based
// kprobes — the kernel automatically detaches probes when their fd is closed.
// Kept as a stub so callers don't need updating.
func DeleteExistingAktoKernelProbes() {
	slog.Debug("cilium/ebpf link-based probes are cleaned up automatically on fd close; skipping legacy perf probe cleanup")
}
