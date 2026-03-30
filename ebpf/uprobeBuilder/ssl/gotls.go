package ssl

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/elf"
	"github.com/cilium/ebpf"
)

var (
	buildVersion   = "runtime.buildVersion"
	goVersionRegex = regexp.MustCompile(`^go(?P<Major>\d)\.(?P<Minor>\d+)`)

	goTLSWriteSymbol = "crypto/tls.(*Conn).Write"
	goTLSReadSymbol  = "crypto/tls.(*Conn).Read"

	goTLSGIDStatusSymbol = "runtime.g"               // goid field
	goTLSPollFDSymbol    = "net.pollDesc.waitRead"   // net.Conn fd
	goTLSConnSymbol      = "crypto/tls.(*Conn).conn" // TLSConn field
	goTLSRuntimeG        = "runtime.g"               // pointer to current goroutine
)

// TryGoTLSProbes attaches dynamic Go TLS uprobes to a process
func TryGoTLSProbes(pid int32, m map[string]bool, coll *ebpf.Collection) (bool, error) {
	symLinkHostPath, err := GetExeSymLinkHostPath(pid)
	if err != nil {
		return false, err
	}

	isGo := checkGoProcess(symLinkHostPath)
	if !isGo {
		return false, fmt.Errorf("Not a Go process")
	}
	slog.Debug("successfully found a Go process", "path", symLinkHostPath)

	elfFile, err := elf.NewFile(symLinkHostPath)
	if err != nil {
		return false, fmt.Errorf("read executable file error: %v", err)
	}
	defer elfFile.Close()

	buildVersionSymbol := elfFile.FindSymbol(buildVersion)
	if buildVersionSymbol == nil {
		return false, fmt.Errorf("go build symbol not found")
	}

	v, err := getGoVersion(elfFile, buildVersionSymbol)
	if err != nil {
		return false, err
	}
	slog.Debug("go version found", "pid", pid, "version", v.String())

	offsets, err := generateGOTLSSymbolOffsets(elfFile, v)
	if err != nil || offsets == nil {
		return false, fmt.Errorf("no offsets found")
	}
	slog.Debug("go offsets found", "pid", pid, "offsets", offsets)

	if err := updateBpfMap(GoTLS, pid, offsets, nil); err != nil {
		return false, fmt.Errorf("setting the Go TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	// Find absolute addresses for function RETs
	writeAddrs, err := findAddressForFunc(goTLSWriteSymbol, elfFile)
	if err != nil {
		return false, fmt.Errorf("finding Write return addresses: %v", err)
	}
	readAddrs, err := findAddressForFunc(goTLSReadSymbol, elfFile)
	if err != nil {
		return false, fmt.Errorf("finding Read return addresses: %v", err)
	}

	slog.Debug("Addresses for gotls symbols", "pid", pid, goTLSWriteSymbol, writeAddrs)
	slog.Debug("Addresses for gotls symbols", "pid", pid, goTLSReadSymbol, readAddrs)

	// Entry probes
	if _, err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, []bpfwrapper.Uprobe{
		{FunctionToHook: goTLSWriteSymbol, HookName: "probe_entry_tls_conn_write", Type: bpfwrapper.EntryType},
		{FunctionToHook: goTLSReadSymbol, HookName: "probe_entry_tls_conn_read", Type: bpfwrapper.EntryType},
	}); err != nil {
		return false, fmt.Errorf("failed to attach Go TLS entry uprobe: %v", err)
	}

	// Get function symbols for correct SymbolBaseOffset
	writeSym := elfFile.FindSymbol(goTLSWriteSymbol)
	readSym := elfFile.FindSymbol(goTLSReadSymbol)
	if writeSym == nil || readSym == nil {
		return false, fmt.Errorf("failed to find function symbols for TLS probes")
	}

	// Return probes with correct relative offsets
	retHooks := []bpfwrapper.Uprobe{
		{
			FunctionToHook:   goTLSWriteSymbol,
			HookName:         "probe_return_tls_conn_write",
			Type:             bpfwrapper.ReturnType_Matching_Suf_Addr,
			Addresses:        writeAddrs,
			SymbolBaseOffset: writeSym.Location,
		},
		{
			FunctionToHook:   goTLSReadSymbol,
			HookName:         "probe_return_tls_conn_read",
			Type:             bpfwrapper.ReturnType_Matching_Suf_Addr,
			Addresses:        readAddrs,
			SymbolBaseOffset: readSym.Location,
		},
	}

	if _, err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, retHooks); err != nil {
		return false, fmt.Errorf("failed to attach Go TLS return uprobe: %v", err)
	}

	slog.Debug("GoTLS probes attached successfully", "pid", pid)
	return true, nil
}
