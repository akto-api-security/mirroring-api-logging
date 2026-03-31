package ssl

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/elf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// goTLSLinks keeps GoTLS uprobe links alive for the lifetime of the process.
// cilium/ebpf automatically detaches a uprobe when its Link is garbage collected,
// so we must retain a reference here.
var goTLSLinks []link.Link

var (
	buildVersion   = "runtime.buildVersion"
	goVersionRegex = regexp.MustCompile(`^go(?P<Major>\d)\.(?P<Minor>\d+)`)

	goTLSWriteSymbol     = "crypto/tls.(*Conn).Write"
	goTLSReadSymbol      = "crypto/tls.(*Conn).Read"
	goTLSGIDStatusSymbol = "runtime.casgstatus"
	goTLSPollFDSymbol    = "internal/poll.FD"
	goTLSConnSymbol      = "crypto/tls.Conn"
	goTLSRuntimeG        = "runtime.g"
)

func TryGoTLSProbes(pid int32, m map[string]bool, coll *ebpf.Collection) (bool, error) {

	symLinkHostPath, err := GetExeSymLinkHostPath(pid)
	if err != nil {
		return false, err
	}

	isGo := checkGoProcess(symLinkHostPath)
	if !isGo {
		return false, fmt.Errorf("Not a go process")
	} else {
		slog.Debug("successfully found a go process", "path", symLinkHostPath)
	}

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
	if err != nil {
		return false, err
	}
	if offsets == nil {
		return false, fmt.Errorf("no offsets found")
	}

	slog.Debug("go offsets found", "pid", pid, "offsets", offsets)

	// TODO: check egress internal traffic
	if err := updateBpfMap(GoTLS, pid, offsets, nil); err != nil {
		return false, fmt.Errorf("setting the Go TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	for i, probe := range bpfwrapper.GoTlsRetHooks {
		if strings.EqualFold(probe.FunctionToHook, goTLSWriteSymbol) {
			address, err := findAddressForFunc(goTLSWriteSymbol, elfFile)
			slog.Debug("Addresses for gotls sym", "pid", pid, "symbol", goTLSWriteSymbol, "address", address, "error", err)
			if err == nil {
				bpfwrapper.GoTlsRetHooks[i].Addresses = address
			}

		} else if strings.EqualFold(probe.FunctionToHook, goTLSReadSymbol) {
			address, err := findAddressForFunc(goTLSReadSymbol, elfFile)
			slog.Debug("Addresses for gotls sym", "pid", pid, "symbol", goTLSReadSymbol, "address", address, "error", err)
			if err == nil {
				bpfwrapper.GoTlsRetHooks[i].Addresses = address
			}
		}
	}

	// Entry probes: use the same symbol+offset mechanism as return probes (offset=0
	// means function entry). cilium/ebpf resolves Go symbols correctly, as evidenced
	// by return-probe attachment working without errors.
	for i := range bpfwrapper.GoTlsHooks {
		bpfwrapper.GoTlsHooks[i].Addresses = []uint64{0}
		bpfwrapper.GoTlsHooks[i].Type = bpfwrapper.ReturnType_Matching_Suf_Addr
	}

	slog.Debug("Attaching on", "path", symLinkHostPath)
	entryLinks, err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, bpfwrapper.GoTlsHooks)
	if err != nil {
		slog.Error("failed to attach Go TLS uprobe", "error", err)
	}
	retLinks, err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, bpfwrapper.GoTlsRetHooks)
	if err != nil {
		slog.Error("failed to attach Go TLS uretprobe", "error", err)
	}
	// Keep links alive — GC'ing a Link detaches the uprobe.
	goTLSLinks = append(goTLSLinks, entryLinks...)
	goTLSLinks = append(goTLSLinks, retLinks...)
	return true, nil
}
