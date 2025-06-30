package ssl

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/elf"
	"github.com/iovisor/gobpf/bcc"
)

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

func TryGoTLSProbes(pid int32, m map[string]bool, bpfModule *bcc.Module) (bool, error) {

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

	for i, probe := range structs.GoTlsRetHooks {
		if strings.EqualFold(probe.FunctionToHook, goTLSWriteSymbol) {
			address, err := findAddressForFunc(goTLSWriteSymbol, elfFile)
			slog.Debug("Addresses for gotls sym", "pid", pid, "symbol", goTLSWriteSymbol, "address", address, "error", err)
			if err == nil {
				structs.GoTlsRetHooks[i].Addresses = address
			}

		} else if strings.EqualFold(probe.FunctionToHook, goTLSReadSymbol) {
			address, err := findAddressForFunc(goTLSReadSymbol, elfFile)
			slog.Debug("Addresses for gotls sym", "pid", pid, "symbol", goTLSReadSymbol, "address", address, "error", err)
			if err == nil {
				structs.GoTlsRetHooks[i].Addresses = address
			}
		}
	}

	slog.Debug("Attaching on", "path", symLinkHostPath)
	if err := AttachUprobes(symLinkHostPath, -1, bpfModule, structs.GoTlsHooks); err != nil {
		slog.Error("failed to attach Go TLS uprobe", "error", err)
	}
	if err := AttachUprobes(symLinkHostPath, -1, bpfModule, structs.GoTlsRetHooks); err != nil {
		slog.Error("failed to attach Go TLS uretprobe", "error", err)
	}
	return true, nil
}
