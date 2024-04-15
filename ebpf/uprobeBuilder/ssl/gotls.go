package ssl

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/elf"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/host"
	"github.com/iovisor/gobpf/bcc"
)

var (
	buildVersion   = "runtime.buildVersion"
	goVersionRegex = regexp.MustCompile(`^go(?P<Major>\d)\.(?P<Minor>\d+)`)

	goTLSWriteSymbol         = "crypto/tls.(*Conn).Write"
	goTLSReadSymbol          = "crypto/tls.(*Conn).Read"
	goTLSGIDStatusSymbol     = "runtime.casgstatus"
	goTLSPollFDSymbol        = "internal/poll.FD"
	goTLSConnSymbol          = "crypto/tls.Conn"
	goTLSRuntimeG            = "runtime.g"
	symAddrsTable            = &bcc.Table{}
	symAddrsTableInitialized = false
)

func getGoSymAddrsTable(bpfModule *bcc.Module) *bcc.Table {
	if !symAddrsTableInitialized {
		symAddrsTable = bcc.NewTable(bpfModule.TableId("go_symaddrs_table"), bpfModule)
		symAddrsTableInitialized = true
		fmt.Printf("Table initialized\n")
	}
	return symAddrsTable
}

func TryGoTLSProbes(pid int32, m map[string]bool, bpfModule *bcc.Module) (bool, error) {

	pidAbsPath := fmt.Sprintf("/proc/%d/exe", pid)
	pidExeFile := host.GetFileInHost(pidAbsPath)
	symLink, err := os.Readlink(pidExeFile)
	if err != nil {
		return false, fmt.Errorf("exe symlink not found: %v", err)
	}
	fmt.Printf("exe symlink found %v %v\n", pid, symLink)
	if symLink == "/" {
		return false, fmt.Errorf("Empty symlink")
	}
	symLinkAbsPath := fmt.Sprintf("/proc/%d/root%v", pid, symLink)
	symLinkHostPath := host.GetFileInHost(symLinkAbsPath)
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

	fmt.Printf("go version found: %v %v\n", pid, v.String())

	offsets, err := generateGOTLSSymbolOffsets(elfFile, v)
	if err != nil {
		return false, err
	}
	if offsets == nil {
		return false, fmt.Errorf("no offsets found")
	}

	fmt.Printf("go offsets found: %v %v\n", pid, offsets)

	// TODO: check egress internal traffic
	if err := updateBccTableWithSymAddrs(bpfModule, pid, offsets); err != nil {
		return false, fmt.Errorf("setting the Go TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	for i, probe := range bpfwrapper.GoTlsRetHooks {
		if strings.EqualFold(probe.FunctionToHook, goTLSWriteSymbol) {
			address, err := findAddressForFunc(goTLSWriteSymbol, elfFile)
			fmt.Printf("Addresses for gotls sym %v %v %v %v\n", pid, goTLSWriteSymbol, address, err)
			if err == nil {
				bpfwrapper.GoTlsRetHooks[i].Addresses = address
			}

		} else if strings.EqualFold(probe.FunctionToHook, goTLSReadSymbol) {
			address, err := findAddressForFunc(goTLSReadSymbol, elfFile)
			fmt.Printf("Addresses for gotls sym %v %v %v %v\n", pid, goTLSReadSymbol, address, err)
			if err == nil {
				bpfwrapper.GoTlsRetHooks[i].Addresses = address
			}
		}
	}

	fmt.Printf("Attaching on: %v\n", symLinkHostPath)
	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, bpfwrapper.GoTlsHooks); err != nil {
		log.Printf("%s", err.Error())
	}
	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, bpfwrapper.GoTlsRetHooks); err != nil {
		log.Printf("%s", err.Error())
	}
	return true, nil
}
