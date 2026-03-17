package ssl

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/host"
	"github.com/cilium/ebpf"
)

func FindModules(modules map[string]bool, names ...string) (map[string]string, error) {
	result := make(map[string]string)
	for mod := range modules {
		for _, modName := range names {
			if strings.Contains(mod, modName) {
				result[modName] = mod
			}
		}
	}
	return result, nil
}

func GetExeSymLinkHostPath(pid int32) (string, error) {
	pidAbsPath := fmt.Sprintf("/proc/%d/exe", pid)
	pidExeFile := host.GetFileInHost(pidAbsPath)
	symLink, err := os.Readlink(pidExeFile)
	if err != nil {
		return "", fmt.Errorf("exe symlink not found: %v", err)
	}
	if symLink == "/" || symLink == "" {
		return "", fmt.Errorf("Empty symlink")
	}
	symLinkAbsPath := fmt.Sprintf("/proc/%d/root%v", pid, symLink)
	symLinkHostPath := host.GetFileInHost(symLinkAbsPath)

	return symLinkHostPath, nil
}

type ProbeType int

const (
	OpenSSL ProbeType = iota
	Envoy
	GoTLS
	Node
)

const (
	szGoTls   = int(unsafe.Sizeof(GoTLSSymbolAddress{}))
	szNodeTls = int(unsafe.Sizeof(NodeTLSSymbolAddress{}))
)

var (
	goSymAddrsMap   *ebpf.Map
	nodeSymAddrsMap *ebpf.Map
)

// InitMaps retrieves the BPF maps needed for symbol address tables from the loaded collection.
func InitMaps(coll *ebpf.Collection) {
	goSymAddrsMap = coll.Maps["go_symaddrs_table"]
	nodeSymAddrsMap = coll.Maps["node_tlswrap_symaddrs_map"]
}

func getEbpfMap(addrType ProbeType) (*ebpf.Map, error) {
	switch addrType {
	case GoTLS:
		return goSymAddrsMap, nil
	case Node:
		return nodeSymAddrsMap, nil
	}
	return nil, fmt.Errorf("no map found for probe type %d", addrType)
}

func updateBpfMap(addrType ProbeType, pid int32, symAddrsGo *GoTLSSymbolAddress, symAddrsNode *NodeTLSSymbolAddress) error {
	m, err := getEbpfMap(addrType)
	if err != nil {
		return fmt.Errorf("updateBpfMap: %v", err)
	}
	if m == nil {
		return fmt.Errorf("updateBpfMap: map is nil for probe type %d", addrType)
	}

	key := uint32(pid)

	switch addrType {
	case GoTLS:
		slog.Debug("byte arr", "byteSlice", (*(*[szGoTls]byte)(unsafe.Pointer(symAddrsGo)))[:])
		if err := m.Put(key, symAddrsGo); err != nil {
			return fmt.Errorf("updateBpfMap Put key %v failed: %v", pid, err)
		}
	case Node:
		slog.Debug("byte arr", "byteSlice", (*(*[szNodeTls]byte)(unsafe.Pointer(symAddrsNode)))[:])
		if err := m.Put(key, symAddrsNode); err != nil {
			return fmt.Errorf("updateBpfMap Put key %v failed: %v", pid, err)
		}
	}
	return nil
}

func DeletePidFromBPFMap(addrType ProbeType, pid int32) error {
	m, err := getEbpfMap(addrType)
	if err != nil {
		return fmt.Errorf("DeletePidFromBPFMap: %v", err)
	}
	if m == nil {
		return fmt.Errorf("DeletePidFromBPFMap: map is nil for probe type %d", addrType)
	}

	key := uint32(pid)
	if err := m.Delete(key); err != nil {
		return fmt.Errorf("DeletePidFromBPFMap Delete key %v failed: %v", pid, err)
	}
	return nil
}
