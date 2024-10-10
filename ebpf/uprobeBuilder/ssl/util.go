package ssl

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/host"
	"github.com/iovisor/gobpf/bcc"
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
	goSymAddrsTable   = &bcc.Table{}
	nodeSymAddrsTable = &bcc.Table{}
)

func InitMaps(bpfModule *bcc.Module) {
	goSymAddrsTable = bcc.NewTable(bpfModule.TableId("go_symaddrs_table"), bpfModule)
	nodeSymAddrsTable = bcc.NewTable(bpfModule.TableId("node_tlswrap_symaddrs_map"), bpfModule)
}

func getBccTable(addrType ProbeType) (*bcc.Table, error) {
	switch addrType {
	case GoTLS:
		return goSymAddrsTable, nil
	case Node:
		return nodeSymAddrsTable, nil
	}
	return nil, fmt.Errorf("no table found")
}

func updateBpfMap(addrType ProbeType, pid int32, symAddrsGo *GoTLSSymbolAddress, symAddrsNode *NodeTLSSymbolAddress) error {
	var asByteSlice []byte = make([]byte, 0)
	switch addrType {
	case GoTLS:
		asByteSlice = (*(*[szGoTls]byte)(unsafe.Pointer(symAddrsGo)))[:]
	case Node:
		asByteSlice = (*(*[szNodeTls]byte)(unsafe.Pointer(symAddrsNode)))[:]
	}
	fmt.Printf("byte arr: %v\n", asByteSlice)

	table, _ := getBccTable(addrType)
	key := fmt.Sprint(uint32(pid))
	keyByte, _ := table.KeyStrToBytes(key)

	fmt.Printf("key arr: %v %v \n", key, keyByte)

	if err := table.Set(keyByte, asByteSlice); err != nil {
		return fmt.Errorf("table.Set key %v failed: %v", pid, err)
	}
	return nil
}

func DeletePidFromBPFMap(addrType ProbeType, pid int32) error {
	table, _ := getBccTable(addrType)
	key := fmt.Sprint(uint32(pid))
	keyByte, _ := table.KeyStrToBytes(key)
	if err := table.Delete(keyByte); err != nil {
		return fmt.Errorf("table.Delete key %v failed: %v", pid, err)
	}
	return nil
}
