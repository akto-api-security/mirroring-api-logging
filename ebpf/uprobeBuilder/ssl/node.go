package ssl

import (
	"fmt"
	"log"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/iovisor/gobpf/bcc"
)

type NodeTLSSymbolAddress struct {
	TLSWrapStreamListenerOffset     uint32
	StreamListenerStreamOffset      uint32
	StreamBaseStreamResourceOffset  uint32
	LibuvStreamWrapStreamBaseOffset uint32
	LibuvStreamWrapStreamOffset     uint32
	UVStreamSIOWatcherOffset        uint32
	UVIOSFDOffset                   uint32
}

func TryNodeProbes(pid int32, m map[string]bool, bpfModule *bcc.Module) (bool, error) {

	symLinkHostPath, err := getExeSymLinkHostPath(pid)
	if err != nil {
		return false, err
	}
	isNode := checkNodeProcess(symLinkHostPath)
	if !isNode {
		return false, fmt.Errorf("Not a node process")
	}

	v, err := getNodeVersion(symLinkHostPath)
	if err != nil {
		return false, err
	}
	fmt.Printf("read the nodejs version, pid: %d, version: %s\n", pid, v)

	config, err := findNodeTLSAddrConfig(v)
	if err != nil {
		return false, err
	}
	fmt.Printf("Found node config: %v %v\n", pid, config)

	if err := updateBpfMap(Node, pid, nil, config); err != nil {
		return false, fmt.Errorf("setting the Node TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	fmt.Printf("Attaching on: %v %v\n", pid, symLinkHostPath)

	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, bpfwrapper.SslHooks); err != nil {
		log.Printf("%s", err.Error())
	}

	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, bpfwrapper.NodeSSLHooks); err != nil {
		log.Printf("%s", err.Error())
	}

	nodeTlsProbes := getNodeTlsHooks(v)
	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, nodeTlsProbes); err != nil {
		log.Printf("%s", err.Error())
	}

	return true, nil
}
