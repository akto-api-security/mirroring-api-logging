package ssl

// import (
// 	"fmt"
// 	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
// 	"github.com/iovisor/gobpf/bcc"
// 	"log/slog"
// )

type NodeTLSSymbolAddress struct {
	TLSWrapStreamListenerOffset     uint32
	StreamListenerStreamOffset      uint32
	StreamBaseStreamResourceOffset  uint32
	LibuvStreamWrapStreamBaseOffset uint32
	LibuvStreamWrapStreamOffset     uint32
	UVStreamSIOWatcherOffset        uint32
	UVIOSFDOffset                   uint32
}

// func TryNodeProbes(pid int32, m map[string]bool, bpfModule *bcc.Module) (bool, error) {

// 	symLinkHostPath, err := GetExeSymLinkHostPath(pid)
// 	if err != nil {
// 		return false, err
// 	}
// 	isNode := checkNodeProcess(symLinkHostPath)
// 	if !isNode {
// 		return false, fmt.Errorf("Not a node process")
// 	}

// 	v, err := getNodeVersion(symLinkHostPath)
// 	if err != nil {
// 		return false, err
// 	}
// 	slog.Debug("read the nodejs version", "pid", pid, "version", v)

// 	config, err := findNodeTLSAddrConfig(v)
// 	if err != nil {
// 		return false, err
// 	}
// 	slog.Debug("Found node config", "pid", pid, "config", config)

// 	if err := updateBpfMap(Node, pid, nil, config); err != nil {
// 		return false, fmt.Errorf("setting the Node TLS argument location failure, pid: %d, error: %v", pid, err)
// 	}

// 	slog.Debug("Attaching on", "pid", pid, "path", symLinkHostPath)
// 	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, bpfwrapper.SslHooks); err != nil {
// 		slog.Error("failed to attach SSL uprobe", "error", err)
// 	}

// 	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, bpfwrapper.NodeSSLHooks); err != nil {
// 		slog.Error("failed to attach Node SSL uprobe", "error", err)
// 	}

// 	nodeTlsProbes := getNodeTlsHooks(v)
// 	if err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, bpfModule, nodeTlsProbes); err != nil {
// 		slog.Error("failed to attach Node TLS uprobe", "error", err)
// 	}

// 	return true, nil
// }
