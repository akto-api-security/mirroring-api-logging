package ssl

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
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

func TryNodeProbes(pid int32, m map[string]bool, coll *ebpf.Collection) (bool, error) {

	symLinkHostPath, err := GetExeSymLinkHostPath(pid)
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
	slog.Debug("read the nodejs version", "pid", pid, "version", v)

	config, err := findNodeTLSAddrConfig(v)
	if err != nil {
		return false, err
	}
	slog.Debug("Found node config", "pid", pid, "config", config)

	if err := updateBpfMap(Node, pid, nil, config); err != nil {
		return false, fmt.Errorf("setting the Node TLS argument location failure, pid: %d, error: %v", pid, err)
	}

	slog.Debug("Attaching on", "pid", pid, "path", symLinkHostPath)
	if uprobeAlreadyAttached(symLinkHostPath) {
		slog.Debug("Node uprobe already attached", "path", symLinkHostPath)
		return true, nil
	}

	var links []link.Link
	got, err := bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, bpfwrapper.SslHooks)
	links = append(links, got...)
	if err != nil {
		slog.Error("failed to attach SSL uprobe", "error", err)
	}

	got, err = bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, bpfwrapper.NodeSSLHooks)
	links = append(links, got...)
	if err != nil {
		slog.Error("failed to attach Node SSL uprobe", "error", err)
	}

	nodeTlsProbes := getNodeTlsHooks(v)
	got, err = bpfwrapper.AttachUprobes(symLinkHostPath, -1, coll, nodeTlsProbes)
	links = append(links, got...)
	if err != nil {
		slog.Error("failed to attach Node TLS uprobe", "error", err)
	}
	keepUprobeLinks(symLinkHostPath, links)
	if len(links) > 0 {
		slog.Warn("attached Node uprobe", "path", symLinkHostPath, "links", len(links))
	}

	return true, nil
}
