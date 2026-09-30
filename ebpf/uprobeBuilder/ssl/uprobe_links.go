package ssl

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
)

// retainedUprobeLinks keeps OpenSSL and Node uprobe links reachable for the
// life of the process. cilium/ebpf detaches a uprobe when its Link is garbage
// collected, which is what dropped SSL_read/SSL_write after a successful attach.
var (
	uprobeLinkMu        sync.Mutex
	retainedUprobeLinks []link.Link
	attachedUprobeFiles = map[string]struct{}{}
)

func uprobeTargetKey(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return path
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return path
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

func uprobeAlreadyAttached(path string) bool {
	uprobeLinkMu.Lock()
	defer uprobeLinkMu.Unlock()
	_, ok := attachedUprobeFiles[uprobeTargetKey(path)]
	return ok
}

func keepUprobeLinks(path string, links []link.Link) {
	if len(links) == 0 {
		return
	}
	uprobeLinkMu.Lock()
	defer uprobeLinkMu.Unlock()
	retainedUprobeLinks = append(retainedUprobeLinks, links...)
	attachedUprobeFiles[uprobeTargetKey(path)] = struct{}{}
}
