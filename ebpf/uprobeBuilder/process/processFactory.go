package process

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/host"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/ssl"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/cilium/ebpf"
	"github.com/shirou/gopsutil/process"
)

type LinkType int

const (
	DynamicLink LinkType = iota
	StaticLink
)

type Process struct {
	pid         int32
	containerId string // cgroup
	linkType    LinkType
	probeType   ssl.ProbeType
	// command     string // cmdline
	// ppid        int32  // stat [4]
}

type ProcessFactory struct {
	processMap        map[int32]Process
	mutex             *sync.RWMutex
	unattachedProcess map[int32]bool
}

// NewFactory creates a new instance of the factory.
func NewFactory() *ProcessFactory {
	return &ProcessFactory{
		processMap:        make(map[int32]Process),
		mutex:             &sync.RWMutex{},
		unattachedProcess: make(map[int32]bool),
	}
}

var (
	probeAllPid       = false
	probeProcessNames []string
)

func init() {
	utils.InitVar("PROBE_ALL_PID", &probeAllPid)
	var rawNames string
	utils.InitVar("PROBE_PROCESS_NAMES", &rawNames)
	for _, part := range strings.Split(rawNames, ",") {
		name := strings.TrimSpace(part)
		if name != "" {
			probeProcessNames = append(probeProcessNames, name)
		}
	}
}

func (processFactory *ProcessFactory) AddNewProcessesToProbe(coll *ebpf.Collection) {

	pidList, err := process.Pids()
	if err != nil {
		slog.Error("Error getting process list", "error", err)
		return
	}
	slog.Debug("Found processes", "count", len(pidList))
	pidSet := make(map[int32]bool)
	for _, p := range pidList {
		pidSet[p] = true
	}

	deletedPids := make([]int32, 100)

	for pid := range processFactory.processMap {
		_, ok := pidSet[pid]
		if !ok {
			deletedPids = append(deletedPids, pid)
		}
	}
	for _, pid := range deletedPids {
		_, ok := processFactory.processMap[pid]
		if ok {
			probeType := processFactory.processMap[pid].probeType
			ssl.DeletePidFromBPFMap(probeType, pid)
			delete(processFactory.processMap, pid)
		}
	}
	slog.Debug("Attempt for processes", "count", len(pidSet))
	skippedPids := make(map[int32]bool)
	for pid := range pidSet {
		_, ok := processFactory.unattachedProcess[pid]
		if ok {
			skippedPids[pid] = true
			continue
		}
		if len(skippedPids) > 0 {
			slog.Debug("Skipped unattached processes", "count", len(skippedPids), "pids", skippedPids)
			skippedPids = make(map[int32]bool)
		}

		_, ok = processFactory.processMap[pid]
		if !ok {

			if checkSelf(pid) {
				slog.Debug("Self process", "pid", pid)
				continue
			}

			if !processNameAllowed(pid) {
				processFactory.unattachedProcess[pid] = true
				continue
			}

			time.Sleep(200 * time.Millisecond)

			containers, err := CheckProcessCGroupBelongToKube(pid)
			// probe only k8s processes, unless PROBE_ALL_PID or PROBE_PROCESS_NAMES is set
			// TODO: check this once again.
			if err != nil {
				if !probeAllPid && len(probeProcessNames) == 0 {
					slog.Debug("No libraries for process", "pid", pid, "error", err)
					processFactory.unattachedProcess[pid] = true
					continue
				}
			}

			libraries, err := FindLibrariesPathInMapFile(pid)
			if err != nil {
				slog.Debug("No libraries for process", "pid", pid, "error", err)
				processFactory.unattachedProcess[pid] = true
				continue
			}

			slog.Debug("Attempting for process", "pid", pid, "libraries", len(libraries))
			// openssl probes here are being attached on dynamically linked SSL libraries only.
			attached, err := ssl.TryOpensslProbes(libraries, coll)

			if len(containers) == 0 {
				containers = append(containers, "unknown")
			}

			if attached {
				p := Process{
					pid:         pid,
					containerId: containers[0],
					linkType:    DynamicLink,
					probeType:   ssl.OpenSSL,
				}
				processFactory.processMap[pid] = p
				continue
			} else if err != nil {
				slog.Error("openSSL probing error", "pid", pid, "error", err)
			}

			attached, err = ssl.TryGoTLSProbes(pid, libraries, coll)
			if attached {
				p := Process{
					pid:         pid,
					containerId: containers[0],
					linkType:    StaticLink,
					probeType:   ssl.GoTLS,
				}
				processFactory.processMap[pid] = p
				continue
			} else if err != nil {
				slog.Error("GoTLS probing error", "pid", pid, "error", err)
			}

			attached, err = ssl.TryNodeProbes(pid, libraries, coll)
			if attached {
				p := Process{
					pid:         pid,
					containerId: containers[0],
					linkType:    StaticLink,
					probeType:   ssl.Node,
				}
				processFactory.processMap[pid] = p
				continue
			} else if err != nil {
				slog.Error("Node probing error", "pid", pid, "error", err)
			}
			processFactory.unattachedProcess[pid] = true
		}
	}
	if len(skippedPids) > 0 {
		slog.Debug("Skipped unattached processes", "count", len(skippedPids), "pids", skippedPids)
	}
}

// processNameAllowed reports whether pid should be uprobed.
// An empty PROBE_PROCESS_NAMES list allows every process. Otherwise the
// /proc/<pid>/comm name or the executable base name must match an entry.
func processNameAllowed(pid int32) bool {
	if len(probeProcessNames) == 0 {
		return true
	}
	comm, exe := processNames(pid)
	for _, name := range probeProcessNames {
		if strings.EqualFold(comm, name) || strings.EqualFold(exe, name) {
			return true
		}
	}
	return false
}

func processNames(pid int32) (comm string, exe string) {
	commPath := host.GetFileInHost("/proc/" + strconv.FormatInt(int64(pid), 10) + "/comm")
	raw, err := os.ReadFile(commPath)
	if err == nil {
		comm = strings.TrimSpace(string(raw))
	}
	exePath, err := ssl.GetExeSymLinkHostPath(pid)
	if err == nil {
		exe = filepath.Base(exePath)
	}
	return comm, exe
}

func checkSelf(pid int32) bool {
	symLinkHostPath, err := ssl.GetExeSymLinkHostPath(pid)
	if err != nil {
		return false
	}
	if strings.Contains(symLinkHostPath, "ebpf-logging") {
		return true
	}
	return false
}
