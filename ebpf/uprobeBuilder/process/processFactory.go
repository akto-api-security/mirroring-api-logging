package process

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/ssl"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/iovisor/gobpf/bcc"
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
	probeAllPid = false
)

func init() {
	utils.InitVar("PROBE_ALL_PID", &probeAllPid)
}

func (processFactory *ProcessFactory) AddNewProcessesToProbe(bpfModule *bcc.Module) {

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
	attempted := 0
	skippedAttached := 0
	skippedUnattached := 0
	skippedSelf := 0
	skippedNoLibraries := 0
	for pid := range pidSet {
		time.Sleep(200 * time.Millisecond)
		_, ok := processFactory.unattachedProcess[pid]
		if ok {
			skippedUnattached++
			slog.Debug("Not attempting for process", "pid", pid, "reason", "previously_failed")
			continue
		}
		_, ok = processFactory.processMap[pid]
		if ok {
			skippedAttached++
			slog.Debug("Skipping process, probes already attached", "pid", pid, "probeType", processFactory.processMap[pid].probeType)
			continue
		}

		if checkSelf(pid) {
			skippedSelf++
			slog.Debug("Self process", "pid", pid)
			continue
		}

		containers, err := CheckProcessCGroupBelongToKube(pid)
		// probe only k8s processes
		// TODO: check this once again.
		if err != nil {
			if !probeAllPid {
				skippedNoLibraries++
				slog.Debug("No libraries for process", "pid", pid, "error", err, "reason", "not_k8s_process")
				processFactory.unattachedProcess[pid] = true
				continue
			}
		}

		libraries, err := FindLibrariesPathInMapFile(pid)
		if err != nil {
			skippedNoLibraries++
			slog.Debug("No libraries for process", "pid", pid, "error", err, "reason", "maps_read_failed")
			processFactory.unattachedProcess[pid] = true
			continue
		}

		attempted++
		slog.Info("Attempting for process", "pid", pid, "libraries", len(libraries))
		// openssl probes here are being attached on dynamically linked SSL libraries only.
		attached, err := ssl.TryOpensslProbes(libraries, bpfModule)

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
			slog.Info("Attached OpenSSL probes", "pid", pid)
			continue
		} else if err != nil {
			slog.Error("openSSL probing error", "pid", pid, "error", err)
		}

		attached, err = ssl.TryGoTLSProbes(pid, libraries, bpfModule)
		if attached {
			p := Process{
				pid:         pid,
				containerId: containers[0],
				linkType:    StaticLink,
				probeType:   ssl.GoTLS,
			}
			processFactory.processMap[pid] = p
			slog.Info("Attached GoTLS probes", "pid", pid)
			continue
		} else if err != nil {
			slog.Error("GoTLS probing error", "pid", pid, "error", err)
		}

		attached, err = ssl.TryNodeProbes(pid, libraries, bpfModule)
		if attached {
			p := Process{
				pid:         pid,
				containerId: containers[0],
				linkType:    StaticLink,
				probeType:   ssl.Node,
			}
			processFactory.processMap[pid] = p
			slog.Info("Attached Node TLS probes", "pid", pid)
			continue
		} else if err != nil {
			slog.Error("Node probing error", "pid", pid, "error", err)
		}
		processFactory.unattachedProcess[pid] = true
		slog.Info("All probe types failed for process, blacklisting until restart", "pid", pid)
	}
	slog.Info("Finished process probe scan",
		"totalPids", len(pidSet),
		"attempted", attempted,
		"skippedAlreadyAttached", skippedAttached,
		"skippedPreviouslyFailed", skippedUnattached,
		"skippedSelf", skippedSelf,
		"skippedNoLibraries", skippedNoLibraries,
		"currentlyAttached", len(processFactory.processMap),
		"blacklisted", len(processFactory.unattachedProcess),
	)
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
