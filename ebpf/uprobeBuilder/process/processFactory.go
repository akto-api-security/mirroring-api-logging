package process

import (
	"fmt"
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
	hostName    string
	// command     string // cmdline
	// ppid        int32  // stat [4]
}

type ProcessFactory struct {
	processMap        map[int32]Process
	mutex             *sync.RWMutex
	unattachedProcess map[int32]bool
}

var ProcessFactoryInstance *ProcessFactory

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
	logCounter  = 0
)

func init() {
	utils.InitVar("PROBE_ALL_PID", &probeAllPid)
}

func SetupProcessFactory() {
	if ProcessFactoryInstance == nil {
		ProcessFactoryInstance = NewFactory()
		slog.Info("ProcessFactory initialized")
	} else {
		slog.Warn("ProcessFactory already initialized, skipping re-initialization")
	}
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
	for pid := range pidSet {
		time.Sleep(200 * time.Millisecond)
		_, ok := processFactory.unattachedProcess[pid]
		if ok {
			slog.Debug("Not attempting for process", "pid", pid)
			continue
		}

		// TODO: What if the pid was re-assgined to a different process?
		_, ok = processFactory.processMap[pid]
		if !ok {

			if checkSelf(pid) {
				slog.Debug("Self process", "pid", pid)
				continue
			}

			containers, err := CheckProcessCGroupBelongToKube(pid)
			// probe only k8s processes
			// TODO: check this once again.
			if err != nil {
				if !probeAllPid {
					slog.Debug("No libraries for process", "pid", pid, "error", err)
					processFactory.unattachedProcess[pid] = true
					continue
				}
			}
			// TODO verify this change carefully.
			// Can a PID be skipped due to CHeckProcessCGroupBelongToKube returning an error?
			// Does the existing behaviour remain the same? We were trying to attach any one the ssl libraries.

			processFactory.processMap[pid] = Process{
				pid:         pid,
				containerId: containers[0],
				hostName:    ReadEnvVarForProcessId("HOSTNAME", pid),
			}
			slog.Debug("Process found", "pid", pid, "containerId", containers[0], "hostName", processFactory.processMap[pid].hostName)

			libraries, err := FindLibrariesPathInMapFile(pid)
			if err != nil {
				slog.Debug("No libraries for process", "pid", pid, "error", err)
				processFactory.unattachedProcess[pid] = true
				continue
			}

			slog.Debug("Attempting for process", "pid", pid, "libraries", len(libraries))
			// openssl probes here are being attached on dynamically linked SSL libraries only.
			attached, err := ssl.TryOpensslProbes(libraries, bpfModule)

			if attached {
				pOld := processFactory.processMap[pid]
				pOld.linkType = DynamicLink
				pOld.probeType = ssl.OpenSSL
				processFactory.processMap[pid] = pOld
				continue
			} else if err != nil {
				slog.Error("openSSL probing error", "pid", pid, "error", err)
			}

			attached, err = ssl.TryGoTLSProbes(pid, libraries, bpfModule)
			if attached {
				pOld := processFactory.processMap[pid]
				pOld.linkType = StaticLink
				pOld.probeType = ssl.GoTLS
				processFactory.processMap[pid] = pOld
				continue
			} else if err != nil {
				slog.Error("GoTLS probing error", "pid", pid, "error", err)
			}

			attached, err = ssl.TryNodeProbes(pid, libraries, bpfModule)
			if attached {
				pOld := processFactory.processMap[pid]
				pOld.linkType = StaticLink
				pOld.probeType = ssl.Node
				processFactory.processMap[pid] = pOld
				continue
			} else if err != nil {
				slog.Error("Node probing error", "pid", pid, "error", err)
			}

			processFactory.unattachedProcess[pid] = true

		}
	}
	slog.Debug("Process probing completed", "count", len(processFactory.processMap))
}

func (processFactory *ProcessFactory) logProcessMap() {
	slog.Warn("Logging processMap to file", "file", utils.GoPidLogFile)
	if logCounter > 3 {
		slog.Warn("Process map logging skipped, already logged 3 times")
		return
	}
	var builder strings.Builder

	// Write headers
	fmt.Fprintf(&builder, "PID\tHostname\n")

	// Write process data
	processFactory.mutex.RLock()
	defer processFactory.mutex.RUnlock()
	for pid, p := range processFactory.processMap {
		fmt.Fprintf(&builder, "%d\t%s\t\n", pid, p.hostName)
	}

	fmt.Fprintf(&builder, "-------Total processes tracked: %d----------\n", len(processFactory.processMap))
	// Log to file in one go
	utils.LogToSpecificFile(utils.GoPidLogFile, builder.String())
	logCounter++
}

func (processFactory *ProcessFactory) GetPodNameByProcessId(pid int32) string {
	processFactory.mutex.RLock()
	defer processFactory.mutex.RUnlock()
	if p, ok := processFactory.processMap[pid]; ok {
		slog.Debug("Hostname in processMap found for", "processId", pid, "hostName", p.hostName)
		return p.hostName
	}
	slog.Debug("Reading from filesystem, hostname not found for", "processId", pid)
	hostName := ReadEnvVarForProcessId("HOSTNAME", pid)
	if hostName != "" {
		slog.Debug("Hostname read from filesystem for", "processId", pid, "hostName", hostName)
		// processFactory.processMap
		return hostName
	}
	slog.Debug("Hostname not found for", "processId", pid)
	return ""
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
