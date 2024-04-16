package process

import (
	"fmt"
	"log"
	"sync"

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
	processMap map[int32]Process
	mutex      *sync.RWMutex
}

// NewFactory creates a new instance of the factory.
func NewFactory() *ProcessFactory {
	return &ProcessFactory{
		processMap: make(map[int32]Process),
		mutex:      &sync.RWMutex{},
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
		fmt.Println(err)
		return
	}
	fmt.Printf("Found %v processes\n", len(pidList))
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
	fmt.Printf("Attempt for  %v processes\n", len(pidSet))
	for pid := range pidSet {
		_, ok := processFactory.processMap[pid]
		if !ok {

			containers, err := CheckProcessCGroupBelongToKube(pid)
			// probe only k8s processes
			// TODO: check this once again.
			if err != nil {
				if !probeAllPid {
					fmt.Printf("No libraries for pid: %v %v\n", pid, err)
					continue
				}
			}

			libraries, err := FindLibrariesPathInMapFile(pid)
			if err != nil {
				fmt.Printf("No libraries for pid: %v %v\n", pid, err)
				continue
			}

			fmt.Printf("Attempting for pid: %v %v\n", pid, len(libraries))
			// openssl probes here are being attached on dynamically linked SSL libraries only.
			attached, err := ssl.TryOpensslProbes(libraries, bpfModule)

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
				log.Printf("openSSL probing error: %v %v\n", pid, err)
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
				continue
			} else if err != nil {
				log.Printf("GoTLS probing error: %v %v\n", pid, err)
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
				continue
			} else if err != nil {
				log.Printf("Node probing error: %v %v\n", pid, err)
			}

		}
	}
}
