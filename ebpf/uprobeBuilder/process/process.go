package process

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/host"
)

var (
	kubepodsRegex       = regexp.MustCompile(`cri-containerd-(?P<Group>\w+)\.scope`)
	mapFileContentRegex = regexp.MustCompile("(?P<StartAddr>[a-f\\d]+)\\-(?P<EndAddr>[a-f\\d]+)\\s(?P<Perm>[^\\s]+)" +
		"\\s(?P<Offset>[a-f\\d]+)\\s[a-f\\d]+\\:[a-f\\d]+\\s\\d+\\s+(?P<Name>[^\\n]+)")
)

func CheckProcessCGroupBelongToKube(pid int32) ([]string, error) {
	cgroupAbsPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	processCgroupFilePath := host.GetFileInHost(cgroupAbsPath)
	cgroupFile, err := os.Open(processCgroupFilePath)
	if err != nil {
		return nil, err
	}
	defer cgroupFile.Close()

	cache := make(map[string]bool)
	scanner := bufio.NewScanner(cgroupFile)
	for scanner.Scan() {
		infos := strings.Split(scanner.Text(), ":")
		if len(infos) < 3 {
			continue
		}
		lastPath := strings.LastIndex(infos[2], "/")
		if lastPath > 1 && lastPath != len(infos[2])-1 {
			path := infos[2][lastPath+1:]
			// ex: cri-containerd-7dae778c37bd1204677518f1032bbecf01f5c41878ea7bd370021263417cc626.scope
			if kubepod := kubepodsRegex.FindStringSubmatch(path); len(kubepod) >= 1 {
				path = kubepod[1]
			}
			cache[path] = true
		}
	}
	if len(cache) == 0 {
		return nil, fmt.Errorf("no k8s cgroups")
	}
	result := make([]string, 0)
	for k := range cache {
		result = append(result, k)
	}
	return result, nil
}

func isIgnoreModuleName(name string) bool {
	return name != "" &&
		(strings.HasPrefix(name, "//anon") ||
			strings.HasPrefix(name, "/dev/zero") ||
			strings.HasPrefix(name, "/anon_hugepage") ||
			strings.HasPrefix(name, "[stack") ||
			strings.HasPrefix(name, "/SYSV") ||
			strings.HasPrefix(name, "[heap]") ||
			strings.HasPrefix(name, "/memfd:") ||
			strings.HasPrefix(name, "[vdso]") ||
			strings.HasPrefix(name, "[vsyscall]") ||
			strings.HasPrefix(name, "[uprobes]") ||
			strings.HasSuffix(name, ".map"))
}

func FindLibrariesPathInMapFile(pid int32) (map[string]bool, error) {
	mapsAbsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsFilePath := host.GetFileInHost(mapsAbsPath)
	mapFile, err := os.Open(mapsFilePath)
	if err != nil {
		return nil, err
	}
	defer mapFile.Close()
	scanner := bufio.NewScanner(mapFile)
	modules := make(map[string]bool)
	for scanner.Scan() {
		subMatch := mapFileContentRegex.FindStringSubmatch(scanner.Text())
		if len(subMatch) != 6 {
			continue
		}
		if len(subMatch[3]) > 2 && subMatch[3][2] != 'x' {
			continue
		}
		moduleName := subMatch[5]
		if isIgnoreModuleName(moduleName) {
			continue
		}
		_, ok := modules[moduleName]
		if ok {
			continue
		}

		modulePathAbs := fmt.Sprintf("/proc/%d/root%s", pid, moduleName)
		modulePath := host.GetFileInHost(modulePathAbs)
		_, exists := os.Stat(modulePath)
		if exists != nil {
			log.Printf("could not found the module, ignore. name: %s, path: %s", moduleName, modulePath)
			continue
		}
		modules[modulePath] = true
	}
	return modules, nil
}
