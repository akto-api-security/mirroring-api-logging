package process

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
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
	output := checkKubeProcess(processCgroupFilePath)
	if len(output) <= 1 {
		return nil, fmt.Errorf("no k8s cgroups")
	} else {
		slog.Debug("successfully found a kube process", "path", processCgroupFilePath)
	}
	result := make([]string, 0)
	result = append(result, output)
	return result, nil
}

func checkKubeProcess(exePath string) string {
	cmd := exec.Command("sh", "-c", "strings "+exePath+" | grep cri-containerd | head -n 1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("Error executing command in checkKubeProcess", "error", err)
		return ""
	}
	return string(output)
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
			slog.Debug("could not found the module, ignore", "name", moduleName, "path", modulePath)
			continue
		}
		modules[modulePath] = true
	}
	return modules, nil
}
