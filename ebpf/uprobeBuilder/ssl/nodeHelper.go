package ssl

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/version"
)

var (
	nodeVersionRegex = regexp.MustCompile(`^node\.js/v(?P<Major>\d+)\.(?P<Minor>\d+)\.(?P<Patch>\d+)$`)
)

func checkNodeProcess(exePath string) bool {
	if strings.Contains(exePath, "node") {
		return true
	}
	return false
}

func getNodeVersion(p string) (*version.Version, error) {
	result, err := exec.Command("strings", p).Output()
	if err != nil {
		return nil, err
	}
	for _, d := range strings.Split(string(result), "\n") {
		versionInfo := nodeVersionRegex.FindStringSubmatch(strings.TrimSpace(d))
		if len(versionInfo) != 4 {
			continue
		}
		return version.Read(versionInfo[1], versionInfo[2], versionInfo[3])
	}

	return nil, fmt.Errorf("nodejs version is not found")
}

var nodeTLSAddrWithVersions = []struct {
	v    *version.Version
	conf *NodeTLSSymbolAddress
}{
	{version.Build(10, 19, 0), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(12, 3, 1), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(12, 16, 2), &NodeTLSSymbolAddress{0x0138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(13, 0, 0), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
	{version.Build(13, 2, 0), &NodeTLSSymbolAddress{0x0130, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(13, 10, 1), &NodeTLSSymbolAddress{0x0140, 0x08, 0x00, 0x60, 0xa0, 0x88, 0x30}},
	{version.Build(14, 5, 0), &NodeTLSSymbolAddress{0x138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	{version.Build(15, 0, 0), &NodeTLSSymbolAddress{0x78, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
}

func findNodeTLSAddrConfig(v *version.Version) (*NodeTLSSymbolAddress, error) {
	var temp *NodeTLSSymbolAddress
	for _, c := range nodeTLSAddrWithVersions {
		if v.GreaterOrEquals(c.v) {
			temp = c.conf
		}
	}
	if temp != nil {
		return temp, nil
	}
	return nil, fmt.Errorf("could not support version: %s", v)
}

func getNodeTlsHooks(v *version.Version) []bpfwrapper.Uprobe {
	newV := version.Build(15, 0, 0)
	if v.GreaterOrEquals(newV) {
		return bpfwrapper.NodeTLSMemHooks_15_0_0
	}
	return bpfwrapper.NodeTLSMemHooks_12_3_1
}
