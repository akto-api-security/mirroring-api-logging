package host

import (
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var hostMappingPath string = "/host"

func init() {
	// default host mapping is /host
	utils.InitVar("HOST_MAPPING", &hostMappingPath)
}

func GetFileInHost(absPath string) string {
	if hostMappingPath != "" && strings.HasPrefix(absPath, hostMappingPath) {
		return absPath
	}
	return hostMappingPath + absPath
}
