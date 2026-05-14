package host

import (
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// GetFileInHost maps a host-absolute path (e.g. "/proc/1/exe") to the path this process
// should open. Uses HOST_MAPPING via trafficUtil/utils (single implementation).
func GetFileInHost(absPath string) string {
	return utils.ResolveHostPath(absPath)
}
