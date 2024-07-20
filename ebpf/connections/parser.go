package connections

import (
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func tryReadFromBD(ip string, destIp string, receiveBuffer []byte, sentBuffer []byte, isComplete bool, direction int) {
	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, ip, destIp, 0, false, "MIRRORING", isComplete, direction)
}
