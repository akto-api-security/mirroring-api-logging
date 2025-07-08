package connections

import (
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func tryReadFromBD(ip string, destIp string, tracker *Tracker, isComplete bool, direction int, id uint64, fd uint32, daemonsetIdentifier string) {

	kafkaUtil.ParseAndProduce(tracker.recvBuf, tracker.sentBuf, ip, destIp, 0, false, "MIRRORING", isComplete, direction, id, fd, daemonsetIdentifier)
}
